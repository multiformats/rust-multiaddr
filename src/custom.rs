use std::collections::HashMap;
use std::sync::Arc;

use crate::{Error, Multiaddr, Protocol, Result};

/// A transcoder defines how to encode and decode a custom protocol's data
/// between its binary representation and its human-readable string representation.
pub trait Transcoder: Send + Sync {
    /// Attempts to parse the human-readable string component of a protocol into bytes.
    fn string_to_bytes(
        &self,
        s: &str,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Attempts to format the binary representation of a protocol's data into a human-readable string.
    fn bytes_to_string(
        &self,
        bytes: &[u8],
    ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

/// A custom protocol definition.
#[derive(Clone)]
pub struct CustomProtocolDef {
    /// The string identifier for the protocol (e.g. `tcp`, `http`, or `my-custom`).
    pub name: &'static str,
    /// The unique unsigned integer code for the protocol.
    pub code: u32,
    /// The length of the binary payload.
    /// `0` means no data. `> 0` means a fixed data length. `-1` denotes a length-prefixed protocol or custom encoding.
    pub size: i32,
    /// Whether the protocol's string representation is a file path (e.g., `/unix/tmp/socket` instead of a base-encoded payload).
    pub path: bool,
    /// An optional transcoder used to encode and decode the protocol's data between binary and human-readable string formats.
    pub transcoder: Option<Arc<dyn Transcoder>>,
}

impl CustomProtocolDef {
    /// Create a new custom protocol definition.
    pub fn new(
        name: &'static str,
        code: u32,
        size: i32,
        path: bool,
        transcoder: Option<impl Transcoder + 'static>,
    ) -> Self {
        let transcoder = transcoder.map(|t| Arc::new(t) as Arc<dyn Transcoder>);
        Self {
            name,
            code,
            size,
            path,
            transcoder,
        }
    }
}

impl std::cmp::PartialEq for CustomProtocolDef {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.name == other.name
    }
}

impl std::cmp::Eq for CustomProtocolDef {}

impl std::fmt::Debug for CustomProtocolDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomProtocolDef")
            .field("name", &self.name)
            .field("code", &self.code)
            .field("size", &self.size)
            .field("path", &self.path)
            .finish()
    }
}

/// A registry mapping protocol codes and names to their custom definitions.
#[derive(Clone)]
pub struct Registry {
    by_code: HashMap<u32, CustomProtocolDef>,
    by_name: HashMap<String, CustomProtocolDef>,
}

impl Default for Registry {
    fn default() -> Self {
        let mut r = Self {
            by_code: HashMap::new(),
            by_name: HashMap::new(),
        };
        r.register_builtins();
        r
    }
}

impl Registry {
    /// Create a new, empty protocol registry. Wait, new() actually uses default and adds built-ins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add all built-in standard protocols to the registry.
    fn register_builtins(&mut self) {
        for &(name, code, size, path) in crate::protocol::BUILT_IN_PROTOCOLS.iter() {
            self.register(CustomProtocolDef {
                name,
                code,
                size,
                path,
                transcoder: None,
            });
        }
    }

    /// Add a custom protocol definition to this registry.
    pub fn register(&mut self, mut def: CustomProtocolDef) {
        if def.path && def.name.starts_with('/') {
            def.name = def.name.trim_start_matches('/');
        }
        let name = def.name.to_string();
        let code = def.code;
        self.by_code.insert(code, def.clone());
        self.by_name.insert(name, def.clone());
    }

    /// Returns a registered custom protocol by its integer code.
    pub fn get_by_code(&self, code: u32) -> Option<CustomProtocolDef> {
        self.by_code.get(&code).cloned()
    }

    /// Returns a registered custom protocol by its string name.
    pub fn get_by_name(&self, name: &str) -> Option<CustomProtocolDef> {
        self.by_name.get(name).cloned()
    }

    /// Unregisters a protocol by its string name.
    pub fn unregister_by_name(&mut self, name: &str) {
        if let Some(def) = self.by_name.remove(name) {
            self.by_code.remove(&def.code);
        }
    }

    /// Unregisters a protocol by its integer code.
    pub fn unregister_by_code(&mut self, code: u32) {
        if let Some(def) = self.by_code.remove(&code) {
            self.by_name.remove(def.name);
        }
    }

    /// Iterate over the protocols in a `Multiaddr` using this registry.
    pub fn parse_addr<'a>(&'a self, ma: &'a Multiaddr) -> RegistryIter<'a> {
        RegistryIter {
            registry: self,
            data: ma.as_ref(),
        }
    }
}

/// Iterator over protocols using a registry.
pub struct RegistryIter<'a> {
    registry: &'a Registry,
    data: &'a [u8],
}

impl<'a> Iterator for RegistryIter<'a> {
    type Item = Protocol<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let (p, next_data) = self.registry.parse_protocol_from_bytes(self.data).ok()?;
        self.data = next_data;
        Some(p)
    }
}

impl Registry {
    /// Try parsing a single Protocol from bytes using the registry.
    pub fn parse_protocol_from_bytes<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Protocol<'a>, &'a [u8])> {
        let n_input = input;
        let id_res = unsigned_varint::decode::u32(n_input);

        if let Ok(res) = Protocol::from_bytes(input) {
            let is_unknown = matches!(&res.0, Protocol::Unknown(_, _));
            if !is_unknown {
                return Ok(res);
            }
        }

        let (id, rest) = match id_res {
            Ok((id, rest)) => (id, rest),
            Err(_) => return Err(Error::UnknownProtocolId(0)),
        };

        let def = match self.get_by_code(id) {
            Some(def) => def,
            None => {
                // If the protocol isn't registered, we just return it as Unknown
                // so that we can gracefully iterate over or reserialize it later.
                return Ok((
                    Protocol::Unknown(id, std::borrow::Cow::Borrowed(rest)),
                    [].as_ref(),
                ));
            }
        };

        // Extract the protocol data based on the registered size definition
        let (data, out_rest) = if def.size == 0 {
            // Protocol has no data payload expected
            (std::borrow::Cow::Borrowed(&rest[..0]), rest)
        } else if def.size > 0 {
            // Protocol has a fixed-length data payload
            let fixed = def.size as usize;
            if rest.len() < fixed {
                return Err(Error::DataLessThanLen);
            }
            let (d, r) = rest.split_at(fixed);
            (std::borrow::Cow::Borrowed(d), r)
        } else {
            // Protocol size is -1, meaning it is length-prefixed.
            // Decode the varint representing the length of the upcoming data.
            let (len, r) =
                unsigned_varint::decode::usize(rest).map_err(|_| Error::DataLessThanLen)?;
            if r.len() < len {
                return Err(Error::DataLessThanLen);
            }
            let (d, r2) = r.split_at(len);
            (std::borrow::Cow::Borrowed(d), r2)
        };

        Ok((
            Protocol::Custom {
                def: Arc::new(def),
                data,
            },
            out_rest,
        ))
    }

    /// Try parsing a single Protocol from string parts using the registry.
    pub fn parse_protocol_from_str_parts<'a, I>(
        &self,
        iter: &mut std::iter::Peekable<I>,
    ) -> Result<Protocol<'a>>
    where
        I: Iterator<Item = &'a str> + Clone,
    {
        let &tag = iter.peek().ok_or(Error::InvalidProtocolString)?;

        if !self.by_name.contains_key(tag) {
            return Err(Error::UnknownProtocolString(tag.to_string()));
        }

        let mut native_iter = iter.clone();
        if let Ok(p) = Protocol::from_str_parts(&mut native_iter) {
            *iter = native_iter;
            return Ok(p);
        }

        let def = self.get_by_name(tag).unwrap();
        iter.next(); // consume the tag
        let data = if def.size == 0 {
            vec![]
        } else if let Some(t) = &def.transcoder {
            let part = iter.next().ok_or(Error::InvalidProtocolString)?;
            t.string_to_bytes(part)
                .map_err(|_| Error::InvalidProtocolString)?
        } else if def.path {
            let part = iter.next().ok_or(Error::InvalidProtocolString)?;
            percent_encoding::percent_decode(part.as_bytes()).collect::<Vec<u8>>()
        } else {
            let part = iter.next().ok_or(Error::InvalidProtocolString)?;
            multibase::Base::Base64Url
                .decode(part)
                .map_err(|_| Error::InvalidProtocolString)?
        };
        Ok(Protocol::Custom {
            def: Arc::new(def),
            data: std::borrow::Cow::Owned(data),
        })
    }

    /// Parse a Multiaddr string using this registry
    pub fn try_from_str(&self, input: &str) -> Result<Multiaddr> {
        let mut addr = Multiaddr::empty();
        let mut parts = input.split('/').peekable();

        if Some("") != parts.next() {
            return Err(Error::InvalidMultiaddr);
        }

        while parts.peek().is_some() {
            let p = self.parse_protocol_from_str_parts(&mut parts)?;
            addr = addr.with(p);
        }

        Ok(addr)
    }

    /// Parse a Multiaddr from bytes using this registry
    pub fn try_from_bytes(&self, mut input: &[u8]) -> Result<Multiaddr> {
        let mut addr = Multiaddr::empty();
        while !input.is_empty() {
            let (p, rest) = self.parse_protocol_from_bytes(input)?;
            addr = addr.with(p);
            input = rest;
        }
        Ok(addr)
    }

    /// Format a Multiaddr into a string using this registry
    pub fn to_string(&self, addr: &Multiaddr) -> String {
        let mut s = String::new();
        for p in self.parse_addr(addr) {
            s.push_str(&p.to_string());
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleTranscoder;
    impl Transcoder for SimpleTranscoder {
        fn string_to_bytes(
            &self,
            s: &str,
        ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(s.as_bytes().to_vec())
        }
        fn bytes_to_string(
            &self,
            bytes: &[u8],
        ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>> {
            Ok(String::from_utf8(bytes.to_vec())?)
        }
    }

    #[test]
    fn test_custom_protocol_registry() {
        let mut registry = Registry::new();
        registry.register(CustomProtocolDef::new(
            "my-custom",
            999,
            -1,
            false,
            Some(SimpleTranscoder),
        ));

        let addr = registry
            .try_from_str("/ip4/127.0.0.1/my-custom/helloworld")
            .unwrap();

        // Output via normal iter should panic because the global parser doesn't know 999,
        // wait, we modified the normal fmt::Display to iterate, BUT Display iterates the multiaddr.
        // If we try `addr.to_string()`, it will panic if it's not a generic iterator.

        let vec = addr.to_vec();
        // Parse back from vec
        let parsed = registry.try_from_bytes(&vec).unwrap();

        let mut iter = registry.parse_addr(&parsed);
        if let Some(Protocol::Ip4(ip)) = iter.next() {
            assert_eq!(ip, std::net::Ipv4Addr::new(127, 0, 0, 1));
        } else {
            panic!("expected ip4");
        }

        if let Some(Protocol::Custom { def, data }) = iter.next() {
            assert_eq!(def.code, 999);
            assert_eq!(def.name, "my-custom");
            assert_eq!(data.as_ref(), b"helloworld");
        } else {
            panic!("expected custom protocol");
        }
    }

    #[test]
    fn test_unregister_builtin() {
        let mut registry = Registry::default();

        // Assert tcp works
        let addr = registry.try_from_str("/ip4/127.0.0.1/tcp/80").unwrap();
        let mut iter = registry.parse_addr(&addr);
        assert!(matches!(iter.next(), Some(Protocol::Ip4(_))));
        assert!(matches!(iter.next(), Some(Protocol::Tcp(80))));

        // Unregister tcp
        registry.unregister_by_name("tcp");

        // Assert tcp fails now
        assert!(registry.try_from_str("/ip4/127.0.0.1/tcp/80").is_err());

        // And similarly from bytes, it will now parse as Tcp since we natively fallback to standard protocols
        let vec = addr.to_vec();
        let parsed_unknown = registry.try_from_bytes(&vec).unwrap();
        let mut parsed_iter = registry.parse_addr(&parsed_unknown);
        assert!(matches!(parsed_iter.next(), Some(Protocol::Ip4(_))));
        assert!(matches!(parsed_iter.next(), Some(Protocol::Tcp(80))));
    }

    #[test]
    fn test_custom_protocol_registry_printing() {
        let mut registry = Registry::new();
        registry.register(CustomProtocolDef::new(
            "my-custom",
            999,
            -1,
            false,
            Some(SimpleTranscoder),
        ));

        // Parsed string multi addr with a custom protocol
        let addr = registry
            .try_from_str("/ip4/127.0.0.1/my-custom/helloworld")
            .unwrap();

        // 1. Printing with Registry works as expected, displaying the registered custom format
        let registry_printed = registry.to_string(&addr);
        assert_eq!(registry_printed, "/ip4/127.0.0.1/my-custom/helloworld");

        // 2. Native Multiaddr printing gracefully falls back to unknown without panicking
        let native_printed = addr.to_string();
        // Native printing uses base64url for the rest of the bytes (the length varint and data).
        // For size=-1, the length varint `10` followed by "helloworld" becomes 'CmhlbGxvd29ybGQ'
        assert_eq!(native_printed, "/ip4/127.0.0.1/unknown-999/CmhlbGxvd29ybGQ");

        // 3. Confirm that the final 'unknown-999' round-trips on parse back to the same multiaddr
        let parsed_back = native_printed
            .parse::<Multiaddr>()
            .expect("Should parse unknown protocol formatting natively");
        assert_eq!(
            parsed_back, addr,
            "Round-trip multiaddr bytes must match the original instance precisely"
        );
    }

    #[test]
    fn test_custom_protocol_size_zero() {
        let mut registry = Registry::new();
        // Register a custom protocol with size 0 (no data payload expected)
        registry.register(CustomProtocolDef::new(
            "my-empty",
            1000,
            0,
            false,
            None::<SimpleTranscoder>,
        ));

        // It should parse without needing an additional value
        let addr = registry.try_from_str("/ip4/127.0.0.1/my-empty").unwrap();

        let vec = addr.to_vec();
        let parsed = registry.try_from_bytes(&vec).unwrap();

        let mut iter = registry.parse_addr(&parsed);
        if let Some(Protocol::Ip4(ip)) = iter.next() {
            assert_eq!(ip, std::net::Ipv4Addr::new(127, 0, 0, 1));
        } else {
            panic!("expected ip4");
        }

        if let Some(Protocol::Custom { def, data }) = iter.next() {
            assert_eq!(def.code, 1000);
            assert_eq!(def.name, "my-empty");
            assert!(data.is_empty());
        } else {
            panic!("expected custom protocol");
        }

        // Ensure that a subsequent protocol is parsed correctly, not consumed as data
        let addr2 = registry.try_from_str("/my-empty/tcp/80").unwrap();
        let mut iter2 = registry.parse_addr(&addr2);

        assert!(
            matches!(iter2.next(), Some(Protocol::Custom { def, .. }) if def.name == "my-empty")
        );
        assert!(matches!(iter2.next(), Some(Protocol::Tcp(80))));
    }
}
