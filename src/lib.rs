///! # multiaddr
///!
///! Implementation of [multiaddr](https://github.com/jbenet/multiaddr)
///! in Rust.
extern crate byteorder;
extern crate cid;
extern crate integer_encoding;

pub mod protocol;
mod parser;
mod errors;

pub use errors::{Result, Error};
pub use protocol::{Protocol, Segment, AddressSegment, AddressSegmentReaderExt, AddressSegmentWriterExt};

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

/// Representation of a Multiaddr.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Multiaddr {
    addr: Vec<Segment>,

    #[deprecated]
    bytes: Vec<u8>
}

impl ToString for Multiaddr {
    /// Convert a Multiaddr to a string
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt").unwrap();
    /// assert_eq!(address.to_string(), "/ip4/127.0.0.1/udt");
    /// ```
    ///
    fn to_string(&self) -> String {
        parser::multiaddr_to_str(&self.addr)
    }
}

#[allow(deprecated)] // We have to access our own deprecated `bytes` field
impl Multiaddr {
    /// Create a new multiaddr based on a string representation, like
    /// `/ip4/127.0.0.1/udp/1234`.
    ///
    /// # Examples
    ///
    /// Simple construction
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();
    /// assert_eq!(address.to_bytes(), [
    ///     4, 127, 0, 0, 1,
    ///     17, 4, 210
    /// ]);
    /// ```
    ///
    pub fn new(input: &str) -> Result<Multiaddr> {
        let addr = parser::multiaddr_from_str(input)?;

        Ok(Multiaddr { bytes: Self::_addr_to_bytes(&addr), addr: addr })
    }

    fn _addr_to_bytes(addr: &Vec<Segment>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for addr_segment in addr {
            addr_segment.to_stream(&mut bytes).unwrap();
        }
        bytes
    }

    /// Return a copy to disallow changing the bytes directly
    pub fn to_bytes(&self) -> Vec<u8> {
        Self::_addr_to_bytes(&self.addr)
    }

    /// Extracts a slice containing the entire underlying vector.
    #[deprecated(note="Use `.to_bytes()` instead")]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Return a list of protocols
    ///
    /// # Examples
    ///
    /// A single protocol
    ///
    /// ```
    /// use multiaddr::{Multiaddr, Protocol};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// assert_eq!(address.protocol(), vec![Protocol::IP4]);
    /// ```
    ///
    #[deprecated(note="Use `.segments()` instead")]
    pub fn protocol(&self) -> Vec<Protocol> {
        self.addr.iter().map(|s| s.protocol()).collect()
    }

    /// Return the individual address segments of this multiaddr
    ///
    /// # Examples
    ///
    /// A single protocol
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use multiaddr::{Multiaddr, protocol};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// assert_eq!(address.segments(), [protocol::Segment::IP4(protocol::IP4Segment(Ipv4Addr::new(127, 0, 0, 1)))]);
    /// ```
    ///
    pub fn segments(&self) -> &[Segment] {
        &self.addr
    }

    /// Wrap a given Multiaddr and return the combination.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// let nested = address.encapsulate("/udt").unwrap();
    /// assert_eq!(nested, Multiaddr::new("/ip4/127.0.0.1/udt").unwrap());
    /// ```
    ///
    pub fn encapsulate<T: ToMultiaddr>(&self, input: T) -> Result<Multiaddr> {
        let mut multiaddr = self.clone();
        multiaddr.addr.extend(input.to_multiaddr()?.addr);
        multiaddr.bytes = Self::_addr_to_bytes(&multiaddr.addr);
        Ok(multiaddr)
    }

    /// Remove the outer most address from itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::{Multiaddr, ToMultiaddr};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt/sctp/5678").unwrap();
    /// let unwrapped = address.decapsulate("/udt").unwrap();
    /// assert_eq!(unwrapped, Multiaddr::new("/ip4/127.0.0.1").unwrap());
    ///
    /// assert_eq!(
    ///     address.decapsulate("/udt").unwrap(),
    ///     "/ip4/127.0.0.1/".to_multiaddr().unwrap()
    /// );
    /// ```
    ///
    /// Returns the original if the passed in address is not found
    ///
    /// ```
    /// use multiaddr::ToMultiaddr;
    ///
    /// let address = "/ip4/127.0.0.1/udt/sctp/5678".to_multiaddr().unwrap();
    /// let unwrapped = address.decapsulate("/ip4/127.0.1.1").unwrap();
    /// assert_eq!(unwrapped, address);
    /// ```
    ///
    pub fn decapsulate<T: ToMultiaddr>(&self, input: T) -> Result<Multiaddr> {
        let input = input.to_multiaddr()?;

        for (idx, addr_window) in self.addr.windows(input.addr.len()).enumerate() {
            if addr_window == input.addr.as_slice() {
                let addr = self.addr.iter().take(idx).map(|s| s.clone()).collect();
                return Ok(Multiaddr { bytes: Self::_addr_to_bytes(&addr), addr: addr });
            }
        }

        Ok(self.clone())
    }
}


/// A trait for objects which can be converted to a
/// Multiaddr.
///
/// This trait is implemented by default for
///
/// * `SocketAddr`, `SocketAddrV4` and `SocketAddrV6`, assuming that the
///   the given port is a tcp port.
///
/// * `Ipv4Addr`, `Ipv6Addr`
///
/// * `String` and `&str`, requiring the default string format for a Multiaddr.
///
pub trait ToMultiaddr {
    /// Converts this object to a Multiaddr
    ///
    /// # Errors
    ///
    /// Any errors encountered during parsing will be returned
    /// as an `Err`.
    fn to_multiaddr(&self) -> Result<Multiaddr>;
}

impl ToMultiaddr for SocketAddr {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        match *self {
            SocketAddr::V4(ref a) => (*a).to_multiaddr(),
            SocketAddr::V6(ref a) => (*a).to_multiaddr(),
        }
    }
}

impl ToMultiaddr for SocketAddrV4 {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Multiaddr::new(&format!("/ip4/{}/tcp/{}", self.ip(), self.port()))
    }
}

impl ToMultiaddr for SocketAddrV6 {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        // TODO: Should how should we handle `flowinfo` and `scope_id`?
        Multiaddr::new(&format!("/ip6/{}/tcp/{}", self.ip(), self.port()))
    }
}

impl ToMultiaddr for Ipv4Addr {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Multiaddr::new(&format!("/ip4/{}", &self))
    }
}

impl ToMultiaddr for Ipv6Addr {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Multiaddr::new(&format!("/ip6/{}", &self))
    }
}

impl ToMultiaddr for String {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Multiaddr::new(self)
    }
}

impl<'a> ToMultiaddr for &'a str {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Multiaddr::new(self)
    }
}

impl ToMultiaddr for Multiaddr {
    fn to_multiaddr(&self) -> Result<Multiaddr> {
        Ok(self.clone())
    }
}
