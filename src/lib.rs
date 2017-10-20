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
pub use protocol::{Protocol, Addr, AddressSegment, AddressSegmentReaderExt, AddressSegmentWriterExt};

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

/// Representation of a Multiaddr.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Multiaddr {
    bytes: Vec<u8>,
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
        parser::address_from_bytes(self.as_slice()).expect("failed to validate at construction")
    }
}

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
        let bytes = parser::multiaddr_from_str(input)?;

        Ok(Multiaddr { bytes: bytes })
    }

    /// Return a copy to disallow changing the bytes directly
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_owned()
    }

    /// Extracts a slice containing the entire underlying vector.
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
    pub fn protocol(&self) -> Vec<Protocol> {
        parser::protocol_from_bytes(&self.bytes[..]).expect("failed to validate at construction")
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
        let new = input.to_multiaddr()?;
        let mut bytes = self.bytes.clone();

        bytes.extend(new.to_bytes());

        Ok(Multiaddr { bytes: bytes })
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
        let input = input.to_multiaddr()?.to_bytes();

        let bytes_len = self.bytes.len();
        let input_length = input.len();

        let mut input_pos = 0;
        let mut matches = false;

        for (i, _) in self.bytes.iter().enumerate() {
            let next = i + input_length;

            if next > bytes_len {
                continue;
            }

            if &self.bytes[i..next] == input.as_slice() {
                matches = true;
                input_pos = i;
                break;
            }
        }

        if !matches {
            return Ok(Multiaddr { bytes: self.bytes.clone() });
        }

        let mut bytes = self.bytes.clone();
        bytes.truncate(input_pos);

        Ok(Multiaddr { bytes: bytes })
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
