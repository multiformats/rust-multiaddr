#[macro_use]
extern crate nom;
extern crate byteorder;

pub use self::protocol_types::*;
pub mod protocol_types;

use std::cmp::PartialEq;
use self::parser::*;
mod parser;

pub struct Multiaddr {
    bytes: Vec<u8>
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
    ///     0, 4, 127, 0, 0, 1,
    ///     0, 17, 4, 210
    /// ]);
    /// ```
    ///
    pub fn new(input: &str) -> Result<Multiaddr, ParseError> {
        let bytes = try!(parser::multiaddr_from_str(input));

        Result::Ok(Multiaddr {
            bytes: bytes,
        })
    }

    /// Return a copy to disallow changing the bytes directly
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_owned()
    }

    /// Return a list of protocols
    ///
    /// # Examples
    ///
    /// A single protocol
    ///
    /// ```
    /// use multiaddr::{Multiaddr, ProtocolTypes};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// assert_eq!(address.protocols(), vec![ProtocolTypes::IP4]);
    /// ```
    ///
    pub fn protocols(&self) -> Vec<ProtocolTypes> {
        parser::protocols_from_bytes(&self.bytes[..])
    }
}

impl PartialEq for Multiaddr {
    fn eq(&self, other: &Multiaddr) -> bool {
        self.bytes == other.bytes
    }
}
