#[macro_use]
extern crate nom;
extern crate byteorder;

pub use self::protocols::*;
pub mod protocols;

use self::parser::*;
mod parser;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Multiaddr {
    bytes: Vec<u8>
}

impl ToString for Multiaddr {
    /// Convert a Multiaddr to a string
    ///
    /// # Examples
    ///
    /// ```rust
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt").unwrap();
    /// assert_eq!(address.to_string(), "/ip4/127.0.0.1/udt");
    /// ```
    ///
    fn to_string(&self) -> String {
        parser::address_from_bytes(&self.bytes[..])
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
    /// use multiaddr::{Multiaddr, Protocols};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// assert_eq!(address.protocols(), vec![Protocols::IP4]);
    /// ```
    ///
    pub fn protocols(&self) -> Vec<Protocols> {
        parser::protocols_from_bytes(&self.bytes[..])
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
    pub fn encapsulate(&self, input: &str) -> Result<Multiaddr, ParseError> {
        let mut bytes = self.bytes.clone();
        let new = try!(parser::multiaddr_from_str(input));
        println!("bytes: {:?}, new: {:?}", bytes, new);
        bytes.extend(new);
        println!("res {:?}", bytes);
        Result::Ok(Multiaddr {
            bytes: bytes
        })
    }

    /// Remove the outer most address from itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt/sctp/5678").unwrap();
    /// let unwrapped = address.decapsulate(Multiaddr::new("/udt").unwrap());
    /// assert_eq!(unwrapped, Multiaddr::new("/ip4/127.0.0.1").unwrap());
    /// ```
    ///
    /// Returns the original if the passed in address is not found
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt/sctp/5678").unwrap();
    /// let unwrapped = address.decapsulate(Multiaddr::new("/ip4/127.0.1.1").unwrap());
    /// assert_eq!(unwrapped, address);
    /// ```
    ///
    pub fn decapsulate(&self, input: Multiaddr) -> Multiaddr {
        let bytes = self.bytes.clone();
        let input = input.to_bytes();
        let bytes_len = bytes.len();
        let input_length = input.len();

        let mut input_pos = 0;
        let mut matches = false;

        for (i, _) in bytes.iter().enumerate() {
            let next = i + input_length;

            if next > bytes_len {
                continue;
            }

            if &bytes[i..next] == &input[..] {
                matches = true;
                input_pos = i;
                break;
            }
        }

        if !matches {
            return Multiaddr {bytes: bytes}
        }

        let mut bytes = bytes;
        bytes.truncate(input_pos);

        Multiaddr {
            bytes: bytes
        }
    }
}
