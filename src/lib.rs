#[macro_use]
extern crate nom;

extern crate byteorder;

pub use self::protocol_types::*;
pub mod protocol_types;

use std::fmt;
use std::error;
use std::io::Cursor;
use std::cmp::PartialEq;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::IResult;

pub struct Multiaddr {
    bytes: Vec<u8>
}

/// Parse a single /
named!(sep <&[u8], &[u8]>, tag!("/"));

/// Parse a single multiaddress in the form of `/ip4/127.0.0.1`.
named!(address <&[u8], (&[u8], &[u8])>,
    chain!(
         opt!(sep)             ~
      t: take_until!("/")      ~
         sep                   ~
      a: is_not!("/"),
      || {

      }
    )
);

/// Parse a list of addresses
named!(addresses < &[u8], Vec<(&[u8], &[u8])> >, many1!(address));

fn print_bytes(i: &[u8]) -> &str {
    std::str::from_utf8(i).unwrap()
}

#[derive(Debug)]
struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The given multiaddress is invalid");
    }
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        "Invalid multiaddress"
    }
}

fn parse_multiaddr(input: &str) -> Result<Vec<(&[u8], &[u8])>, ParseError> {
    match addresses(input.as_bytes()) {
        IResult::Done(i, tuple_vec) => {
            println!("Not yet parsed {}", print_bytes(i));
            println!("found {} addresse(s)", tuple_vec.len());
            for el in &tuple_vec {
                println!("{}, {}", print_bytes(el.0), print_bytes(el.1));
            }
            Result::Ok(tuple_vec)
        },
        _ => Result::Err(ParseError),
    }
}

impl Multiaddr {
    /// Create a new multiaddr based on a string representation, like
    /// `/ip4/127.0.0.1/udp/1234`.
    pub fn new(input: &str) -> Result<Multiaddr, ParseError> {
        let bytes = try!(parse_multiaddr(input));

        // for part in address.split("/") {
        //     if let Some(protocol) = ProtocolTypes::from_name(part) {
        //         bytes.write_u16::<LittleEndian>(protocol.to_code());
        //         println!("Bytes {:?}", bytes);
        //         let mut rdr = Cursor::new(vec![4, 0]);
        //         println!("Bytes reversed {:?}", rdr.read_u16::<LittleEndian>());
        //         println!("Got protocol {}", protocol.to_name());
        //         println!("With size {}", protocol.to_size());
        //     } else if part.len() > 0 {
        //         let mut part_bytes = part.to_string().into_bytes();
        //         bytes.append(&mut part_bytes);
        //         println!("got part {}, {}", part.len(), part);
        //     }
        // }

        Multiaddr {
            bytes: bytes,
        }
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
    /// let address = Multiaddr::new("/ip4/127.0.0.1");
    /// assert_eq!(address.protocols(), vec![ProtocolTypes::IP4])
    /// ```
    ///
    pub fn protocols(&self) -> Vec<ProtocolTypes> {
        let mut protos = vec![];

        // let mut skipper = 0;
        // let mut first = true;
        // let mut current = [0u8, 0u8];

        // for (i, byte) in self.bytes.iter().enumerate() {
        //     println!("{}: {}", byte, i);
        //     if (skipper > 0) {
        //         skipper --;
        //         continue;
        //     }

        //     if (first) {
        //         current[0] = byte;
        //         first = false;
        //     } else {
        //         current[1] = byte;

        //         a[]
        //     }
        // }

        protos
    }
}

impl PartialEq for Multiaddr {
    fn eq(&self, other: &Multiaddr) -> bool {
        self.bytes == other.bytes
    }
}
