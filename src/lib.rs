extern crate byteorder;
extern crate nom;

pub use self::protocol_types::*;
pub mod protocol_types;

use std::io::Cursor;
use std::cmp::PartialEq;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};


pub struct Multiaddr {
    bytes: Vec<u8>
}

fn parse_addr(input: &[u8]) -> IResult<&[u8], Multiaddr> {
    chain!(input,

           )
}

impl Multiaddr {
    /// Create a new multiaddr based on a string representation, like
    /// `/ip4/127.0.0.1/udp/1234`.
    pub fn new(address: &str) -> Multiaddr {
        let address = address.to_string();
        let mut bytes: Vec<u8>= vec![];

        for part in address.split("/") {
            if let Some(protocol) = ProtocolTypes::from_name(part) {
                bytes.write_u16::<LittleEndian>(protocol.to_code());
                println!("Bytes {:?}", bytes);
                let mut rdr = Cursor::new(vec![4, 0]);
                println!("Bytes reversed {:?}", rdr.read_u16::<LittleEndian>());
                println!("Got protocol {}", protocol.to_name());
                println!("With size {}", protocol.to_size());
            } else if part.len() > 0 {
                let mut part_bytes = part.to_string().into_bytes();
                bytes.append(&mut part_bytes);
                println!("got part {}, {}", part.len(), part);
            }
        }

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
