#[macro_use]
extern crate nom;

extern crate byteorder;

pub use self::protocol_types::*;
pub mod protocol_types;

use std::io::Cursor;
use std::cmp::PartialEq;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::IResult;

pub struct Multiaddr {
    bytes: Vec<u8>
}

/// Parse a single /
named!(sep, tag!("/"));

/// Parse a single multiaddress in the form of `/ip4/127.0.0.1`.
named!(address <&[u8], (&str, &str)>,
    chain!(
         opt!(sep)             ~
      t: map_res!(
          take_until!("/"),
          std::str::from_utf8
         )                     ~
         sep                   ~
      a: map_res!(
          is_not!("/"),
          std::str::from_utf8
         ),
      || {(t, a)}
    )
);

/// Parse a list of addresses
named!(addresses < &[u8], Vec<(&str, &str)> >, many1!(address));

impl Multiaddr {
    /// Create a new multiaddr based on a string representation, like
    /// `/ip4/127.0.0.1/udp/1234`.
    pub fn new(input: &str) -> Multiaddr {
        match addresses(input.as_bytes()) {
            IResult::Done(i, tuple_vec) => {
                println!("Not yet parsed {}", std::str::from_utf8(i).unwrap());
                println!("found {} addresse(s)", tuple_vec.len());
                for el in &tuple_vec {
                    println!("{}, {}", el.0, el.1);
                }
            },
            _ => println!("error")
        }

        let mut bytes: Vec<u8>= vec![];

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
