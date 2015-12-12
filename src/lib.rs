extern crate byteorder;

use std::io::Cursor;
use std::cmp::PartialEq;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

// ProtocolTypes is the list of all supported protocols.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ProtocolTypes {
    IP4,
    TCP,
    UDP,
    DCCP,
    IP6,
    SCTP,
    UTP,
    UDT,
    IPFS,
    HTTP,
    HTTPS,
    ONION,
}

impl ProtocolTypes {
    pub fn to_code(&self) -> u16 {
        match *self {
            ProtocolTypes::IP4   => 4,
	    ProtocolTypes::TCP   => 6,
	    ProtocolTypes::UDP   => 17,
	    ProtocolTypes::DCCP  => 33,
	    ProtocolTypes::IP6   => 41,
	    ProtocolTypes::SCTP  => 132,
	    ProtocolTypes::UTP   => 301,
	    ProtocolTypes::UDT   => 302,
	    ProtocolTypes::IPFS  => 421,
	    ProtocolTypes::HTTP  => 480,
	    ProtocolTypes::HTTPS => 443,
	    ProtocolTypes::ONION => 444,
        }
    }

    // Try to convert a u16 to a protocol
    pub fn from_code(b: u16) -> Option<ProtocolTypes> {
        match b {
            4u16   => Some(ProtocolTypes::IP4),
	    6u16   => Some(ProtocolTypes::TCP),
	    17u16  => Some(ProtocolTypes::UDP),
	    33u16  => Some(ProtocolTypes::DCCP),
	    41u16  => Some(ProtocolTypes::IP6),
	    132u16 => Some(ProtocolTypes::SCTP),
	    301u16 => Some(ProtocolTypes::UTP),
	    302u16 => Some(ProtocolTypes::UDT),
	    421u16 => Some(ProtocolTypes::IPFS),
	    480u16 => Some(ProtocolTypes::HTTP),
	    443u16 => Some(ProtocolTypes::HTTPS),
	    444u16 => Some(ProtocolTypes::ONION),
            _ => None
        }
    }

    pub fn to_size(&self) -> isize {
        match *self {
            ProtocolTypes::IP4   => 32,
	    ProtocolTypes::TCP   => 16,
	    ProtocolTypes::UDP   => 16,
	    ProtocolTypes::DCCP  => 16,
	    ProtocolTypes::IP6   => 128,
	    ProtocolTypes::SCTP  => 16,
	    ProtocolTypes::UTP   => 0,
	    ProtocolTypes::UDT   => 0,
	    ProtocolTypes::IPFS  => -1,
	    ProtocolTypes::HTTP  => 0,
	    ProtocolTypes::HTTPS => 0,
	    ProtocolTypes::ONION => 80,
        }
    }

    pub fn to_name(&self) -> String {
        match *self {
            ProtocolTypes::IP4   => "ip4".to_string(),
	    ProtocolTypes::TCP   => "tcp".to_string(),
	    ProtocolTypes::UDP   => "udp".to_string(),
	    ProtocolTypes::DCCP  => "dccp".to_string(),
	    ProtocolTypes::IP6   => "ip6".to_string(),
	    ProtocolTypes::SCTP  => "sctp".to_string(),
	    ProtocolTypes::UTP   => "utp".to_string(),
	    ProtocolTypes::UDT   => "udt".to_string(),
	    ProtocolTypes::IPFS  => "ipfs".to_string(),
	    ProtocolTypes::HTTP  => "http".to_string(),
	    ProtocolTypes::HTTPS => "https".to_string(),
	    ProtocolTypes::ONION => "onion".to_string(),
        }
    }

    // Try to convert a string to a protocol
    pub fn from_name(s: &str) -> Option<ProtocolTypes> {
        match s {
            "ip4"   => Some(ProtocolTypes::IP4),
	    "tcp"   => Some(ProtocolTypes::TCP),
	    "udp"   => Some(ProtocolTypes::UDP),
	    "dccp"  => Some(ProtocolTypes::DCCP),
	    "ip6"   => Some(ProtocolTypes::IP6),
	    "sctp"  => Some(ProtocolTypes::SCTP),
	    "utp"   => Some(ProtocolTypes::UTP),
	    "udt"   => Some(ProtocolTypes::UDT),
	    "ipfs"  => Some(ProtocolTypes::IPFS),
	    "http"  => Some(ProtocolTypes::HTTP),
	    "https" => Some(ProtocolTypes::HTTPS),
	    "onion" => Some(ProtocolTypes::ONION),
            _ => None
        }
    }
}


pub struct Multiaddr {
    bytes: Vec<u8>
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
