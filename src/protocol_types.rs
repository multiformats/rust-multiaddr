use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{FromStr, from_utf8};
use byteorder::{LittleEndian, WriteBytesExt};

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

    pub fn address_string_to_bytes(&self, a: &str) -> Option<Vec<u8>> {
        match *self {
            ProtocolTypes::IP4        => {
                let octets = Ipv4Addr::from_str(a).unwrap().octets();
                let mut res = Vec::new();
                res.extend(octets.iter().cloned());
                println!("{:?}", res);
                Some(res)
            },
            // ProtocolTypes::IP6        => {
            //     //let a = from_utf8(a).unwrap();
            //     let segments = Ipv6Addr::from_str(a).unwrap().segments();
            //     let res: Vec<u8> = Vec::new();

            //     for segment in &segments {
            //         println!("{}", *segment);
            //         res.write_u16::<LittleEndian>(*segment);
            //     }

            //     Some(&res[..])
            // },
	    ProtocolTypes::TCP
                | ProtocolTypes::UDP
                | ProtocolTypes::DCCP
                | ProtocolTypes::SCTP => {
                    let parsed = [
                        &a[0..2].parse::<u8>().unwrap(),
                        &a[2..4].parse::<u8>().unwrap(),
                     ];
                    let mut res = Vec::new();
                    res.extend(parsed.iter().cloned());
                    println!("{:?}", res);
                    Some(res)
                },
	    ProtocolTypes::IPFS       => Some(Vec::new()),
	    ProtocolTypes::ONION      => Some(Vec::new()),
	    ProtocolTypes::UTP
	        | ProtocolTypes::UDT
	        | ProtocolTypes::HTTP
	        | ProtocolTypes::HTTPS => {
                    // These all have length 0 so just return an empty vector
                    // for consistency
                    Some(Vec::new())
                }
            _ => None
        }
    }
}
