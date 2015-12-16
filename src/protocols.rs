use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::convert::From;
use byteorder::{BigEndian, WriteBytesExt};

// Protocols is the list of all supported protocols.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Protocols {
    IP4   = 4,
    TCP   = 6,
    UDP   = 17,
    DCCP  = 33,
    IP6   = 41,
    SCTP  = 132,
    UTP   = 301,
    UDT   = 302,
    IPFS  = 421,
    HTTP  = 480,
    HTTPS = 443,
    ONION = 444,
}

impl From<Protocols> for u16 {
    fn from(t: Protocols) -> u16 {
        t as u16
    }
}

impl ToString for Protocols {
    fn to_string(&self) -> String {
        match *self {
            Protocols::IP4   => "ip4".to_string(),
	    Protocols::TCP   => "tcp".to_string(),
	    Protocols::UDP   => "udp".to_string(),
	    Protocols::DCCP  => "dccp".to_string(),
	    Protocols::IP6   => "ip6".to_string(),
	    Protocols::SCTP  => "sctp".to_string(),
	    Protocols::UTP   => "utp".to_string(),
	    Protocols::UDT   => "udt".to_string(),
	    Protocols::IPFS  => "ipfs".to_string(),
	    Protocols::HTTP  => "http".to_string(),
	    Protocols::HTTPS => "https".to_string(),
	    Protocols::ONION => "onion".to_string(),
        }
    }
}

impl Protocols {
    // Try to convert a u16 to a protocol
    pub fn from_code(b: u16) -> Option<Protocols> {
        match b {
            4u16   => Some(Protocols::IP4),
	    6u16   => Some(Protocols::TCP),
	    17u16  => Some(Protocols::UDP),
	    33u16  => Some(Protocols::DCCP),
	    41u16  => Some(Protocols::IP6),
	    132u16 => Some(Protocols::SCTP),
	    301u16 => Some(Protocols::UTP),
	    302u16 => Some(Protocols::UDT),
	    421u16 => Some(Protocols::IPFS),
	    480u16 => Some(Protocols::HTTP),
	    443u16 => Some(Protocols::HTTPS),
	    444u16 => Some(Protocols::ONION),
            _ => None
        }
    }

    pub fn size(&self) -> isize {
        match *self {
            Protocols::IP4   => 32,
	    Protocols::TCP   => 16,
	    Protocols::UDP   => 16,
	    Protocols::DCCP  => 16,
	    Protocols::IP6   => 128,
	    Protocols::SCTP  => 16,
	    Protocols::UTP   => 0,
	    Protocols::UDT   => 0,
	    Protocols::IPFS  => -1,
	    Protocols::HTTP  => 0,
	    Protocols::HTTPS => 0,
	    Protocols::ONION => 80,
        }
    }

    // Try to convert a string to a protocol
    pub fn from_name(s: &str) -> Option<Protocols> {
        match s {
            "ip4"   => Some(Protocols::IP4),
	    "tcp"   => Some(Protocols::TCP),
	    "udp"   => Some(Protocols::UDP),
	    "dccp"  => Some(Protocols::DCCP),
	    "ip6"   => Some(Protocols::IP6),
	    "sctp"  => Some(Protocols::SCTP),
	    "utp"   => Some(Protocols::UTP),
	    "udt"   => Some(Protocols::UDT),
	    "ipfs"  => Some(Protocols::IPFS),
	    "http"  => Some(Protocols::HTTP),
	    "https" => Some(Protocols::HTTPS),
	    "onion" => Some(Protocols::ONION),
            _ => None
        }
    }

    pub fn address_string_to_bytes(&self, a: &str) -> Option<Vec<u8>> {
        match *self {
            Protocols::IP4 => {
                let octets = Ipv4Addr::from_str(a).unwrap().octets();
                let mut res = Vec::new();
                res.extend(octets.iter().cloned());
                println!("{:?}", res);
                Some(res)
            },
            Protocols::IP6 => {
                let segments = Ipv6Addr::from_str(a).unwrap().segments();
                let mut res = Vec::new();

                for segment in &segments {
                    println!("{}", *segment);
                    res.write_u16::<BigEndian>(*segment).unwrap();
                }

                Some(res)
            },
	    Protocols::TCP
                | Protocols::UDP
                | Protocols::DCCP
                | Protocols::SCTP => {
                    let parsed: u16 = a.parse().unwrap();
                    let mut res = Vec::new();
                    res.write_u16::<BigEndian>(parsed).unwrap();
                    println!("{:?}", res);
                    Some(res)
                },
	    Protocols::IPFS => Some(Vec::new()),
	    Protocols::ONION => Some(Vec::new()),
	    Protocols::UTP
	        | Protocols::UDT
	        | Protocols::HTTP
	        | Protocols::HTTPS => {
                    // These all have length 0 so just return an empty vector
                    // for consistency
                    Some(Vec::new())
                },
        }
    }
}
