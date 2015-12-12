use std::mem;
use std::cmp::PartialEq;

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
                // Is there a way to do this safely?
                unsafe {
                    let code_u16 = protocol.to_code();
                    let code = mem::transmute::<u16, [u8; 2]>(code_u16);

                    if code_u16 > 255 {
                        let mut code = code.iter().cloned().collect();
                        bytes.append(&mut code);
                    } else {
                        bytes.push(code[0])
                    }
                }

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
}

impl PartialEq for Multiaddr {
    fn eq(&self, other: &Multiaddr) -> bool {
        self.bytes == other.bytes
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocols_to_u16() {
        assert_eq!(ProtocolTypes::TCP.to_code(), 6u16);
    }

    #[test]
    fn protocols_from_u16() {
        assert_eq!(ProtocolTypes::from_code(6u16), Some(ProtocolTypes::TCP));
        assert_eq!(ProtocolTypes::from_code(455u16), None);
    }

    #[test]
    fn protocols_to_size() {
        assert_eq!(ProtocolTypes::TCP.to_size(), 16);
    }

    #[test]
    fn protocols_to_name() {
        assert_eq!(ProtocolTypes::TCP.to_name(), "tcp");
    }

    #[test]
    fn multiaddr_from_string() {
        let mut target = vec![4u8];
        target.append(&mut "127.0.0.1".to_string().into_bytes());
        target.push(17u8);
        target.append(&mut "1234".to_string().into_bytes());

        assert_eq!(
            Multiaddr::new("/ip4/127.0.0.1/udp/1234").bytes,
            target
         );
    }

    #[test]
    fn multiaddr_eq() {
        assert!(Multiaddr::new("/ip4/127.0.0.1") == Multiaddr::new("/ip4/127.0.0.1"));
        assert!(Multiaddr::new("/ip4/127.0.0.1") != Multiaddr::new("/ip4/128.0.0.1"))
    }
}
