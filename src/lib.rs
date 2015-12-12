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
}
