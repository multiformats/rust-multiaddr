use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::convert::From;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

///! # Protocol
///!
///! A type to describe the possible protocol used in a
///! Multiaddr.

/// Protocol is the list of all possible protocols.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Protocol {
    /// [IP4](https://en.wikipedia.org/wiki/IPv4)
    IP4   = 4,
    /// [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
    TCP   = 6,
    /// [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
    UDP   = 17,
    /// [DCCP](https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol)
    DCCP  = 33,
    /// [IP6](https://en.wikipedia.org/wiki/IPv6)
    IP6   = 41,
    /// [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol)
    SCTP  = 132,
    /// [UTP](https://en.wikipedia.org/wiki/Micro_Transport_Protocol)
    UTP   = 301,
    /// [UDT](https://en.wikipedia.org/wiki/UDP-based_Data_Transfer_Protocol)
    UDT   = 302,
    /// [IPFS](https://github.com/ipfs/specs/tree/master/protocol#341-merkledag-paths)
    IPFS  = 421,
    /// [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)
    HTTP  = 480,
    /// [HTTPS](https://en.wikipedia.org/wiki/HTTPS)
    HTTPS = 443,
    /// Onion
    ONION = 444,
}

impl From<Protocol> for u16 {
    fn from(t: Protocol) -> u16 {
        t as u16
    }
}

impl ToString for Protocol {
    fn to_string(&self) -> String {
        match *self {
            Protocol::IP4   => "ip4".to_string(),
	    Protocol::TCP   => "tcp".to_string(),
	    Protocol::UDP   => "udp".to_string(),
	    Protocol::DCCP  => "dccp".to_string(),
	    Protocol::IP6   => "ip6".to_string(),
	    Protocol::SCTP  => "sctp".to_string(),
	    Protocol::UTP   => "utp".to_string(),
	    Protocol::UDT   => "udt".to_string(),
	    Protocol::IPFS  => "ipfs".to_string(),
	    Protocol::HTTP  => "http".to_string(),
	    Protocol::HTTPS => "https".to_string(),
	    Protocol::ONION => "onion".to_string(),
        }
    }
}

impl Protocol {
    /// Convert a `u16` based code to a `Protocol`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// assert_eq!(Protocol::from_code(6u16), Some(Protocol::TCP));
    /// assert_eq!(Protocol::from_code(455u16), None);
    /// ```
    ///
    /// # Failures
    ///
    /// If no matching code is found `None` is returned.
    ///
    pub fn from_code(b: u16) -> Option<Protocol> {
        match b {
            4u16   => Some(Protocol::IP4),
	    6u16   => Some(Protocol::TCP),
	    17u16  => Some(Protocol::UDP),
	    33u16  => Some(Protocol::DCCP),
	    41u16  => Some(Protocol::IP6),
	    132u16 => Some(Protocol::SCTP),
	    301u16 => Some(Protocol::UTP),
	    302u16 => Some(Protocol::UDT),
	    421u16 => Some(Protocol::IPFS),
	    480u16 => Some(Protocol::HTTP),
	    443u16 => Some(Protocol::HTTPS),
	    444u16 => Some(Protocol::ONION),
            _ => None
        }
    }

    /// Get the size from a `Protocol`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// assert_eq!(Protocol::TCP.size(), 16);
    /// ```
    ///
    pub fn size(&self) -> isize {
        match *self {
            Protocol::IP4   => 32,
	    Protocol::TCP   => 16,
	    Protocol::UDP   => 16,
	    Protocol::DCCP  => 16,
	    Protocol::IP6   => 128,
	    Protocol::SCTP  => 16,
	    Protocol::UTP   => 0,
	    Protocol::UDT   => 0,
	    Protocol::IPFS  => -1,
	    Protocol::HTTP  => 0,
	    Protocol::HTTPS => 0,
	    Protocol::ONION => 80,
        }
    }

    /// Get the `Protocol` from a `&str` name.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// assert_eq!(Protocol::from_name("tcp").unwrap(), Protocol::TCP);
    /// ```
    ///
    /// # Failures
    ///
    /// If no matching protocol is found `None` is returned.
    ///
    pub fn from_name(s: &str) -> Option<Protocol> {
        match s {
            "ip4"   => Some(Protocol::IP4),
	    "tcp"   => Some(Protocol::TCP),
	    "udp"   => Some(Protocol::UDP),
	    "dccp"  => Some(Protocol::DCCP),
	    "ip6"   => Some(Protocol::IP6),
	    "sctp"  => Some(Protocol::SCTP),
	    "utp"   => Some(Protocol::UTP),
	    "udt"   => Some(Protocol::UDT),
	    "ipfs"  => Some(Protocol::IPFS),
	    "http"  => Some(Protocol::HTTP),
	    "https" => Some(Protocol::HTTPS),
	    "onion" => Some(Protocol::ONION),
            _ => None
        }
    }

    /// Convert an array slice to the string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// let proto = Protocol::IP4;
    /// assert_eq!(proto.address_string_to_bytes("127.0.0.1").unwrap(), [127, 0, 0, 1]);
    /// ```
    ///
    /// # Failures
    ///
    /// If there is no address representation for the protocol, like for `https`
    /// then `None` is returned.
    ///
    pub fn address_string_to_bytes(&self, a: &str) -> Option<Vec<u8>> {
        match *self {
            Protocol::IP4 => {
                let addr = Ipv4Addr::from_str(a).unwrap();
                let mut res = Vec::new();
                res.extend(addr.octets().iter().cloned());

                Some(res)
            },
            Protocol::IP6 => {
                let addr = Ipv6Addr::from_str(a).unwrap();
                let mut res = Vec::new();

                for segment in &addr.segments() {
                    res.write_u16::<BigEndian>(*segment).unwrap();
                }

                Some(res)
            },
	    Protocol::TCP
                | Protocol::UDP
                | Protocol::DCCP
                | Protocol::SCTP => {
                    let parsed: u16 = a.parse().unwrap();
                    let mut res = Vec::new();
                    res.write_u16::<BigEndian>(parsed).unwrap();

                    Some(res)
                },
	    Protocol::IPFS => Some(Vec::new()),
	    Protocol::ONION => Some(Vec::new()),
	    Protocol::UTP
	        | Protocol::UDT
	        | Protocol::HTTP
	        | Protocol::HTTPS => {
                    // These all have length 0 so just return an empty vector
                    // for consistency
                    Some(Vec::new())
                },
        }
    }

    /// Convert an array slice to the string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// let proto = Protocol::IP4;
    /// let bytes = [127, 0, 0, 1];
    /// assert_eq!(proto.bytes_to_string(&bytes).unwrap(), "127.0.0.1");
    /// ```
    ///
    /// # Failures
    ///
    /// If there is no address representation for the protocol, like for `https`
    /// then `None` is returned.
    ///
    pub fn bytes_to_string(&self, b: &[u8]) -> Option<String> {
        match *self {
            Protocol::IP4 => {
                Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
            },
            Protocol::IP6 => {
                let mut rdr = Cursor::new(b);
                let seg: Vec<u16> = (0..8).into_iter().map(|_| {
                    rdr.read_u16::<BigEndian>().unwrap()
                }).collect();

                Some(Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]
                ).to_string())
            },
	    Protocol::TCP
                | Protocol::UDP
                | Protocol::DCCP
                | Protocol::SCTP => {
                    let mut rdr = Cursor::new(b);
                    rdr.read_u16::<BigEndian>().map(|num| num.to_string()).ok()
                },
	    Protocol::IPFS => None,
	    Protocol::ONION => None,
	    Protocol::UTP
	        | Protocol::UDT
	        | Protocol::HTTP
	        | Protocol::HTTPS => {
                    None
                },
        }
    }
}
