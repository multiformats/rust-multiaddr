use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::convert::From;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

///! # Protocols
///!
///! A type to describe the possible protocols used in a
///! Multiaddr.

/// Protocols is the list of all possible protocols.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Protocols {
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
    /// Convert a `u16` based code to a `Protocol`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocols;
    ///
    /// assert_eq!(Protocols::from_code(6u16), Some(Protocols::TCP));
    /// assert_eq!(Protocols::from_code(455u16), None);
    /// ```
    ///
    /// # Failures
    ///
    /// If no matching code is found `None` is returned.
    ///
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

    /// Get the size from a `Protocol`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocols;
    ///
    /// assert_eq!(Protocols::TCP.size(), 16);
    /// ```
    ///
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

    /// Get the `Protocol` from a `&str` name.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocols;
    ///
    /// assert_eq!(Protocols::from_name("tcp").unwrap(), Protocols::TCP);
    /// ```
    ///
    /// # Failures
    ///
    /// If no matching protocol is found `None` is returned.
    ///
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

    /// Convert an array slice to the string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocols;
    ///
    /// let proto = Protocols::IP4;
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
            Protocols::IP4 => {
                let addr = Ipv4Addr::from_str(a).unwrap();
                let mut res = Vec::new();
                res.extend(addr.octets().iter().cloned());

                Some(res)
            },
            Protocols::IP6 => {
                let addr = Ipv6Addr::from_str(a).unwrap();
                let mut res = Vec::new();

                for segment in &addr.segments() {
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

    /// Convert an array slice to the string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocols;
    ///
    /// let proto = Protocols::IP4;
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
            Protocols::IP4 => {
                Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
            },
            Protocols::IP6 => {
                let mut rdr = Cursor::new(b);
                let seg: Vec<u16> = (0..8).into_iter().map(|_| {
                    rdr.read_u16::<BigEndian>().unwrap()
                }).collect();

                Some(Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]
                ).to_string())
            },
	    Protocols::TCP
                | Protocols::UDP
                | Protocols::DCCP
                | Protocols::SCTP => {
                    let mut rdr = Cursor::new(b);
                    rdr.read_u16::<BigEndian>().map(|num| num.to_string()).ok()
                },
	    Protocols::IPFS => None,
	    Protocols::ONION => None,
	    Protocols::UTP
	        | Protocols::UDT
	        | Protocols::HTTP
	        | Protocols::HTTPS => {
                    None
                },
        }
    }
}
