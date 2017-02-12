use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::convert::From;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use cid::Cid;
use varmint::WriteVarInt;

use {Result, Error};

///! # Protocol
///!
///! A type to describe the possible protocol used in a
///! Multiaddr.

macro_rules! build_protocol_enum {
    {$( $val:expr => $var:ident: $alph:expr, $size:expr, )*} => {
        /// Protocol is the list of all possible protocols.
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        pub enum Protocol {
            $( $var = $val, )*
        }

        use Protocol::*;

        impl From<Protocol> for u64 {
            /// Convert to the matching integer code
            fn from(proto: Protocol) -> u64 {
                match proto {
                    $( $var => $val, )*
                }                
            }
        }

        impl ToString for Protocol {
            fn to_string(&self) -> String {
                match *self {
                    $( $var => $alph.to_string(), )*
                }
            }
        }

        impl FromStr for Protocol {
            type Err = Error;
            
            fn from_str(raw: &str) -> Result<Self> {
                match raw {
                    $( $alph => Ok($var), )*
                    _ => Err(Error::UnkownProtocolString),
                }
            }
        }


        impl Protocol {
            /// Convert a `u64` based code to a `Protocol`.
            ///
            /// # Examples
            ///
            /// ```
            /// use multiaddr::Protocol;
            ///
            /// assert_eq!(Protocol::from(6).unwrap(), Protocol::TCP);
            /// assert!(Protocol::from(455).is_err());
            /// ```
            pub fn from(raw: u64) -> Result<Protocol> {
                match raw {
                    $( $val => Ok($var), )*
                    _ => Err(Error::UnkownProtocol),
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
                    $( $var => $size, )*
                }
            }               
        }
    }
}

build_protocol_enum!(
    // [IP4](https://en.wikipedia.org/wiki/IPv4)
    4 => IP4: "ip4", 32,
    // [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
    6 => TCP: "tcp", 16,
    // [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
    17 => UDP: "udp", 16,
    // [DCCP](https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol)
    33 => DCCP: "dccp", 16,
    // [IP6](https://en.wikipedia.org/wiki/IPv6)
    41 => IP6: "ip6", 128,
    // [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol)
    132 => SCTP: "sctp", 16,
    // [UDT](https://en.wikipedia.org/wiki/UDP-based_Data_Transfer_Protocol)
    301 => UDT: "udt", 0,
    // [UTP](https://en.wikipedia.org/wiki/Micro_Transport_Protocol)
    302 => UTP: "utp", 0,
    // [IPFS](https://github.com/ipfs/specs/tree/master/protocol#341-merkledag-paths)
    421 => IPFS: "ipfs", -1,
    // [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)
    480 => HTTP: "http", 0,
    // [HTTPS](https://en.wikipedia.org/wiki/HTTPS)
    443 => HTTPS: "https", 0,
    // Onion
    444 => ONION: "onion", 80,
);


impl Protocol {
    /// Convert an array slice to the string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Protocol;
    ///
    /// let proto = Protocol::IP4;
    /// assert_eq!(proto.string_to_bytes("127.0.0.1").unwrap(), [127, 0, 0, 1]);
    /// ```
    ///
    pub fn string_to_bytes(&self, a: &str) -> Result<Vec<u8>> {
        use Protocol::*;

        match *self {
            IP4 => {
                let addr = Ipv4Addr::from_str(a)?;
                let mut res = Vec::new();
                res.extend(addr.octets().iter().cloned());

                Ok(res)
            }
            IP6 => {
                let addr = Ipv6Addr::from_str(a)?;
                let mut res = Vec::new();

                for segment in &addr.segments() {
                    res.write_u16::<BigEndian>(*segment)?;
                }

                Ok(res)
            }
            TCP | UDP | DCCP | SCTP => {
                let parsed: u16 = a.parse()?;
                let mut res = Vec::new();
                res.write_u16::<BigEndian>(parsed)?;

                Ok(res)
            }
            IPFS => {
                let bytes = Cid::from(a)?.to_bytes();
                let mut res = vec![];
                res.write_u64_varint(bytes.len() as u64)?;
                res.extend(bytes);
                    
                Ok(res)
            }
            ONION => Ok(Vec::new()),
            UTP | UDT | HTTP | HTTPS => {
                // These all have length 0 so just return an empty vector
                // for consistency
                Ok(Vec::new())
            }
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
    /// assert_eq!(proto.bytes_to_string(&bytes).unwrap(), Some("127.0.0.1".to_string()));
    /// ```
    ///
    /// # Failures
    ///
    /// If there is no address representation for the protocol, like for `https`
    /// then `None` is returned.
    ///
    pub fn bytes_to_string(&self, b: &[u8]) -> Result<Option<String>> {
        use Protocol::*;

        match *self {
            IP4 => Ok(Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())),
            IP6 => {
                let mut rdr = Cursor::new(b);
                let mut seg = vec![];
                
                for _ in 0..8 {
                    seg.push(rdr.read_u16::<BigEndian>()?);
                }

                Ok(Some(Ipv6Addr::new(seg[0],
                                   seg[1],
                                   seg[2],
                                   seg[3],
                                   seg[4],
                                   seg[5],
                                   seg[6],
                                   seg[7])
                    .to_string()))
            }
            TCP | UDP | DCCP | SCTP => {
                let mut rdr = Cursor::new(b);
                let num = rdr.read_u16::<BigEndian>()?;

                Ok(Some(num.to_string()))
            }
            IPFS => {
                let c = Cid::from(b)?;
                
                Ok(Some(c.to_string()))
            }
            ONION => Ok(None),
            UTP | UDT | HTTP | HTTPS => Ok(None),
        }
    }
}
