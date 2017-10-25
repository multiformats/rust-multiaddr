use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::convert::From;
use std::fmt;
use std::hash;
use std::io;
use std::io::Cursor;
use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use cid;
use integer_encoding::{VarIntReader, VarIntWriter};

use {Result, Error};


///! # Protocol
///!
///! A type to describe the possible protocol used in a
///! Multiaddr.


/// Single multiaddress segment with its attached data
pub trait AddressSegment : fmt::Display + ToString {
    const STREAM_LENGTH: usize = 0;

    fn protocol(&self) -> Protocol;

    /// Read address segment data from stream
    ///
    /// If the address segment does expect any additional data, then
    /// no data will be read and an empty struct will be created.
    fn from_stream(stream: &mut io::Read) -> Result<Self> where Self: Sized;

    /// Generate the canonical binary representation of the contents of this
    /// address segment
    ///
    /// In order to obtain a human-readable string representation use
    /// `ToString.to_string` instead.
    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()>;
}

impl<T> From<T> for Protocol where T: AddressSegment {
    fn from(addr: T) -> Protocol {
        addr.protocol()
    }
}



/// A trait for reading any kind of address segment from a byte stream
pub trait AddressSegmentReaderExt<T: AddressSegment> {
    fn read_addr(&mut self) -> io::Result<T>;
}
impl<T: AddressSegment, R: io::Read> AddressSegmentReaderExt<T> for R {
    fn read_addr(&mut self) -> io::Result<T> {
        T::from_stream(self).map_err(|err: Error| {
            io::Error::new(io::ErrorKind::InvalidData, err)
        })
    }
}


/// A trait for writing any kind of address segment to a byte stream
pub trait AddressSegmentWriterExt<T: AddressSegment> {
    fn write_addr(&mut self, addr: &T) -> io::Result<()>;
}
impl<T: AddressSegment, W: io::Write> AddressSegmentWriterExt<T> for W {
    fn write_addr(&mut self, addr: &T) -> io::Result<()> {
        addr.to_stream(self)
    }
}


macro_rules! derive_for_wrapping_segment {
    ( $name:ident ) => {};
    ( $name:ident , $( $rest:tt )+ ) => {
        derive_for_wrapping_segment!($name : $($rest)*);
    };

    ( $name:ident : Display $( $rest:tt )* ) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        derive_for_wrapping_segment!($name $($rest)*);
    };

    ( $name:ident : FromStr $( $rest:tt )* ) => {
        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                Ok($name(FromStr::from_str(s)?))
            }
        }

        derive_for_wrapping_segment!($name $($rest)*);
    };

    ( $name:ident : From < $type:path > $( $rest:tt )* ) => {
        impl From < $type > for $name {
            fn from(addr: $type ) -> Self {
                $name (addr)
            }
        }

        derive_for_wrapping_segment!($name $($rest)*);
    };
}


macro_rules! derive_for_empty_segment {
    ( $name:ident ) => {};
    ( $name:ident , $( $rest:tt )+ ) => {
        derive_for_empty_segment!($name : $($rest)*);
    };

    ( $name:ident : Display $( $rest:tt )* ) => {
        impl fmt::Display for $name {
            fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
                Ok(())
            }
        }

        derive_for_empty_segment!($name $($rest)*);
    };

    ( $name:ident : FromStr $( $rest:tt )* ) => {
        impl FromStr for $name {
            type Err = Error;

            fn from_str(_: &str) -> Result<Self> {
                Ok( $name {} )
            }
        }

        derive_for_empty_segment!($name $($rest)*);
    };

    ( $name:ident : AddressSegment < $proto:ident > $( $rest:tt )* ) => {
        impl AddressSegment for $name {
            fn protocol(&self) -> Protocol {
                Protocol::$proto
            }

            fn from_stream(_: &mut io::Read) -> Result<Self> {
                Ok($name {})
            }

            fn to_stream(&self, _: &mut io::Write) -> io::Result<()> {
                Ok(())
            }
        }

        derive_for_empty_segment!($name $($rest)*);
    };
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct IP4Segment(pub Ipv4Addr);

derive_for_wrapping_segment!(IP4Segment: Display, FromStr, From<Ipv4Addr>);
impl AddressSegment for IP4Segment {
    const STREAM_LENGTH: usize = 4;

    fn protocol(&self) -> Protocol {
        Protocol::IP4
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;

        Ok(IP4Segment(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        stream.write_all(&self.0.octets())
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct TCPSegment(pub u16);

derive_for_wrapping_segment!(TCPSegment: Display, FromStr, From<u16>);
impl AddressSegment for TCPSegment {
    const STREAM_LENGTH: usize = 2;

    fn protocol(&self) -> Protocol {
        Protocol::TCP
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        Ok(TCPSegment(stream.read_u16::<BigEndian>()?))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        Ok(stream.write_u16::<BigEndian>(self.0)?)
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct UDPSegment(pub u16);

derive_for_wrapping_segment!(UDPSegment: Display, FromStr, From<u16>);
impl AddressSegment for UDPSegment {
    const STREAM_LENGTH: usize = 2;

    fn protocol(&self) -> Protocol {
        Protocol::UDP
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        Ok(UDPSegment(stream.read_u16::<BigEndian>()?))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        Ok(stream.write_u16::<BigEndian>(self.0)?)
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct DCCPSegment(pub u16);

derive_for_wrapping_segment!(DCCPSegment: Display, FromStr, From<u16>);
impl AddressSegment for DCCPSegment {
    const STREAM_LENGTH: usize = 2;

    fn protocol(&self) -> Protocol {
        Protocol::DCCP
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        Ok(DCCPSegment(stream.read_u16::<BigEndian>()?))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        Ok(stream.write_u16::<BigEndian>(self.0)?)
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct IP6Segment(pub Ipv6Addr);

derive_for_wrapping_segment!(IP6Segment: Display, FromStr, From<Ipv6Addr>);
impl AddressSegment for IP6Segment {
    const STREAM_LENGTH: usize = 16;

    fn protocol(&self) -> Protocol {
        Protocol::IP6
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        Ok(IP6Segment(
            Ipv6Addr::new(
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?,
                stream.read_u16::<BigEndian>()?
            )
        ))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        for segment in &self.0.segments() {
            stream.write_u16::<BigEndian>(*segment)?;
        }
        Ok(())
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SCTPSegment(pub u16);

derive_for_wrapping_segment!(SCTPSegment: Display, FromStr, From<u16>);
impl AddressSegment for SCTPSegment {
    const STREAM_LENGTH: usize = 2;

    fn protocol(&self) -> Protocol {
        Protocol::SCTP
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        Ok(SCTPSegment(stream.read_u16::<BigEndian>()?))
    }

    fn to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
        Ok(stream.write_u16::<BigEndian>(self.0)?)
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct UDTSegment;

derive_for_empty_segment!(UDTSegment: Display, FromStr, AddressSegment<UDT>);



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct UTPSegment;

derive_for_empty_segment!(UTPSegment: Display, FromStr, AddressSegment<UTP>);



#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IPFSSegment(pub cid::Cid);

derive_for_wrapping_segment!(IPFSSegment: Display, From<cid::Cid>);
impl IPFSSegment {
    fn _read_cid_polyfill(stream: &mut io::Read) -> Result<cid::Cid> {
        // Read minimal CID length at start to check for CIDv0
        let mut buf = [0u8; 34];
        stream.read_exact(&mut buf)?;

        if cid::Version::is_v0_binary(&buf) {
            Ok(cid::Cid::from(&buf as &[u8])?)
        } else {
            // Do normal CID parsing using the already read data
            let mut stream = Cursor::new(&buf as &[u8]).chain(stream);

            // Read and parse CID header
            let raw_version = stream.read_varint()?;
            let raw_codec = stream.read_varint()?;
            let _: u64 = stream.read_varint()?;

            let version = cid::Version::from(raw_version)?;
            let codec = cid::Codec::from(raw_codec)?;

            let mh_len = stream.read_varint()?;

            // Read CID hash data
            // (Unsafe because data in `Vec` contains uninitialized memory
            //  until we overwrite it with data read from `stream`.)
            let mut hash = Vec::with_capacity(mh_len);
            unsafe { hash.set_len(mh_len) };
            stream.read_exact(hash.as_mut())?;

            Ok(cid::Cid::new(codec, version, hash.as_slice()))
        }
    }
}

impl AddressSegment for IPFSSegment {
    const STREAM_LENGTH: usize = 34;

    fn protocol(&self) -> Protocol {
        Protocol::IPFS
    }

    fn from_stream(stream: &mut io::Read) -> Result<Self> {
        //FIXME: `cid::Prefix` creates its own `Cursor` instead of
        //       overloading `io::Read`

        // Read CID hash from stream
        let cid = Self::_read_cid_polyfill(stream).map_err(|err| {
            println!("CID Parsing failed!");
            err
        })?;

        Ok(IPFSSegment(cid))
    }

    fn to_stream(&self, mut stream: &mut io::Write) -> io::Result<()> {
        let bytes = self.0.to_bytes();

        stream.write_varint(bytes.len())?;
        stream.write_all(bytes.as_ref())?;

        Ok(())
    }
}

impl FromStr for IPFSSegment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        //FIXME: `cid::Cid` does not implement `FromStr`
        Ok(IPFSSegment(cid::Cid::from(s)?))
    }
}

impl hash::Hash for IPFSSegment {
    fn hash<H>(&self, state: &mut H) where H: hash::Hasher {
        //FIXME: `cid::Cid` does not derive `Hash`
        state.write_usize(self.0.version as usize);
        state.write_usize(self.0.codec as usize);
        hash::Hash::hash(&self.0.hash, state);
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct HTTPSegment;

derive_for_empty_segment!(HTTPSegment: Display, FromStr, AddressSegment<HTTP>);



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct HTTPSSegment;

derive_for_empty_segment!(HTTPSSegment: Display, FromStr, AddressSegment<HTTPS>);



//TODO: Properly parse and format union addresses
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OnionSegment(pub Box<[u8; 10]>);

derive_for_empty_segment!(OnionSegment: Display);
impl AddressSegment for OnionSegment {
    const STREAM_LENGTH: usize = 80;

    fn protocol(&self) -> Protocol {
        Protocol::Onion
    }

    fn from_stream(_: &mut io::Read) -> Result<Self> {
        Err(Error::ParsingError)
    }

    fn to_stream(&self, _: &mut io::Write) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl FromStr for OnionSegment {
    type Err = Error;

    fn from_str(_: &str) -> Result<Self> {
        Err(Error::ParsingError)
    }
}



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct WSSegment;

derive_for_empty_segment!(WSSegment: Display, FromStr, AddressSegment<WS>);



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct WSSSegment;

derive_for_empty_segment!(WSSSegment: Display, FromStr, AddressSegment<WSS>);



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Libp2pWebrtcStarSegment;

derive_for_empty_segment!(Libp2pWebrtcStarSegment: Display, FromStr, AddressSegment<Libp2pWebrtcStar>);



#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Libp2pWebrtcDirectSegment;

derive_for_empty_segment!(Libp2pWebrtcDirectSegment: Display, FromStr, AddressSegment<Libp2pWebrtcDirect>);



macro_rules! build_enums {
    { $( $val:expr => $var:ident ( $alph:expr ) for $addr_type:ident ),* } => {
        /// Protocol is the list of all possible protocols.
        //XXX: #[non_exhaustive] is not stable yet
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        pub enum Protocol {
            $( $var = $val, )*
            
            /// We want to be able to add new multiaddrs types in the future
            #[doc(hidden)]
            __Nonexhaustive
        }

        impl From<Protocol> for u64 {
            /// Convert to the matching integer code
            fn from(proto: Protocol) -> u64 {
                match proto {
                    $( Protocol::$var => $val, )*
                    _ => unreachable!()
                }
            }
        }

        impl ToString for Protocol {
            fn to_string(&self) -> String {
                self.as_str().to_string()
            }
        }

        impl FromStr for Protocol {
            type Err = Error;

            fn from_str(raw: &str) -> Result<Self> {
                match raw {
                    $( $alph => Ok(Protocol::$var), )*
                    _ => Err(Error::UnkownProtocolString)
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
                    $( $val => Ok(Protocol::$var), )*
                    _ => Err(Error::UnkownProtocol)
                }
            }

            /// Get the estimated size of the binary representation of this
            /// `Protocol` in bits.
            ///
            /// Note the values are only estimates and calling `.to_stream()`
            /// on a corresponding `Segment` instance may result in a buffer of a
            /// different size. The only noteworthy execption is a returned
            /// value of `0` which guarantees that the given protocol will
            /// never expect a value parameter and will never read or write
            /// anything when being asked to process serialize/deserialize
            /// itself.
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
                    $( Protocol::$var => ($addr_type::STREAM_LENGTH * 8) as isize, )*
                    _ => unreachable!()
                }
            }

            /// Obtain the name of this protocol variant as an human-readable
            /// string
            pub fn as_str(&self) -> &str {
                match *self {
                    $( Protocol::$var => $alph, )*
                    _ => unreachable!()
                }
            }
        }


        /// Enumeration of all known address segment types
        //XXX: #[non_exhaustive] is not stable yet
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        pub enum Segment {
            $( $var( $addr_type ), )*
            
            /// We want to be able to add new multiaddrs types in the future
            #[doc(hidden)]
            __Nonexhaustive
        }

        impl Segment {
            /// Create address segment for the given protocol number and with
            /// data from `stream`
            pub fn from_protocol_stream(protocol: Protocol, stream: &mut io::Read) -> Result<Self> {
                Ok(match protocol {
                    $( Protocol::$var => Segment::$var($addr_type::from_stream(stream)?), )*
                    _ => unreachable!()
                })
            }

            pub fn from_protocol_str(protocol: Protocol, s: &str) -> Result<Self> {
                Ok(match protocol {
                    $( Protocol::$var => Segment::$var($addr_type::from_str(s)?), )*
                    _ => unreachable!()
                })
            }
        }

        impl fmt::Display for Segment {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $( &Segment::$var(ref addr) => fmt::Display::fmt(addr, f), )*
                    _ => unreachable!()
                }
            }
        }

        impl AddressSegment for Segment {
            fn protocol(&self) -> Protocol {
                match self {
                    $( &Segment::$var(ref addr) => addr.protocol(), )*
                    _ => unreachable!()
                }
            }

            fn from_stream(mut stream: &mut io::Read) -> Result<Self> {
                let protocol = Protocol::from(stream.read_varint()?)?;
                Segment::from_protocol_stream(protocol, stream)
            }

            fn to_stream(&self, mut stream: &mut io::Write) -> io::Result<()> {
                match self {
                    $( &Segment::$var(ref addr) => {
                        // Write protocol number
                        stream.write_varint(u64::from(addr.protocol()))?;

                        // Serialize data of the underlying protocol
                        addr.to_stream(stream)?;
                    }, )*
                    
                    // Need extra match arm because of non-exhaustiveness
                    _ => unreachable!()
                }
                
                Ok(())
            }
        }

        impl Segment {
            /// Serialize only the variant's data to bytes
            ///
            /// Will return the result of calling `.to_bytes()` on the inner
            /// address segment instance.
            pub fn data_to_stream(&self, stream: &mut io::Write) -> io::Result<()> {
                match self {
                    $( &Segment::$var(ref addr) => addr.to_stream(stream), )*
                    _ => unreachable!()
                }
            }
        }
    }
}


build_enums!(
    // [IP4](https://en.wikipedia.org/wiki/IPv4)
    4 => IP4("ip4") for IP4Segment,
    // [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
    6 => TCP("tcp") for TCPSegment,
    // [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
    17 => UDP("udp") for UDPSegment,
    // [DCCP](https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol)
    33 => DCCP("dccp") for DCCPSegment,
    // [IP6](https://en.wikipedia.org/wiki/IPv6)
    41 => IP6("ip6") for IP6Segment,
    // [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol)
    132 => SCTP("sctp") for SCTPSegment,
    // [UDT](https://en.wikipedia.org/wiki/UDP-based_Data_Transfer_Protocol)
    301 => UDT("udt") for UDTSegment,
    // [UTP](https://en.wikipedia.org/wiki/Micro_Transport_Protocol)
    302 => UTP("utp") for UTPSegment,
    // [IPFS](https://github.com/ipfs/specs/tree/master/protocol#341-merkledag-paths)
    421 => IPFS("ipfs") for IPFSSegment,
    // [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)
    480 => HTTP("http") for HTTPSegment,
    // [HTTPS](https://en.wikipedia.org/wiki/HTTPS)
    443 => HTTPS("https") for HTTPSSegment,
    // Onion
    444 => Onion("onion") for OnionSegment,
    // Websockets
    477 => WS("ws") for WSSegment,
    // Websockets secure
    478 => WSS("wss") for WSSSegment,
    // libp2p webrtc protocols
    275 => Libp2pWebrtcStar("libp2p-webrtc-star") for Libp2pWebrtcStarSegment,
    276 => Libp2pWebrtcDirect("libp2p-webrtc-direct") for Libp2pWebrtcDirectSegment
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
    #[deprecated(note = "Use `Segment::from_protocol_str` and `.data_to_stream()` instead")]
    pub fn string_to_bytes(&self, a: &str) -> Result<Vec<u8>> {
        let mut vec = Vec::new();
        Segment::from_protocol_str(*self, a)?.data_to_stream(&mut vec).unwrap();
        Ok(vec)
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
    #[deprecated(note = "Use `Segment::from_protocol_stream` and `.to_string()` instead")]
    pub fn bytes_to_string(&self, b: &[u8]) -> Result<Option<String>> {
        let mut cursor = Cursor::new(b);

        let string = Segment::from_protocol_stream(*self, &mut cursor)?.to_string();
        if string.len() < 1 {
            Ok(None)
        } else {
            Ok(Some(string))
        }
    }
}
