use crate::onion_addr::Onion3Addr;
use crate::{Error, Result};
use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use data_encoding::BASE32;
use libp2p_identity::PeerId;
use std::{
    borrow::Cow,
    convert::From,
    fmt,
    io::{Cursor, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::{self, FromStr},
};
use unsigned_varint::{decode, encode};

// All the values are obtained by converting hexadecimal protocol codes to u32.
// Protocols as well as their corresponding codes are defined in
// https://github.com/multiformats/multiaddr/blob/master/protocols.csv .
const IP4: u32 = 4;
const TCP: u32 = 6;
const UDP: u32 = 273;
const DCCP: u32 = 33;
const IP6: u32 = 41;
const IP6ZONE: u32 = 42;
const IPCIDR: u32 = 43;
const DNS: u32 = 53;
const DNS4: u32 = 54;
const DNS6: u32 = 55;
const DNSADDR: u32 = 56;
const SCTP: u32 = 132;
const UDT: u32 = 301;
const UTP: u32 = 302;
const UNIX: u32 = 400;
const P2P: u32 = 421;
// const IPFS: u32 = 421; // Deprecated
const ONION: u32 = 444;
const ONION3: u32 = 445;
const GARLIC64: u32 = 446;
const GARLIC32: u32 = 447;
const TLS: u32 = 448;
const SNI: u32 = 449;
const NOISE: u32 = 454;
const QUIC: u32 = 460;
const QUIC_V1: u32 = 461;
const WEBTRANSPORT: u32 = 465;
const CERTHASH: u32 = 466;
const HTTP: u32 = 480;
const HTTPS: u32 = 443; // Deprecated - alias for /tls/http
const WS: u32 = 477;
const WS_WITH_PATH: u32 = 4770; // Note: not standard
const WSS: u32 = 478; // Deprecated - alias for /tls/ws
const WSS_WITH_PATH: u32 = 4780; // Note: not standard
const P2P_WEBSOCKET_STAR: u32 = 479; // Deprecated
const P2P_STARDUST: u32 = 277; // Deprecated
const P2P_WEBRTC_STAR: u32 = 275; // Deprecated
const P2P_WEBRTC_DIRECT: u32 = 276; // Deprecated
const WEBRTC_DIRECT: u32 = 280;
const WEBRTC: u32 = 281;
const P2P_CIRCUIT: u32 = 290;
const MEMORY: u32 = 777;

/// Type-alias for how multi-addresses use `Multihash`.
///
/// The `64` defines the allocation size for the digest within the `Multihash`.
/// This allows us to use hashes such as SHA512.
/// In case protocols like `/certhash` ever support hashes larger than that, we will need to update this size here (which will be a breaking change!).
type Multihash = multihash::Multihash<64>;

const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b'%')
    .add(b'/')
    .add(b'`')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>');

/// `Protocol` describes all possible multiaddress protocols.
///
/// For `Unix`, `Ws` and `Wss` we use `&str` instead of `Path` to allow
/// cross-platform usage of `Protocol` since encoding `Paths` to bytes is
/// platform-specific. This means that the actual validation of paths needs to
/// happen separately.
#[derive(PartialEq, Eq, Clone, Debug)]
#[non_exhaustive]
pub enum Protocol<'a> {
    Ip4(Ipv4Addr),
    Tcp(u16),
    Udp(u16),
    Dccp(u16),
    Ip6(Ipv6Addr),
    Ip6zone(Cow<'a, str>),
    Ipcidr(u8),
    Dns(Cow<'a, str>),
    Dns4(Cow<'a, str>),
    Dns6(Cow<'a, str>),
    Dnsaddr(Cow<'a, str>),
    Sctp(u16),
    Udt,
    Utp,
    Unix(Cow<'a, str>),
    P2p(PeerId),
    Onion(Cow<'a, [u8; 10]>, u16),
    Onion3(Onion3Addr<'a>),
    Garlic64(Cow<'a, [u8]>),
    Garlic32(Cow<'a, [u8]>),
    Tls,
    Sni(Cow<'a, str>),
    Noise,
    Quic,
    QuicV1,
    WebTransport,
    Certhash(Multihash),
    Http,
    Https,
    Ws(Cow<'a, str>),
    Wss(Cow<'a, str>),
    P2pWebSocketStar,
    P2pStardust,
    P2pWebRtcStar,
    P2pWebRtcDirect,
    WebRTCDirect,
    WebRTC,
    P2pCircuit,
    /// Contains the "port" to contact. Similar to TCP or UDP, 0 means "assign me a port".
    Memory(u64),
}

impl<'a> Protocol<'a> {
    /// Parse a protocol value from the given iterator of string slices.
    ///
    /// The parsing only consumes the minimum amount of string slices necessary to
    /// produce a well-formed protocol. The same iterator can thus be used to parse
    /// a sequence of protocols in succession. It is up to client code to check
    /// that iteration has finished whenever appropriate.
    pub fn from_str_parts<I>(mut iter: I) -> Result<Self>
    where
        I: Iterator<Item = &'a str>,
    {
        match iter.next().ok_or(Error::InvalidProtocolString)? {
            "ip4" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ip4(Ipv4Addr::from_str(s)?))
            }
            "tcp" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Tcp(s.parse()?))
            }
            "udp" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Udp(s.parse()?))
            }
            "dccp" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dccp(s.parse()?))
            }
            "ip6" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ip6(Ipv6Addr::from_str(s)?))
            }
            "ip6zone" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ip6zone(Cow::Borrowed(s)))
            }
            "ipcidr" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ipcidr(s.parse()?))
            }
            "dns" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dns(Cow::Borrowed(s)))
            }
            "dns4" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dns4(Cow::Borrowed(s)))
            }
            "dns6" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dns6(Cow::Borrowed(s)))
            }
            "dnsaddr" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dnsaddr(Cow::Borrowed(s)))
            }
            "sctp" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Sctp(s.parse()?))
            }
            "udt" => Ok(Protocol::Udt),
            "utp" => Ok(Protocol::Utp),
            "unix" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Unix(Cow::Borrowed(s)))
            }
            "p2p" | "ipfs" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                let decoded = multibase::Base::Base58Btc.decode(s)?;
                let peer_id =
                    PeerId::from_bytes(&decoded).map_err(|e| Error::ParsingError(Box::new(e)))?;
                Ok(Protocol::P2p(peer_id))
            }
            "onion" => iter
                .next()
                .ok_or(Error::InvalidProtocolString)
                .and_then(|s| read_onion(&s.to_uppercase()))
                .map(|(a, p)| Protocol::Onion(Cow::Owned(a), p)),
            "onion3" => iter
                .next()
                .ok_or(Error::InvalidProtocolString)
                .and_then(|s| read_onion3(&s.to_uppercase()))
                .map(|(a, p)| Protocol::Onion3((a, p).into())),
            "garlic64" => {
                let s = iter
                    .next()
                    .ok_or(Error::InvalidProtocolString)?
                    .replace('-', "+")
                    .replace('~', "/");

                if s.len() < 516 || s.len() > 616 {
                    return Err(Error::InvalidProtocolString);
                }

                let decoded = multibase::Base::Base64.decode(s)?;
                Ok(Protocol::Garlic64(Cow::from(decoded)))
            }
            "garlic32" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;

                if s.len() < 55 && s.len() != 52 {
                    return Err(Error::InvalidProtocolString);
                }

                let decoded = multibase::Base::Base32Lower.decode(s)?;
                Ok(Protocol::Garlic32(Cow::from(decoded)))
            }
            "tls" => Ok(Protocol::Tls),
            "sni" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Sni(Cow::Borrowed(s)))
            }
            "noise" => Ok(Protocol::Noise),
            "quic" => Ok(Protocol::Quic),
            "quic-v1" => Ok(Protocol::QuicV1),
            "webtransport" => Ok(Protocol::WebTransport),
            "certhash" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                let (_base, decoded) = multibase::decode(s)?;
                Ok(Protocol::Certhash(Multihash::from_bytes(&decoded)?))
            }
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            "ws" => Ok(Protocol::Ws(Cow::Borrowed("/"))),
            "x-parity-ws" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                let decoded = percent_encoding::percent_decode(s.as_bytes()).decode_utf8()?;
                Ok(Protocol::Ws(decoded))
            }
            "wss" => Ok(Protocol::Wss(Cow::Borrowed("/"))),
            "x-parity-wss" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                let decoded = percent_encoding::percent_decode(s.as_bytes()).decode_utf8()?;
                Ok(Protocol::Wss(decoded))
            }
            "p2p-websocket-star" => Ok(Protocol::P2pWebSocketStar),
            "p2p-stardust" => Ok(Protocol::P2pStardust),
            "p2p-webrtc-star" => Ok(Protocol::P2pWebRtcStar),
            "p2p-webrtc-direct" => Ok(Protocol::P2pWebRtcDirect),
            "webrtc-direct" => Ok(Protocol::WebRTCDirect),
            "webrtc" => Ok(Protocol::WebRTC),
            "p2p-circuit" => Ok(Protocol::P2pCircuit),
            "memory" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Memory(s.parse()?))
            }
            unknown => Err(Error::UnknownProtocolString(unknown.to_string())),
        }
    }

    /// Parse a single `Protocol` value from its byte slice representation,
    /// returning the protocol as well as the remaining byte slice.
    pub fn from_bytes(input: &'a [u8]) -> Result<(Self, &'a [u8])> {
        fn split_at(n: usize, input: &[u8]) -> Result<(&[u8], &[u8])> {
            if input.len() < n {
                return Err(Error::DataLessThanLen);
            }
            Ok(input.split_at(n))
        }
        let (id, input) = decode::u32(input)?;
        match id {
            IP4 => {
                let (data, rest) = split_at(4, input)?;
                Ok((
                    Protocol::Ip4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    rest,
                ))
            }
            TCP => {
                let (data, rest) = split_at(2, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.read_u16::<BigEndian>()?;
                Ok((Protocol::Tcp(num), rest))
            }
            UDP => {
                let (data, rest) = split_at(2, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.read_u16::<BigEndian>()?;
                Ok((Protocol::Udp(num), rest))
            }
            DCCP => {
                let (data, rest) = split_at(2, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.read_u16::<BigEndian>()?;
                Ok((Protocol::Dccp(num), rest))
            }
            IP6 => {
                let (data, rest) = split_at(16, input)?;
                let mut rdr = Cursor::new(data);
                let mut seg = [0_u16; 8];

                for x in seg.iter_mut() {
                    *x = rdr.read_u16::<BigEndian>()?;
                }

                let addr = Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                );

                Ok((Protocol::Ip6(addr), rest))
            }
            IP6ZONE => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((
                    Protocol::Ip6zone(Cow::Borrowed(str::from_utf8(data)?)),
                    rest,
                ))
            }
            IPCIDR => {
                let (data, rest) = split_at(1, input)?;
                Ok((Protocol::Ipcidr(data[0]), rest))
            }
            DNS => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Dns(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            DNS4 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Dns4(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            DNS6 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Dns6(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            DNSADDR => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((
                    Protocol::Dnsaddr(Cow::Borrowed(str::from_utf8(data)?)),
                    rest,
                ))
            }
            SCTP => {
                let (data, rest) = split_at(2, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.read_u16::<BigEndian>()?;
                Ok((Protocol::Sctp(num), rest))
            }
            UDT => Ok((Protocol::Udt, input)),
            UTP => Ok((Protocol::Utp, input)),
            UNIX => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Unix(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            P2P => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((
                    Protocol::P2p(
                        PeerId::from_bytes(data).map_err(|e| Error::ParsingError(Box::new(e)))?,
                    ),
                    rest,
                ))
            }
            ONION => {
                let (data, rest) = split_at(12, input)?;
                let port = BigEndian::read_u16(&data[10..]);
                Ok((
                    Protocol::Onion(Cow::Borrowed(array_ref!(data, 0, 10)), port),
                    rest,
                ))
            }
            ONION3 => {
                let (data, rest) = split_at(37, input)?;
                let port = BigEndian::read_u16(&data[35..]);
                Ok((
                    Protocol::Onion3((array_ref!(data, 0, 35), port).into()),
                    rest,
                ))
            }
            GARLIC64 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Garlic64(Cow::Borrowed(data)), rest))
            }
            GARLIC32 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Garlic32(Cow::Borrowed(data)), rest))
            }
            TLS => Ok((Protocol::Tls, input)),
            SNI => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Sni(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            NOISE => Ok((Protocol::Noise, input)),
            QUIC => Ok((Protocol::Quic, input)),
            QUIC_V1 => Ok((Protocol::QuicV1, input)),
            WEBTRANSPORT => Ok((Protocol::WebTransport, input)),
            CERTHASH => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Certhash(Multihash::from_bytes(data)?), rest))
            }
            HTTP => Ok((Protocol::Http, input)),
            HTTPS => Ok((Protocol::Https, input)),
            WS => Ok((Protocol::Ws(Cow::Borrowed("/")), input)),
            WS_WITH_PATH => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Ws(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            WSS => Ok((Protocol::Wss(Cow::Borrowed("/")), input)),
            WSS_WITH_PATH => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_at(n, input)?;
                Ok((Protocol::Wss(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            P2P_WEBSOCKET_STAR => Ok((Protocol::P2pWebSocketStar, input)),
            P2P_STARDUST => Ok((Protocol::P2pStardust, input)),
            P2P_WEBRTC_STAR => Ok((Protocol::P2pWebRtcStar, input)),
            P2P_WEBRTC_DIRECT => Ok((Protocol::P2pWebRtcDirect, input)),
            WEBRTC_DIRECT => Ok((Protocol::WebRTCDirect, input)),
            WEBRTC => Ok((Protocol::WebRTC, input)),
            P2P_CIRCUIT => Ok((Protocol::P2pCircuit, input)),
            MEMORY => {
                let (data, rest) = split_at(8, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.read_u64::<BigEndian>()?;
                Ok((Protocol::Memory(num), rest))
            }
            _ => Err(Error::UnknownProtocolId(id)),
        }
    }

    /// Encode this protocol by writing its binary representation into
    /// the given `Write` impl.
    pub fn write_bytes<W: Write>(&self, w: &mut W) -> Result<()> {
        let mut buf = encode::u32_buffer();
        match self {
            Protocol::Ip4(addr) => {
                w.write_all(encode::u32(IP4, &mut buf))?;
                w.write_all(&addr.octets())?
            }
            Protocol::Tcp(port) => {
                w.write_all(encode::u32(TCP, &mut buf))?;
                w.write_u16::<BigEndian>(*port)?
            }
            Protocol::Udp(port) => {
                w.write_all(encode::u32(UDP, &mut buf))?;
                w.write_u16::<BigEndian>(*port)?
            }
            Protocol::Dccp(port) => {
                w.write_all(encode::u32(DCCP, &mut buf))?;
                w.write_u16::<BigEndian>(*port)?
            }
            Protocol::Ip6(addr) => {
                w.write_all(encode::u32(IP6, &mut buf))?;
                for &segment in &addr.segments() {
                    w.write_u16::<BigEndian>(segment)?
                }
            }
            Protocol::Ip6zone(zone_id) => {
                w.write_all(encode::u32(IP6ZONE, &mut buf))?;
                let bytes = zone_id.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Ipcidr(mask) => {
                w.write_all(encode::u32(IPCIDR, &mut buf))?;
                w.write_u8(*mask)?
            }
            Protocol::Dns(s) => {
                w.write_all(encode::u32(DNS, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Dns4(s) => {
                w.write_all(encode::u32(DNS4, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Dns6(s) => {
                w.write_all(encode::u32(DNS6, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Dnsaddr(s) => {
                w.write_all(encode::u32(DNSADDR, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Sctp(port) => {
                w.write_all(encode::u32(SCTP, &mut buf))?;
                w.write_u16::<BigEndian>(*port)?
            }
            Protocol::Udt => w.write_all(encode::u32(UDT, &mut buf))?,
            Protocol::Utp => w.write_all(encode::u32(UTP, &mut buf))?,
            Protocol::Unix(s) => {
                w.write_all(encode::u32(UNIX, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::P2p(peer_id) => {
                w.write_all(encode::u32(P2P, &mut buf))?;
                let bytes = peer_id.to_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(&bytes)?
            }
            Protocol::Onion(addr, port) => {
                w.write_all(encode::u32(ONION, &mut buf))?;
                w.write_all(addr.as_ref())?;
                w.write_u16::<BigEndian>(*port)?
            }
            Protocol::Onion3(addr) => {
                w.write_all(encode::u32(ONION3, &mut buf))?;
                w.write_all(addr.hash().as_ref())?;
                w.write_u16::<BigEndian>(addr.port())?
            }
            Protocol::Garlic64(addr) => {
                w.write_all(encode::u32(GARLIC64, &mut buf))?;
                w.write_all(encode::usize(addr.len(), &mut encode::usize_buffer()))?;
                w.write_all(addr)?
            }
            Protocol::Garlic32(addr) => {
                w.write_all(encode::u32(GARLIC32, &mut buf))?;
                w.write_all(encode::usize(addr.len(), &mut encode::usize_buffer()))?;
                w.write_all(addr)?
            }
            Protocol::Tls => w.write_all(encode::u32(TLS, &mut buf))?,
            Protocol::Sni(s) => {
                w.write_all(encode::u32(SNI, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Noise => w.write_all(encode::u32(NOISE, &mut buf))?,
            Protocol::Quic => w.write_all(encode::u32(QUIC, &mut buf))?,
            Protocol::QuicV1 => w.write_all(encode::u32(QUIC_V1, &mut buf))?,
            Protocol::WebTransport => w.write_all(encode::u32(WEBTRANSPORT, &mut buf))?,
            Protocol::Certhash(hash) => {
                w.write_all(encode::u32(CERTHASH, &mut buf))?;
                let bytes = hash.to_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(&bytes)?
            }
            Protocol::Http => w.write_all(encode::u32(HTTP, &mut buf))?,
            Protocol::Https => w.write_all(encode::u32(HTTPS, &mut buf))?,
            Protocol::Ws(ref s) if s == "/" => w.write_all(encode::u32(WS, &mut buf))?,
            Protocol::Ws(s) => {
                w.write_all(encode::u32(WS_WITH_PATH, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::Wss(ref s) if s == "/" => w.write_all(encode::u32(WSS, &mut buf))?,
            Protocol::Wss(s) => {
                w.write_all(encode::u32(WSS_WITH_PATH, &mut buf))?;
                let bytes = s.as_bytes();
                w.write_all(encode::usize(bytes.len(), &mut encode::usize_buffer()))?;
                w.write_all(bytes)?
            }
            Protocol::P2pWebSocketStar => w.write_all(encode::u32(P2P_WEBSOCKET_STAR, &mut buf))?,
            Protocol::P2pStardust => w.write_all(encode::u32(P2P_STARDUST, &mut buf))?,
            Protocol::P2pWebRtcStar => w.write_all(encode::u32(P2P_WEBRTC_STAR, &mut buf))?,
            Protocol::P2pWebRtcDirect => w.write_all(encode::u32(P2P_WEBRTC_DIRECT, &mut buf))?,
            Protocol::WebRTCDirect => w.write_all(encode::u32(WEBRTC_DIRECT, &mut buf))?,
            Protocol::WebRTC => w.write_all(encode::u32(WEBRTC, &mut buf))?,
            Protocol::P2pCircuit => w.write_all(encode::u32(P2P_CIRCUIT, &mut buf))?,
            Protocol::Memory(port) => {
                w.write_all(encode::u32(MEMORY, &mut buf))?;
                w.write_u64::<BigEndian>(*port)?
            }
        }
        Ok(())
    }

    /// Turn this `Protocol` into one that owns its data, thus being valid for any lifetime.
    pub fn acquire<'b>(self) -> Protocol<'b> {
        use self::Protocol::*;
        match self {
            Ip4(a) => Ip4(a),
            Tcp(a) => Tcp(a),
            Udp(a) => Udp(a),
            Dccp(a) => Dccp(a),
            Ip6(a) => Ip6(a),
            Ip6zone(cow) => Ip6zone(Cow::Owned(cow.into_owned())),
            Ipcidr(mask) => Ipcidr(mask),
            Dns(cow) => Dns(Cow::Owned(cow.into_owned())),
            Dns4(cow) => Dns4(Cow::Owned(cow.into_owned())),
            Dns6(cow) => Dns6(Cow::Owned(cow.into_owned())),
            Dnsaddr(cow) => Dnsaddr(Cow::Owned(cow.into_owned())),
            Sctp(a) => Sctp(a),
            Udt => Udt,
            Utp => Utp,
            Unix(cow) => Unix(Cow::Owned(cow.into_owned())),
            P2p(a) => P2p(a),
            Onion(addr, port) => Onion(Cow::Owned(addr.into_owned()), port),
            Onion3(addr) => Onion3(addr.acquire()),
            Garlic64(addr) => Garlic64(Cow::Owned(addr.into_owned())),
            Garlic32(addr) => Garlic32(Cow::Owned(addr.into_owned())),
            Tls => Tls,
            Sni(cow) => Sni(Cow::Owned(cow.into_owned())),
            Noise => Noise,
            Quic => Quic,
            QuicV1 => QuicV1,
            WebTransport => WebTransport,
            Certhash(hash) => Certhash(hash),
            Http => Http,
            Https => Https,
            Ws(cow) => Ws(Cow::Owned(cow.into_owned())),
            Wss(cow) => Wss(Cow::Owned(cow.into_owned())),
            P2pWebSocketStar => P2pWebSocketStar,
            P2pStardust => P2pStardust,
            P2pWebRtcStar => P2pWebRtcStar,
            P2pWebRtcDirect => P2pWebRtcDirect,
            WebRTCDirect => WebRTCDirect,
            WebRTC => WebRTC,
            P2pCircuit => P2pCircuit,
            Memory(a) => Memory(a),
        }
    }

    pub fn tag(&self) -> &'static str {
        use self::Protocol::*;
        match self {
            Ip4(_) => "ip4",
            Tcp(_) => "tcp",
            Udp(_) => "udp",
            Dccp(_) => "dccp",
            Ip6(_) => "ip6",
            Ip6zone(_) => "ip6zone",
            Ipcidr(_) => "ipcidr",
            Dns(_) => "dns",
            Dns4(_) => "dns4",
            Dns6(_) => "dns6",
            Dnsaddr(_) => "dnsaddr",
            Sctp(_) => "sctp",
            Udt => "udt",
            Utp => "utp",
            Unix(_) => "unix",
            P2p(_) => "p2p",
            Onion(_, _) => "onion",
            Onion3(_) => "onion3",
            Garlic64(_) => "garlic64",
            Garlic32(_) => "garlic32",
            Tls => "tls",
            Sni(_) => "sni",
            Noise => "noise",
            Quic => "quic",
            QuicV1 => "quic-v1",
            WebTransport => "webtransport",
            Certhash(_) => "certhash",
            Http => "http",
            Https => "https",
            Ws(ref s) if s == "/" => "ws",
            Ws(_) => "x-parity-ws",
            Wss(ref s) if s == "/" => "wss",
            Wss(_) => "x-parity-wss",
            P2pWebSocketStar => "p2p-websocket-star",
            P2pStardust => "p2p-stardust",
            P2pWebRtcStar => "p2p-webrtc-star",
            P2pWebRtcDirect => "p2p-webrtc-direct",
            WebRTCDirect => "webrtc-direct",
            WebRTC => "webrtc",
            P2pCircuit => "p2p-circuit",
            Memory(_) => "memory",
        }
    }
}

impl<'a> fmt::Display for Protocol<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Protocol::*;
        write!(f, "/{}", self.tag())?;
        match self {
            Ip4(addr) => write!(f, "/{addr}"),
            Tcp(port) => write!(f, "/{port}"),
            Udp(port) => write!(f, "/{port}"),
            Dccp(port) => write!(f, "/{port}"),
            Ip6(addr) => write!(f, "/{addr}"),
            Ip6zone(zone) => write!(f, "/{zone}"),
            Ipcidr(mask) => write!(f, "/{mask}"),
            Dns(s) => write!(f, "/{s}"),
            Dns4(s) => write!(f, "/{s}"),
            Dns6(s) => write!(f, "/{s}"),
            Dnsaddr(s) => write!(f, "/{s}"),
            Sctp(port) => write!(f, "/{port}"),
            Unix(s) => write!(f, "/{s}"),
            P2p(c) => write!(f, "/{}", multibase::Base::Base58Btc.encode(c.to_bytes())),
            Onion(addr, port) => {
                let s = BASE32.encode(addr.as_ref());
                write!(f, "/{}:{}", s.to_lowercase(), port)
            }
            Onion3(addr) => {
                let s = BASE32.encode(addr.hash());
                write!(f, "/{}:{}", s.to_lowercase(), addr.port())
            }
            Garlic64(addr) => write!(
                f,
                "/{}",
                multibase::Base::Base64
                    .encode(addr)
                    .replace('+', "-")
                    .replace('/', "~")
            ),
            Garlic32(addr) => write!(f, "/{}", multibase::Base::Base32Lower.encode(addr)),
            Sni(s) => write!(f, "/{s}"),
            Certhash(hash) => write!(
                f,
                "/{}",
                multibase::encode(multibase::Base::Base64Url, hash.to_bytes())
            ),
            Ws(s) if s != "/" => {
                let encoded =
                    percent_encoding::percent_encode(s.as_bytes(), PATH_SEGMENT_ENCODE_SET);
                write!(f, "/{encoded}")
            }
            Wss(s) if s != "/" => {
                let encoded =
                    percent_encoding::percent_encode(s.as_bytes(), PATH_SEGMENT_ENCODE_SET);
                write!(f, "/{encoded}")
            }
            Memory(port) => write!(f, "/{port}"),
            _ => Ok(()),
        }
    }
}

impl<'a> From<IpAddr> for Protocol<'a> {
    #[inline]
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Protocol::Ip4(addr),
            IpAddr::V6(addr) => Protocol::Ip6(addr),
        }
    }
}

impl<'a> From<Ipv4Addr> for Protocol<'a> {
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        Protocol::Ip4(addr)
    }
}

impl<'a> From<Ipv6Addr> for Protocol<'a> {
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        Protocol::Ip6(addr)
    }
}

macro_rules! read_onion_impl {
    ($name:ident, $len:expr, $encoded_len:expr) => {
        fn $name(s: &str) -> Result<([u8; $len], u16)> {
            let mut parts = s.split(':');

            // address part (without ".onion")
            let b32 = parts.next().ok_or(Error::InvalidMultiaddr)?;
            if b32.len() != $encoded_len {
                return Err(Error::InvalidMultiaddr);
            }

            // port number
            let port = parts
                .next()
                .ok_or(Error::InvalidMultiaddr)
                .and_then(|p| str::parse(p).map_err(From::from))?;

            // port == 0 is not valid for onion
            if port == 0 {
                return Err(Error::InvalidMultiaddr);
            }

            // nothing else expected
            if parts.next().is_some() {
                return Err(Error::InvalidMultiaddr);
            }

            if $len
                != BASE32
                    .decode_len(b32.len())
                    .map_err(|_| Error::InvalidMultiaddr)?
            {
                return Err(Error::InvalidMultiaddr);
            }

            let mut buf = [0u8; $len];
            BASE32
                .decode_mut(b32.as_bytes(), &mut buf)
                .map_err(|_| Error::InvalidMultiaddr)?;

            Ok((buf, port))
        }
    };
}

// Parse a version 2 onion address and return its binary representation.
//
// Format: <base-32 address> ":" <port number>
read_onion_impl!(read_onion, 10, 16);
// Parse a version 3 onion address and return its binary representation.
//
// Format: <base-32 address> ":" <port number>
read_onion_impl!(read_onion3, 35, 56);
