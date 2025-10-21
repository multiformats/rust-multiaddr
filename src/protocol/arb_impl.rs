use std::borrow::Cow;

use crate::{protocol::arb_util::SubString, Multiaddr, Protocol};

impl quickcheck::Arbitrary for Multiaddr {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let iter = (0..u8::arbitrary(g) % 128).map(|_| Protocol::arbitrary(g));
        Multiaddr::from_iter(iter)
    }
}

impl quickcheck::Arbitrary for Protocol<'static> {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        use quickcheck::Arbitrary;
        use std::iter;
        use strum::EnumCount;
        match usize::arbitrary(g) % Protocol::COUNT {
            0 => Protocol::Dccp(Arbitrary::arbitrary(g)),
            1 => Protocol::Dns(Cow::Owned(SubString::arbitrary(g).0)),
            2 => Protocol::Dns4(Cow::Owned(SubString::arbitrary(g).0)),
            3 => Protocol::Dns6(Cow::Owned(SubString::arbitrary(g).0)),
            4 => Protocol::Dnsaddr(Cow::Owned(SubString::arbitrary(g).0)),
            5 => Protocol::Http,
            6 => Protocol::Https,
            7 => Protocol::Ip4(std::net::Ipv4Addr::arbitrary(g)),
            8 => Protocol::Ip6(std::net::Ipv6Addr::arbitrary(g)),
            9 => Protocol::P2pWebRtcDirect,
            10 => Protocol::P2pWebRtcStar,
            11 => Protocol::WebRTCDirect,
            12 => Protocol::Certhash(crate::protocol::Multihash::arbitrary(g)),
            13 => Protocol::P2pWebSocketStar,
            14 => Protocol::Memory(Arbitrary::arbitrary(g)),
            15 => {
                let a = iter::repeat_with(|| u8::arbitrary(g))
                    .take(10)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Protocol::Onion(Cow::Owned(a), std::cmp::max(1, u16::arbitrary(g)))
            }
            16 => {
                let a: [u8; 35] = iter::repeat_with(|| u8::arbitrary(g))
                    .take(35)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Protocol::Onion3((a, std::cmp::max(1, u16::arbitrary(g))).into())
            }
            17 => Protocol::P2p(crate::protocol::arb_util::PId::arbitrary(g).0),
            18 => Protocol::P2pCircuit,
            19 => Protocol::Quic,
            20 => Protocol::QuicV1,
            21 => Protocol::Sctp(Arbitrary::arbitrary(g)),
            22 => Protocol::Tcp(Arbitrary::arbitrary(g)),
            23 => Protocol::Tls,
            24 => Protocol::Noise,
            25 => Protocol::Udp(Arbitrary::arbitrary(g)),
            26 => Protocol::Udt,
            27 => Protocol::Unix(Cow::Owned(SubString::arbitrary(g).0)),
            28 => Protocol::Utp,
            29 => Protocol::WebTransport,
            30 => Protocol::Ws("/".into()),
            31 => Protocol::Wss("/".into()),
            32 => Protocol::Ip6zone(Cow::Owned(SubString::arbitrary(g).0)),
            33 => Protocol::Ipcidr(Arbitrary::arbitrary(g)),
            34 => {
                let len = usize::arbitrary(g) % (462 - 387) + 387;
                let a = iter::repeat_with(|| u8::arbitrary(g))
                    .take(len)
                    .collect::<Vec<_>>();
                Protocol::Garlic64(Cow::Owned(a))
            }
            35 => {
                let len = if bool::arbitrary(g) {
                    32
                } else {
                    usize::arbitrary(g) % 128 + 35
                };
                let a = iter::repeat_with(|| u8::arbitrary(g))
                    .take(len)
                    .collect::<Vec<_>>();
                Protocol::Garlic32(Cow::Owned(a))
            }
            36 => Protocol::Sni(Cow::Owned(SubString::arbitrary(g).0)),
            37 => Protocol::P2pStardust,
            38 => Protocol::WebRTC,
            39 => Protocol::HttpPath(Cow::Owned(SubString::arbitrary(g).0)),
            _ => panic!("outside range"),
        }
    }
}
