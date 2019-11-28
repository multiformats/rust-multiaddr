extern crate data_encoding;
extern crate multiaddr;

use data_encoding::HEXUPPER;
use multiaddr::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[test]
fn protocol_to_code() {
    assert_eq!(Protocol::IP4 as usize, 4);
}

#[test]
fn protocol_to_name() {
    assert_eq!(Protocol::TCP.to_string(), "tcp");
}

fn ma_valid(source: &str, target: &str, protocols: Vec<Protocol>) {
    let parsed = source.parse::<Multiaddr>().unwrap();
    assert_eq!(HEXUPPER.encode(parsed.to_bytes().as_slice()), target);
    assert_eq!(
        parsed.iter().map(|addr| addr.protocol_id()).collect::<Vec<_>>(),
        protocols
    );
    assert_eq!(source.parse::<Multiaddr>().unwrap().to_string(), source);
    assert_eq!(
        Multiaddr::from_bytes(HEXUPPER.decode(target.as_bytes()).unwrap()).unwrap(),
        parsed
    );
}

#[test]
fn multiaddr_eq() {
    let m1 = "/ip4/127.0.0.1/udp/1234".parse::<Multiaddr>().unwrap();
    let m2 = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();
    let m3 = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();

    assert_ne!(m1, m2);
    assert_ne!(m2, m1);
    assert_eq!(m2, m3);
    assert_eq!(m1, m1);
}

#[test]
fn construct_success() {
    use Protocol::*;

    ma_valid("/ip4/1.2.3.4", "0401020304", vec![IP4]);
    ma_valid("/ip4/0.0.0.0", "0400000000", vec![IP4]);
    ma_valid("/ip6/::1", "2900000000000000000000000000000001", vec![IP6]);
    ma_valid(
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
        "29260100094F819700803ECA6566E80C21",
        vec![IP6],
    );
    ma_valid("/udp/0", "91020000", vec![UDP]);
    ma_valid("/tcp/0", "060000", vec![TCP]);
    ma_valid("/sctp/0", "84010000", vec![SCTP]);
    ma_valid("/udp/1234", "910204D2", vec![UDP]);
    ma_valid("/tcp/1234", "0604D2", vec![TCP]);
    ma_valid("/sctp/1234", "840104D2", vec![SCTP]);
    ma_valid("/udp/65535", "9102FFFF", vec![UDP]);
    ma_valid("/tcp/65535", "06FFFF", vec![TCP]);
    ma_valid(
        "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![IPFS],
    );
    ma_valid("/udp/1234/sctp/1234", "910204D2840104D2", vec![UDP, SCTP]);
    ma_valid("/udp/1234/udt", "910204D2AD02", vec![UDP, UDT]);
    ma_valid("/udp/1234/utp", "910204D2AE02", vec![UDP, UTP]);
    ma_valid("/tcp/1234/http", "0604D2E003", vec![TCP, HTTP]);
    ma_valid("/tcp/1234/https", "0604D2BB03", vec![TCP, HTTPS]);
    ma_valid(
        "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
        "A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
        vec![IPFS, TCP],
    );
    ma_valid("/ip4/127.0.0.1/udp/1234", "047F000001910204D2", vec![IP4, UDP]);
    ma_valid("/ip4/127.0.0.1/udp/0", "047F00000191020000", vec![IP4, UDP]);
    ma_valid("/ip4/127.0.0.1/tcp/1234", "047F0000010604D2", vec![IP4, TCP]);
    ma_valid(
        "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "047F000001A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![IP4, IPFS],
    );
    ma_valid(
        "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
        "047F000001A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
        vec![IP4, IPFS, TCP],
    );
    // /unix/a/b/c/d/e,
    // /unix/stdio,
    // /ip4/1.2.3.4/tcp/80/unix/a/b/c/d/e/f,
    // /ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234/unix/stdio
    ma_valid(
        "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:\
         7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "29200108A07AC542013AC986FFFE317095061F40DD03A5\
         03221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![IP6, TCP, WS, IPFS],
    );
    ma_valid(
        "/p2p-webrtc-star/ip4/127.0.0.1/tcp/9090/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "9302047F000001062382DD03A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![Libp2pWebrtcStar, IP4, TCP, WS, IPFS],
    );
    ma_valid(
        "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:\
         7095/tcp/8000/wss/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "29200108A07AC542013AC986FFFE317095061F40DE03A503221220D52EBB8\
         9D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![IP6, TCP, WSS, IPFS],
    );
    ma_valid(
        "/ip4/127.0.0.1/tcp/9090/p2p-circuit/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "047F000001062382A202A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
        vec![IP4, TCP, P2pCircuit, IPFS],
    );

    ma_valid("/onion/aaimaq4ygg2iegci:80", "BC030010C0439831B48218480050", vec![
        ONION,
    ]);
    ma_valid(
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234",
        "BD03ADADEC040BE047F9658668B11A504F3155001F231A37F54C4476C07FB4CC139ED7E30304D2",
        vec![ONION3],
    );

    ma_valid(
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80/http",
        "BD03ADADEC040BE047F9658668B11A504F3155001F231A37F54C4476C07FB4CC139ED7E3030050E003",
        vec![ONION3, HTTP],
    );
}

#[test]
fn construct_fail() {
    let addresses = [
        "/ip4",
        "/ip4/::1",
        "/ip4/fdpsofodsajfdoisa",
        "/ip6",
        "/udp",
        "/tcp",
        "/sctp",
        "/udp/65536",
        "/tcp/65536",
        "/onion/9imaq4ygg2iegci7:80",
        "/onion/aaimaq4ygg2iegci7:80",
        "/onion/timaq4ygg2iegci7:0",
        "/onion/timaq4ygg2iegci7:-1",
        "/onion/timaq4ygg2iegci7",
        "/onion/timaq4ygg2iegci@:666",
        "/onion3/9ww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd7:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyy@:666",
        "/udp/1234/sctp",
        "/udp/1234/udt/1234",
        "/udp/1234/utp/1234",
        "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
        "/ip4/127.0.0.1/udp",
        "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
        "/ip4/127.0.0.1/tcp",
        "/ip4/127.0.0.1/ipfs",
        "/ip4/127.0.0.1/ipfs/tcp",
        "/p2p-circuit/50",
    ];

    for address in &addresses {
        assert!(address.parse::<Multiaddr>().is_err(), address.to_string());
    }
}

#[test]
fn to_multiaddr() {
    assert_eq!(
        Ipv4Addr::new(127, 0, 0, 1).to_multiaddr().unwrap(),
        "/ip4/127.0.0.1".parse::<Multiaddr>().unwrap()
    );
    assert_eq!(
        Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21)
            .to_multiaddr()
            .unwrap(),
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21".parse::<Multiaddr>().unwrap()
    );
    assert_eq!(
        "/ip4/127.0.0.1/tcp/1234".to_string().to_multiaddr().unwrap(),
        "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap()
    );
    assert_eq!(
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21".to_multiaddr().unwrap(),
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21".parse::<Multiaddr>().unwrap()
    );
    assert_eq!(
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)
            .to_multiaddr()
            .unwrap(),
        "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap()
    );
    assert_eq!(
        SocketAddrV6::new(
            Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21),
            1234,
            0,
            0
        )
        .to_multiaddr()
        .unwrap(),
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21/tcp/1234"
            .parse::<Multiaddr>()
            .unwrap()
    );
}

#[test]
fn from_bytes_fail() {
    let bytes = vec![1, 2, 3, 4];
    assert!(Multiaddr::from_bytes(bytes).is_err());
}
