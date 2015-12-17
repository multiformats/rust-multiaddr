extern crate multiaddr;

use multiaddr::*;

use std::net::{SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

#[test]
fn pt_into() {
    let proto: u16 = Protocol::IP4.into();
    assert_eq!(proto, 4u16);
}

#[test]
fn protocol_to_name() {
    assert_eq!(Protocol::TCP.to_string(), "tcp");
}

#[test]
fn multiaddr_eq() {
    let m1 = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();
    let m2 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap();
    let m3 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap();
    let m4 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234/").unwrap();

    assert!(m1 != m2);
    assert!(m2 != m1);
    assert!(m2 == m3);
    assert!(m1 == m1);
    assert!(m2 == m4);
    assert!(m4 == m3);
}

fn assert_bytes(source: &str, target: &[u8], protocols: Vec<Protocol>) -> () {
    let address = Multiaddr::new(source).unwrap();
    println!("source {:?}, target {:?}", source, target);
    assert_eq!(address.to_bytes(), target);
    assert_eq!(address.protocol(), protocols);
 }
fn assert_bytes_all(source: &str, target: &[u8], protocols: Vec<Protocol>) -> () {
    assert_bytes(source, target, protocols);
    assert_eq!(Multiaddr::new(source).unwrap().to_string(), source);
}

#[test]
fn byte_formats() {
    assert_bytes_all("/ip4/1.2.3.4", &[0, 4, 1, 2, 3, 4], vec![Protocol::IP4]);
    assert_bytes_all("/ip4/0.0.0.0", &[0, 4, 0, 0, 0, 0], vec![Protocol::IP4]);
    assert_bytes_all("/ip6/::1", &[
        0, 41,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ], vec![Protocol::IP6]);
    assert_bytes_all("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21", &[
        0, 41,
        38, 1, 0, 9, 79, 129, 151, 0, 128, 62, 202, 101, 102, 232, 12, 33
    ], vec![Protocol::IP6]);
    // assert_bytes_all("/onion/timaq4ygg2iegci7:1234", &[], vec![Protocol::Onion]);
    // assert_bytes_all("/onion/timaq4ygg2iegci7:80/http", &[], vec![Protocol::Onion]);
    assert_bytes_all("/udp/0", &[0, 17, 0, 0], vec![Protocol::UDP]);
    assert_bytes_all("/tcp/0", &[0, 6, 0, 0], vec![Protocol::TCP]);
    assert_bytes_all("/sctp/0", &[0, 132, 0, 0], vec![Protocol::SCTP]);
    assert_bytes_all("/udp/1234", &[0, 17, 4, 210], vec![Protocol::UDP]);
    assert_bytes_all("/tcp/1234", &[0, 6, 4, 210], vec![Protocol::TCP]);
    assert_bytes_all("/sctp/1234", &[0, 132, 4, 210], vec![Protocol::SCTP]);
    assert_bytes_all("/udp/65535", &[0, 17, 255, 255], vec![Protocol::UDP]);
    assert_bytes_all("/tcp/65535", &[0, 6, 255, 255], vec![Protocol::TCP]);
    // assert_bytes_all("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &[], vec![Protocol::IPFS]);
    assert_bytes_all("/udp/1234/sctp/1234", &[
        0, 17, 4, 210,
        0, 132, 4, 210
    ], vec![Protocol::UDP, Protocol::SCTP]);
    assert_bytes_all("/udp/1234/udt", &[
        0, 17, 4, 210,
        1, 46
    ], vec![Protocol::UDP, Protocol::UDT]);
    assert_bytes_all("/udp/1234/utp", &[
        0, 17, 4, 210,
        1, 45
    ], vec![Protocol::UDP, Protocol::UTP]);
    assert_bytes_all("/tcp/1234/http", &[
        0, 6, 4, 210,
        1, 224
    ], vec![Protocol::TCP, Protocol::HTTP]);
    assert_bytes_all("/tcp/1234/https", &[
        0, 6, 4, 210,
        1, 187
    ], vec![Protocol::TCP, Protocol::HTTPS]);
    // assert_bytes_all("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[
    // ], vec![Protocol::IPFS, Protocol::TCP]);
    assert_bytes_all("/ip4/127.0.0.1/udp/1234", &[
        0, 4, 127, 0, 0, 1,
        0, 17, 4, 210
    ], vec![Protocol::IP4, Protocol::UDP]);
    assert_bytes_all("/ip4/127.0.0.1/udp/0", &[
        0, 4, 127, 0, 0, 1,
        0, 17, 0, 0
    ], vec![Protocol::IP4, Protocol::UDP]);
    assert_bytes_all("/ip4/127.0.0.1/tcp/1234", &[
        0, 4, 127, 0, 0, 1,
        0, 6, 4, 210
    ], vec![Protocol::IP4, Protocol::TCP]);
    assert_bytes("/ip4/127.0.0.1/tcp/1234/", &[
        0, 4, 127, 0, 0, 1,
        0, 6, 4, 210
    ], vec![Protocol::IP4, Protocol::TCP]);
    // assert_bytes_all("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &[], vec![]);
    // assert_bytes_all("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[], vec![]);
}

// #[test]
// fn multiaddr_new_fail() {
//     let addresses = [
//         "/ip4",
// 	"/ip4/::1",
// 	"/ip4/fdpsofodsajfdoisa",
// 	"/ip6",
// 	"/udp",
// 	"/tcp",
// 	"/sctp",
// 	"/udp/65536",
// 	"/tcp/65536",
// 	"/onion/9imaq4ygg2iegci7:80",
// 	"/onion/aaimaq4ygg2iegci7:80",
// 	"/onion/timaq4ygg2iegci7:0",
// 	"/onion/timaq4ygg2iegci7:-1",
// 	"/onion/timaq4ygg2iegci7",
// 	"/onion/timaq4ygg2iegci@:666",
// 	"/udp/1234/sctp",
// 	"/udp/1234/udt/1234",
// 	"/udp/1234/utp/1234",
// 	"/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
// 	"/ip4/127.0.0.1/udp",
// 	"/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
// 	"/ip4/127.0.0.1/tcp",
// 	"/ip4/127.0.0.1/ipfs",
// 	"/ip4/127.0.0.1/ipfs/tcp",
//     ];

//     for address in &addresses {
//         assert!(Multiaddr::new(address).is_err());
//     }
// }


#[test]
fn to_multiaddr() {
    assert_eq!(
        Ipv4Addr::new(127, 0, 0, 1).to_multiaddr().unwrap(),
        Multiaddr::new("/ip4/127.0.0.1").unwrap()
    );
    assert_eq!(
        Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21).to_multiaddr().unwrap(),
        Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21").unwrap()
    );
    assert_eq!(
        "/ip4/127.0.0.1/tcp/1234".to_string().to_multiaddr().unwrap(),
        Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap()
    );
    assert_eq!(
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21".to_multiaddr().unwrap(),
        Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21").unwrap()
    );
    assert_eq!(
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234).to_multiaddr().unwrap(),
        Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap()
    );
    assert_eq!(
        SocketAddrV6::new(Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21), 1234, 0, 0).to_multiaddr().unwrap(),
        Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21/tcp/1234").unwrap()
    );
}
