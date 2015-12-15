extern crate multiaddr;

use multiaddr::*;

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


fn assert_bytes(source: &str, target: &[u8], protocols: Vec<ProtocolTypes>) -> () {
    let address = Multiaddr::new(source).unwrap();
    println!("source {:?}, target {:?}", source, target);
    assert_eq!(address.to_bytes(), target);
    assert_eq!(address.protocols(), protocols);
}

#[test]
fn byte_formats() {
    assert_bytes("/ip4/1.2.3.4", &[0, 4, 1, 2, 3, 4], vec![ProtocolTypes::IP4]);
    assert_bytes("/ip4/0.0.0.0", &[0, 4, 0, 0, 0, 0], vec![ProtocolTypes::IP4]);
    assert_bytes("/ip6/::1", &[
        0, 41,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ], vec![ProtocolTypes::IP6]);
    assert_bytes("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21", &[
        0, 41,
        38, 1, 0, 9, 79, 129, 151, 0, 128, 62, 202, 101, 102, 232, 12, 33
    ], vec![ProtocolTypes::IP6]);
    // assert_bytes("/onion/timaq4ygg2iegci7:1234", &[], vec![ProtocolTypes::Onion]);
    // assert_bytes("/onion/timaq4ygg2iegci7:80/http", &[], vec![ProtocolTypes::Onion]);
    assert_bytes("/udp/0", &[0, 17, 0, 0], vec![ProtocolTypes::UDP]);
    assert_bytes("/tcp/0", &[0, 6, 0, 0], vec![ProtocolTypes::TCP]);
    assert_bytes("/sctp/0", &[0, 132, 0, 0], vec![ProtocolTypes::SCTP]);
    assert_bytes("/udp/1234", &[0, 17, 4, 210], vec![ProtocolTypes::UDP]);
    assert_bytes("/tcp/1234", &[0, 6, 4, 210], vec![ProtocolTypes::TCP]);
    assert_bytes("/sctp/1234", &[0, 132, 4, 210], vec![ProtocolTypes::SCTP]);
    assert_bytes("/udp/65535", &[0, 17, 255, 255], vec![ProtocolTypes::UDP]);
    assert_bytes("/tcp/65535", &[0, 6, 255, 255], vec![ProtocolTypes::TCP]);
    // assert_bytes("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &[], vec![ProtocolTypes::IPFS]);
    assert_bytes("/udp/1234/sctp/1234", &[
        0, 17, 4, 210,
        0, 132, 4, 210
    ], vec![ProtocolTypes::UDP, ProtocolTypes::SCTP]);
    assert_bytes("/udp/1234/udt", &[
        0, 17, 4, 210,
        1, 46
    ], vec![ProtocolTypes::UDP, ProtocolTypes::UDT]);
    assert_bytes("/udp/1234/utp", &[
        0, 17, 4, 210,
        1, 45
    ], vec![ProtocolTypes::UDP, ProtocolTypes::UTP]);
    assert_bytes("/tcp/1234/http", &[
        0, 6, 4, 210,
        1, 224
    ], vec![ProtocolTypes::TCP, ProtocolTypes::HTTP]);
    assert_bytes("/tcp/1234/https", &[
        0, 6, 4, 210,
        1, 187
    ], vec![ProtocolTypes::TCP, ProtocolTypes::HTTPS]);
    // assert_bytes("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[
    // ], vec![ProtocolTypes::IPFS, ProtocolTypes::TCP]);
    assert_bytes("/ip4/127.0.0.1/udp/1234", &[
        0, 4, 127, 0, 0, 1,
        0, 17, 4, 210
    ], vec![ProtocolTypes::IP4, ProtocolTypes::UDP]);
    assert_bytes("/ip4/127.0.0.1/udp/0", &[
        0, 4, 127, 0, 0, 1,
        0, 17, 0, 0
    ], vec![ProtocolTypes::IP4, ProtocolTypes::UDP]);
    assert_bytes("/ip4/127.0.0.1/tcp/1234", &[
        0, 4, 127, 0, 0, 1,
        0, 6, 4, 210
    ], vec![ProtocolTypes::IP4, ProtocolTypes::TCP]);
    assert_bytes("/ip4/127.0.0.1/tcp/1234/", &[
        0, 4, 127, 0, 0, 1,
        0, 6, 4, 210
    ], vec![ProtocolTypes::IP4, ProtocolTypes::TCP]);
    // assert_bytes("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &[], vec![]);
    // assert_bytes("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[], vec![]);
}

#[test]
fn multiaddr_new_fail() {
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
	"/udp/1234/sctp",
	"/udp/1234/udt/1234",
	"/udp/1234/utp/1234",
	"/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
	"/ip4/127.0.0.1/udp",
	"/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
	"/ip4/127.0.0.1/tcp",
	"/ip4/127.0.0.1/ipfs",
	"/ip4/127.0.0.1/ipfs/tcp",
    ];

    for address in &addresses {
        assert!(Multiaddr::new(address).is_err());
    }
}

#[test]
fn pt_into() {
    let proto: u16 = ProtocolTypes::IP4.into();
    assert_eq!(proto, 4u16);
}

#[test]
fn pt_from() {

}
