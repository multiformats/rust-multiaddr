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
    assert!(
        Multiaddr::new("/ip4/127.0.0.1").unwrap() == Multiaddr::new("/ip4/127.0.0.1").unwrap()
    );
    assert!(
        Multiaddr::new("/ip4/127.0.0.1").unwrap() != Multiaddr::new("/ip4/128.0.0.1").unwrap()
    );
}


fn assert_bytes(source: &str, target: &[u8]) -> () {
    let address = Multiaddr::new(source).unwrap();
    assert_eq!(address.to_bytes(), target);
}

#[test]
fn byte_formats() {
    assert_bytes("/ip4/1.2.3.4", &[0, 4, 1, 2, 3, 4]);
    assert_bytes("/ip4/0.0.0.0", &[0, 4, 0, 0, 0, 0]);
    assert_bytes("/ip6/::1", &[
        0, 41,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ]);
    assert_bytes("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21", &[
        0, 41,
        38, 1, 0, 9, 79, 129, 151, 0, 128, 62, 202, 101, 102, 232, 12, 33
    ]);
    // assert_bytes("/onion/timaq4ygg2iegci7:1234", &[]);
    // assert_bytes("/onion/timaq4ygg2iegci7:80/http", &[]);
    assert_bytes("/udp/0", &[0, 17, 0, 0]);
    assert_bytes("/tcp/0", &[0, 6, 0, 0]);
    // assert_bytes("/sctp/0", &[]);
    assert_bytes("/udp/1234", &[0, 17, 4, 210]);
    assert_bytes("/tcp/1234", &[0, 6, 4, 210]);
    // assert_bytes("/sctp/1234", &[]);
    // assert_bytes("/udp/65535", &[0, 17, 0, 0]);
    // assert_bytes("/tcp/65535", &[0, 6, 0, 0]);
    // assert_bytes("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &[]);
    // assert_bytes("/udp/1234/sctp/1234", &[]);
    // assert_bytes("/udp/1234/udt", &[]);
    // assert_bytes("/udp/1234/utp", &[]);
    // assert_bytes("/tcp/1234/http", &[]);
    // assert_bytes("/tcp/1234/https", &[]);
    // assert_bytes("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[]);
    // assert_bytes("/ip4/127.0.0.1/udp/1234", &[]);
    // assert_bytes("/ip4/127.0.0.1/udp/0", &[]);
    // assert_bytes("/ip4/127.0.0.1/tcp/1234", &[]);
    // assert_bytes("/ip4/127.0.0.1/tcp/1234/", &[]);
    // assert_bytes("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", &&[]);
    // assert_bytes("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234", &[]);
}
