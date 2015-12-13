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
