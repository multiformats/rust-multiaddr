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
fn multiaddr_from_string() {
    let mut target = vec![4u8, 0];
    target.append(&mut "127.0.0.1".to_string().into_bytes());
    target.append(&mut vec![17u8, 0]);
    target.append(&mut "1234".to_string().into_bytes());
    let bytes = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap().to_bytes();

    assert_eq!(
        bytes,
        target
    );
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
