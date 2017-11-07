extern crate multiaddr;
extern crate cid;
extern crate data_encoding;

use data_encoding::hex;
use multiaddr::*;
use std::net::{SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

#[test]
fn protocol_to_code() {
    assert_eq!(Protocol::IP4 as usize, 4);
}

#[test]
fn protocol_to_name() {
    assert_eq!(Protocol::TCP.to_string(), "tcp");
}


#[allow(deprecated)]
fn ma_valid(source: &str, target: &str, segments: &[Segment]) -> () {
	// Create MultiAddr from string
	let address = Multiaddr::new(source).unwrap();
	
	// Serialize MultiAddr to string and verify that it matches the original string
	assert_eq!(address.to_string(), source);
	
	// Serialize MultiAddr to bytes and compare with the expected value
	let bytes = address.to_bytes();
	assert_eq!(hex::encode(bytes.as_slice()), target);
	
	// Validate that the parsed MultiAddr representation matches the expected values
	assert_eq!(address.segments(), segments);
	
	// Validate that the parsed MultiAddr matches the original address
	assert_eq!(bytes.to_multiaddr().unwrap(), address);
	
	// Test the deprecated `.protocol()` API
	assert_eq!(address.protocol(), address.segments().iter().map(|s: &Segment| s.protocol()).collect::<Vec<Protocol>>());
}

#[test]
fn multiaddr_eq() {
    let m1 = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();
    let m2 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap();
    let m3 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap();
    let m4 = Multiaddr::new("/ip4/127.0.0.1/tcp/1234/").unwrap();

    assert_ne!(m1, m2);
    assert_ne!(m2, m1);
    assert_eq!(m2, m3);
    assert_eq!(m1, m1);
    assert_eq!(m2, m4);
    assert_eq!(m4, m3);
}

#[test]
fn construct_success() {
	use protocol::*;
	
	ma_valid("/ip4/1.2.3.4", "0401020304",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(1, 2, 3, 4)))]
	);
	ma_valid("/ip4/0.0.0.0", "0400000000",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(0, 0, 0, 0)))]
	);
	ma_valid("/ip6/::1", "2900000000000000000000000000000001",
		&[Segment::IP6(IP6Segment(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))]
	);
	ma_valid("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
		"29260100094F819700803ECA6566E80C21",
		&[Segment::IP6(IP6Segment(Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21)))]
	);
	
	ma_valid("/udp/0", "110000", &[Segment::UDP(UDPSegment(0))]);
	ma_valid("/tcp/0", "060000", &[Segment::TCP(TCPSegment(0))]);
	ma_valid("/sctp/0", "84010000", &[Segment::SCTP(SCTPSegment(0))]);
	ma_valid("/udp/1234", "1104D2", &[Segment::UDP(UDPSegment(1234))]);
	ma_valid("/tcp/1234", "0604D2", &[Segment::TCP(TCPSegment(1234))]);
	ma_valid("/sctp/1234", "840104D2", &[Segment::SCTP(SCTPSegment(1234))]);
	ma_valid("/udp/65535", "11FFFF", &[Segment::UDP(UDPSegment(65535))]);
	ma_valid("/tcp/65535", "06FFFF", &[Segment::TCP(TCPSegment(65535))]);
	
	
	
	ma_valid("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
		&[Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap()))]
	);
	ma_valid("/udp/1234/sctp/1234", "1104D2840104D2",
		&[Segment::UDP(UDPSegment(1234)), Segment::SCTP(SCTPSegment(1234))]
	);
	ma_valid("/udp/1234/udt", "1104D2AD02",
		&[Segment::UDP(UDPSegment(1234)), Segment::UDT(UDTSegment {})]
	);
	ma_valid("/udp/1234/utp", "1104D2AE02",
		&[Segment::UDP(UDPSegment(1234)), Segment::UTP(UTPSegment {})]
	);
	ma_valid("/tcp/1234/http", "0604D2E003",
		&[Segment::TCP(TCPSegment(1234)), Segment::HTTP(HTTPSegment {})]
	);
	ma_valid("/tcp/1234/https", "0604D2BB03",
		&[Segment::TCP(TCPSegment(1234)), Segment::HTTPS(HTTPSSegment {})]
	);
	
	ma_valid("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
		"A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
		&[Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap())),
		  Segment::TCP(TCPSegment(1234))]
	);
	ma_valid("/ip4/127.0.0.1/udp/1234", "047F0000011104D2",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::UDP(UDPSegment(1234))]
	);
	ma_valid("/ip4/127.0.0.1/udp/0", "047F000001110000",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::UDP(UDPSegment(0))]
	);
	ma_valid("/ip4/127.0.0.1/tcp/1234", "047F0000010604D2",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::TCP(TCPSegment(1234))]
	);
	ma_valid("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"047F000001A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap()))]
	);
	ma_valid("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
		"047F000001A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
		&[Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap())),
		  Segment::TCP(TCPSegment(1234))]
	);
	
	// /unix/a/b/c/d/e,
	// /unix/stdio,
	// /ip4/1.2.3.4/tcp/80/unix/a/b/c/d/e/f,
	// /ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234/unix/stdio
	ma_valid("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"29200108A07AC542013AC986FFFE317095061F40DD03A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
		&[Segment::IP6(IP6Segment(Ipv6Addr::new(0x2001, 0x8a0, 0x7ac5, 0x4201, 0x3ac9, 0x86ff, 0xfe31, 0x7095))),
		  Segment::TCP(TCPSegment(8000)),
		  Segment::WS(WSSegment {}),
		  Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap()))]
	);
	ma_valid("/libp2p-webrtc-star/ip4/127.0.0.1/tcp/9090/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"9302047F000001062382DD03A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
		&[Segment::Libp2pWebrtcStar(Libp2pWebrtcStarSegment {}),
		  Segment::IP4(IP4Segment(Ipv4Addr::new(127, 0, 0, 1))),
		  Segment::TCP(TCPSegment(9090)),
		  Segment::WS(WSSegment {}),
		  Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap()))]
	);
	ma_valid("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/wss/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"29200108A07AC542013AC986FFFE317095061F40DE03A503221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
		&[Segment::IP6(IP6Segment(Ipv6Addr::new(0x2001, 0x8a0, 0x7ac5, 0x4201, 0x3ac9, 0x86ff, 0xfe31, 0x7095))),
		  Segment::TCP(TCPSegment(8000)),
		  Segment::WSS(WSSSegment {}),
		  Segment::IPFS(IPFSSegment(cid::Cid::from("QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").unwrap()))]
	);
}

#[test]
fn construct_fail() {
    let addresses = ["/ip4",
                     "/ip4/::1",
                     "/ip4/fdpsofodsajfdoisa",
                     "/ip6",
                     "/udp",
                     "/tcp",
                     "/sctp",
                     "/udp/65536",
                     "/tcp/65536",
                     // "/onion/9imaq4ygg2iegci7:80",
                     // "/onion/aaimaq4ygg2iegci7:80",
                     // "/onion/timaq4ygg2iegci7:0",
                     // "/onion/timaq4ygg2iegci7:-1",
                     // "/onion/timaq4ygg2iegci7",
                     // "/onion/timaq4ygg2iegci@:666",
                     "/udp/1234/sctp",
                     "/udp/1234/udt/1234",
                     "/udp/1234/utp/1234",
                     "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
                     "/ip4/127.0.0.1/udp",
                     "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
                     "/ip4/127.0.0.1/tcp",
                     "/ip4/127.0.0.1/ipfs",
                     "/ip4/127.0.0.1/ipfs/tcp"];

    for address in &addresses {
        assert!(Multiaddr::new(address).is_err(), address.to_string());
    }
}


#[test]
fn to_multiaddr() {
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1).to_multiaddr().unwrap(),
               Multiaddr::new("/ip4/127.0.0.1").unwrap());
    assert_eq!(Ipv6Addr::new(0x2601, 0x9, 0x4f81, 0x9700, 0x803e, 0xca65, 0x66e8, 0xc21)
                   .to_multiaddr()
                   .unwrap(),
               Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21").unwrap());
    assert_eq!("/ip4/127.0.0.1/tcp/1234".to_string().to_multiaddr().unwrap(),
               Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap());
    assert_eq!("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21".to_multiaddr().unwrap(),
               Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21").unwrap());
    assert_eq!(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234).to_multiaddr().unwrap(),
               Multiaddr::new("/ip4/127.0.0.1/tcp/1234").unwrap());
    assert_eq!(SocketAddrV6::new(Ipv6Addr::new(0x2601,
                                               0x9,
                                               0x4f81,
                                               0x9700,
                                               0x803e,
                                               0xca65,
                                               0x66e8,
                                               0xc21),
                                 1234,
                                 0,
                                 0)
                   .to_multiaddr()
                   .unwrap(),
               Multiaddr::new("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21/tcp/1234").unwrap());
}
