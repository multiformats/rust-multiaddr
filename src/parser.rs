use std::io;
use std::str::from_utf8;

use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use nom::IResult;

use ::protocol::Protocol;

/// Parse a single /
named!(sep <&[u8], &[u8]>, tag!("/"));

/// Parse the protocol part `/ip4`
named!(proto <&[u8], &str>, chain!(
    sep? ~
    a: map_res!(is_not!("/"), from_utf8),
    || {a}
));

/// Parse the the address part `/127.0.0.1`
named!(address, chain!(
           sep ~
    inner: is_not!("/"),
    || {inner}
));

/// Parse a single multiaddress in the form of `/ip4/127.0.0.1`.
named!(proto_with_address <&[u8], Vec<u8> >, chain!(
    t: proto  ~
    a: opt!(complete!(address)),
    || {
        let mut res: Vec<u8>= Vec::new();

        // TODO: Better error handling
        // Write the u16 code into the results vector
        if let Some(protocol) = Protocol::from_name(t) {
            res.write_u16::<BigEndian>(protocol as u16).unwrap();
            println!("wrote {:?}", protocol as u16);

            if let Some(a) = a {
                println!("Got an address {:?}", a);
                let a = from_utf8(a).unwrap();
                println!("{:?}, {:?}", protocol, a);
                let address_bytes = protocol.address_string_to_bytes(a).unwrap();
                println!("address {:?}", address_bytes);
                // Write the address into the results vector
                res.extend(address_bytes);
            }
        }

        res
    }
));

/// Parse a list of addresses
named!(addresses < &[u8], Vec< Vec<u8> > >, many1!(proto_with_address));


pub fn multiaddr_from_str(input: &str) -> io::Result<Vec<u8>> {
    match addresses(input.as_bytes()) {
        IResult::Done(i, res) => {
            println!("remain: {:?}", from_utf8(i).unwrap());
            let res = res.iter()
                .fold(Vec::new(), |mut v, a| {
                    v.extend(a.iter().cloned());
                    v
                });

            Ok(res)
        },
        e => {
            println!("{:?}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Failed to parse multiaddr"))
        },
    }
}

fn from_code(code: &[u8]) -> Protocol {
    let mut code = code;
    let code = code.read_u16::<BigEndian>().unwrap();
    println!("code {:?}", code);
    Protocol::from_code(code).unwrap()
}

fn take_size<'a>(i: &'a [u8], code: &[u8]) -> IResult<&'a [u8], &'a [u8]> {
    println!("taking size {:?}", from_code(code).size());
    println!("{:?}", i);
    take!(i, from_code(code).size() / 8)
}

named!(protocol < &[u8], Protocol >,
    chain!(
        code: take!(2) ~
        apply!(take_size, code),
        || {from_code(code)}
    )
);

named!(protocols < &[u8], Vec<Protocol> >, many1!(protocol));

named!(address_bytes < &[u8], String >,
    chain!(
        code: take!(2) ~
        addr: apply!(take_size, code),
        || {
            println!("code {:?}, {:?}", code, addr);
            let mut res = String::new();
            let protocol = from_code(code);
            let addr = protocol.bytes_to_string(addr);

            res.push('/');
            res.push_str(&protocol.to_string());

            if let Some(addr) = addr {
                res.push('/');
                res.push_str(&addr);
            }

            res
        }
    )
);

named!(addresses_bytes < &[u8], Vec<String> >, many1!(address_bytes));

/// Panics on invalid bytes as this would mean data corruption!
pub fn protocol_from_bytes(input: &[u8]) -> Vec<Protocol> {
    match protocols(input) {
        IResult::Done(i, res) => {
            println!("remaining {:?}", i);
            for p in &res {
                println!("results {:?}", p);
            }
            res
        },
        e => {
            println!("{:?}", e);
            panic!("Failed to parse internal bytes, possible corruption")
        },
    }
}


pub fn address_from_bytes(input: &[u8]) -> String {
    match addresses_bytes(input) {
        IResult::Done(i, addresses) => {
            let mut res = String::new();
            println!("remaining {:?}", i);
            for address in &addresses {
                println!("results {:?}", address);
                res.push_str(address);
            }
            res
        },
        e => {
            println!("{:?}", e);
            panic!("Failed to parse internal bytes, possible corruption")
        },
    }
}
