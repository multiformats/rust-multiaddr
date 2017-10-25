use std::str::FromStr;
use std::fmt::Write;

use protocol::{Addr, AddressSegment, Protocol};
use {Result, Error};

pub fn multiaddr_from_str(input: &str) -> Result<Vec<Addr>> {
    // Drop trailing slashes then split address into segment parts
    let input = input.trim_right_matches('/');
    let mut parts = input.split('/');

    // Expect address to start with just a slash ('/')
    let first = parts.next().ok_or(Error::InvalidMultiaddr)?;
    if !first.is_empty() {
        return Err(Error::InvalidMultiaddr);
    }

    let mut multiaddr = Vec::with_capacity(input.split('/').count());
    while let Some(n) = parts.next() {
        // Determine segment protocol number and possible extra data
        let p = Protocol::from_str(n)?;
        let s = match p.size() {
            0 => &"",
            _ => parts.next().ok_or(Error::MissingAddress)?
        };

        // Parse and store segment data
        multiaddr.push(Addr::from_protocol_str(p, s)?);
    }

    Ok(multiaddr)
}


pub fn multiaddr_to_str(addr: &Vec<Addr>) -> String {
    let mut result = String::new();

    for addr_segment in addr {
        result.push('/');
        result.push_str(addr_segment.protocol().as_str());

        if addr_segment.protocol().size() != 0 {
            write!(result, "/{}", addr_segment).unwrap();
        }
    }

    result
}
