use std::str::FromStr;

use integer_encoding::{VarInt, VarIntWriter};

use protocol::Protocol;
use {Result, Error};

pub fn multiaddr_from_str(input: &str) -> Result<Vec<u8>> {
    // drdop trailing slashes
    let input = input.trim_right_matches('/');

    let mut bytes = vec![];
    let mut parts = input.split('/');
    let next = parts.next().ok_or(Error::InvalidMultiaddr)?;

    if !next.is_empty() {
        return Err(Error::InvalidMultiaddr);
    }

    while let Some(n) = parts.next() {
        let p = Protocol::from_str(n)?;

        bytes.write_varint(p as u64)?;

        if p.size() == 0 {
            continue;
        }

        let next = match parts.next() {
            Some(path) => path,
            None => return Err(Error::MissingAddress),
        };

        bytes.extend(p.string_to_bytes(next)?);
    }

    Ok(bytes)
}

fn read_varint_code(input: &[u8]) -> Result<(u64, usize)> {
    let res = u64::decode_var(input);

    if res.0 == 0 {
        return Err(Error::ParsingError)
    }

    Ok(res)
}

fn size_for_addr(protocol: Protocol, input: &[u8]) -> Result<(usize, usize)> {
    if protocol.size() > 0 {
        Ok((protocol.size() as usize / 8, 0))
    } else if protocol.size() == 0 {
        Ok((0, 0))
    } else {
        let (size, n) = read_varint_code(input)?;
        Ok((size as usize, n))
    }
}

pub fn protocol_from_bytes(input: &[u8]) -> Result<Vec<Protocol>> {
    let mut ps = vec![];
    let mut i = 0;

    while i < input.len() {
        let (code, n) = read_varint_code(&input[i..])?;
        let p = Protocol::from(code)?;
        ps.push(p);

        i += n;
        let (size, adv) = size_for_addr(p, &input[i..])?;
        i += size + adv;
    }

    Ok(ps)
}


pub fn address_from_bytes(input: &[u8]) -> Result<String> {
    let mut protos = vec!["".to_string()];
    let mut i = 0;

    while i < input.len() {

        let (code, n) = read_varint_code(&input[i..])?;
        i += n;

        let p = Protocol::from(code)?;
        protos.push(p.to_string());

        let (size, adv) = size_for_addr(p, &input[i..])?;
        i += adv;

        if let Some(s) = p.bytes_to_string(&input[i..i + size])? {
            protos.push(s);
        }

        i += size;
    }

    Ok(protos.join("/"))
}
