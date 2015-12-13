use std::fmt;
use std::error;
use std::str::from_utf8;

use byteorder::{LittleEndian, WriteBytesExt};
use nom::IResult;

use ::protocol_types::*;

/// Parse a single /
named!(sep <&[u8], &[u8]>, tag!("/"));

/// Parse a single multiaddress in the form of `/ip4/127.0.0.1`.
named!(address <&[u8], Vec<u8> >,
    chain!(
           opt!(sep)             ~
        t: map_res!(
             take_until!("/"),
             from_utf8
           )                     ~
           sep                   ~
        a: is_not!("/"),
        || {
            let mut res: Vec<u8>= Vec::new();

            // Write the u16 code into the results vector
            if let Some(protocol) = ProtocolTypes::from_name(t) {
                res.write_u16::<LittleEndian>(protocol.to_code()).unwrap();
            }

            // Write the address into the results vector
            res.extend(a.iter().cloned());

            res
        }
    )
);

/// Parse a list of addresses
named!(addresses < &[u8], Vec< Vec<u8> > >, many1!(address));

#[derive(Debug)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The given multiaddress is invalid")
    }
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        "Invalid multiaddress"
    }
}

pub fn multiaddr_from_str(input: &str) -> Result<Vec<u8>, ParseError> {
    match addresses(input.as_bytes()) {
        IResult::Done(_, res) => {
            let res = res.iter()
                .fold(Vec::new(), |mut v, a| {
                    v.extend(a.iter().cloned());
                    v
                });

            Result::Ok(res)
        },
        _ => Result::Err(ParseError),
    }
}
