use std::{net, fmt, error, io, num};
use cid;

pub type Result<T> = ::std::result::Result<T, Error>;

/// Error types
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Error {
    UnkownProtocol,
    UnkownProtocolString,
    InvalidMultiaddr,
    MissingAddress,
    ParsingError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            UnkownProtocol => "Unkown protocol",
            UnkownProtocolString => "Unkown protocol string",
            InvalidMultiaddr => "Invalid multiaddr",
            MissingAddress => "protocol requires address, none given",
            ParsingError => "failed to parse",
        }
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error {
        Error::ParsingError
    }
}

impl From<cid::Error> for Error {
    fn from(_: cid::Error) -> Error {
        Error::ParsingError
    }
}

impl From<net::AddrParseError> for Error {
    fn from(_: net::AddrParseError) -> Error {
        Error::ParsingError
    }
}


impl From<num::ParseIntError> for Error {
    fn from(_: num::ParseIntError) -> Error {
        Error::ParsingError
    }
}
