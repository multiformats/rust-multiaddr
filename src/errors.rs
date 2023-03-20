use std::{error, fmt, io, net, num, str, string};
use unsigned_varint::decode;

#[deprecated(note = "Use `Result<T, multiaddr::Error>` instead.")]
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    pub fn is_unknown_protocol(&self) -> bool {
        matches!(self.kind, Kind::UnknownProtocolString(_))
    }

    pub(crate) fn data_less_than_len() -> Self {
        Self {
            kind: Kind::DataLessThanLen,
        }
    }

    pub(crate) fn invalid_multiaddr() -> Self {
        Self {
            kind: Kind::InvalidMultiaddr,
        }
    }

    pub(crate) fn invalid_protocol_string() -> Self {
        Self {
            kind: Kind::InvalidProtocolString,
        }
    }

    pub(crate) fn unknown_protocol_id(id: u32) -> Self {
        Self {
            kind: Kind::UnknownProtocolId(id),
        }
    }

    pub(crate) fn unknown_protocol_string(id: String) -> Self {
        Self {
            kind: Kind::UnknownProtocolString(id),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

/// Error types
#[derive(Debug)]
#[non_exhaustive]
enum Kind {
    DataLessThanLen,
    InvalidMultiaddr,
    InvalidProtocolString,
    InvalidUvar(decode::Error),
    ParsingError(Box<dyn error::Error + Send + Sync>),
    UnknownProtocolId(u32),
    UnknownProtocolString(String),
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::DataLessThanLen => f.write_str("we have less data than indicated by length"),
            Kind::InvalidMultiaddr => f.write_str("invalid multiaddr"),
            Kind::InvalidProtocolString => f.write_str("invalid protocol string"),
            Kind::InvalidUvar(e) => write!(f, "failed to decode unsigned varint: {e}"),
            Kind::ParsingError(e) => write!(f, "failed to parse: {e}"),
            Kind::UnknownProtocolId(id) => write!(f, "unknown protocol id: {id}"),
            Kind::UnknownProtocolString(string) => {
                write!(f, "unknown protocol string: {string}")
            }
        }
    }
}

impl error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            Kind::DataLessThanLen => None,
            Kind::InvalidMultiaddr => None,
            Kind::InvalidProtocolString => None,
            Kind::InvalidUvar(inner) => Some(inner),
            Kind::ParsingError(inner) => Some(inner.as_ref()),
            Kind::UnknownProtocolId(_) => None,
            Kind::UnknownProtocolString(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<multihash::Error> for Error {
    fn from(err: multihash::Error) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<multibase::Error> for Error {
    fn from(err: multibase::Error) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<net::AddrParseError> for Error {
    fn from(err: net::AddrParseError) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<num::ParseIntError> for Error {
    fn from(err: num::ParseIntError) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error {
            kind: Kind::ParsingError(err.into()),
        }
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Error {
        Error {
            kind: Kind::InvalidUvar(e),
        }
    }
}
