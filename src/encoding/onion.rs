use crate::Error;
use byteorder::{BigEndian, ReadBytesExt};
use data_encoding::BASE32;
use std::{
    fmt,
    io::{Cursor, Read, Write},
    str::FromStr,
};

struct OnionEncoding;

impl OnionEncoding {
    pub fn decode_v1(bytes: &[u8]) -> Result<(String, u16), Error> {
        let mut c = Cursor::new(&bytes);
        let mut addr_buf = [0; 10];
        c.read_exact(&mut addr_buf)?;
        let decoded = BASE32.encode(&addr_buf);
        let port = c.read_u16::<BigEndian>()?;
        Ok((decoded, port))
    }

    fn decode_v3(bytes: &[u8]) -> Result<(String, u16), Error> {
        let mut c = Cursor::new(&bytes);
        let mut addr_buf = [0; 35];
        c.read_exact(&mut addr_buf)?;
        let decoded = BASE32.encode(&addr_buf);
        let port = c.read_u16::<BigEndian>()?;
        Ok((decoded, port))
    }

    fn from_v1_str(s: &str) -> Result<OnionAddress, Error> {
        let bytes = Self::from_str(s, 16)?;
        Ok(OnionAddress { bytes })
    }

    fn from_v3_str(s: &str) -> Result<Onion3Address, Error> {
        let bytes = Self::from_str(s, 56)?;
        Ok(Onion3Address { bytes })
    }

    fn from_str(s: &str, expected_addr_len: usize) -> Result<Vec<u8>, Error> {
        let parts = s.split(':').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(Error::ParsingError(
                format!("{} does not contain a port number.", s).into(),
            ));
        }

        if parts[0].len() != expected_addr_len {
            return Err(Error::ParsingError(format!("{} is not a Tor onion address.", s).into()));
        }

        let onion_host_bytes = BASE32.decode(&parts[0].to_ascii_uppercase().as_bytes())?;

        let port: u16 = parts[1].parse()?;
        if port < 1 {
            return Err(Error::ParsingError("port is less than 1".into()));
        }
        let port_bytes = port.to_be_bytes();

        let mut bytes = Vec::with_capacity(onion_host_bytes.len() + 2);
        bytes.write_all(&onion_host_bytes)?;
        bytes.write_all(&port_bytes)?;

        Ok(bytes)
    }
}

pub struct OnionAddress {
    bytes: Vec<u8>,
}

impl OnionAddress {
    pub fn from_unchecked_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    pub fn decode(&self) -> Result<(String, u16), Error> {
        OnionEncoding::decode_v1(&self.bytes)
    }
}

impl FromStr for OnionAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OnionEncoding::from_v1_str(s)
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let (addr, port) = OnionEncoding::decode_v1(&self.bytes).map_err(|_| fmt::Error)?;
        write!(f, "{}:{}", addr.to_ascii_lowercase(), port)
    }
}

pub struct Onion3Address {
    bytes: Vec<u8>,
}

impl Onion3Address {
    pub fn from_unchecked_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    pub fn decode(&self) -> Result<(String, u16), Error> {
        OnionEncoding::decode_v3(&self.bytes)
    }
}

impl FromStr for Onion3Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OnionEncoding::from_v3_str(s)
    }
}

impl fmt::Display for Onion3Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let (addr, port) = OnionEncoding::decode_v3(&self.bytes).map_err(|_| fmt::Error)?;
        write!(f, "{}:{}", addr.to_ascii_lowercase(), port)
    }
}
