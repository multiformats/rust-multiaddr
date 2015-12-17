// For explanation of lint checks, run `rustc -W help`
// This is adapted from
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, //missing_docs,
non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
missing_debug_implementations)]

///! # multiaddr
///!
///! Implementation of [multiaddr](https://github.com/jbenet/multiaddr)
///! in Rust.
#[macro_use]
extern crate nom;

extern crate byteorder;

pub use self::protocols::*;
pub mod protocols;

use self::parser::*;
mod parser;

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::io;

/// Representation of a Multiaddr.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Multiaddr {
    bytes: Vec<u8>
}

impl ToString for Multiaddr {
    /// Convert a Multiaddr to a string
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt").unwrap();
    /// assert_eq!(address.to_string(), "/ip4/127.0.0.1/udt");
    /// ```
    ///
    fn to_string(&self) -> String {
        address_from_bytes(&self.bytes[..])
    }
}

impl Multiaddr {
    /// Create a new multiaddr based on a string representation, like
    /// `/ip4/127.0.0.1/udp/1234`.
    ///
    /// # Examples
    ///
    /// Simple construction
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();
    /// assert_eq!(address.to_bytes(), [
    ///     0, 4, 127, 0, 0, 1,
    ///     0, 17, 4, 210
    /// ]);
    /// ```
    ///
    pub fn new(input: &str) -> io::Result<Multiaddr> {
        let bytes = try!(multiaddr_from_str(input));

        Ok(Multiaddr {
            bytes: bytes,
        })
    }

    /// Return a copy to disallow changing the bytes directly
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_owned()
    }

    /// Return a list of protocols
    ///
    /// # Examples
    ///
    /// A single protocol
    ///
    /// ```
    /// use multiaddr::{Multiaddr, Protocols};
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// assert_eq!(address.protocols(), vec![Protocols::IP4]);
    /// ```
    ///
    pub fn protocols(&self) -> Vec<Protocols> {
        protocols_from_bytes(&self.bytes[..])
    }

    /// Wrap a given Multiaddr and return the combination.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1").unwrap();
    /// let nested = address.encapsulate("/udt").unwrap();
    /// assert_eq!(nested, Multiaddr::new("/ip4/127.0.0.1/udt").unwrap());
    /// ```
    ///
    pub fn encapsulate(&self, input: &str) -> io::Result<Multiaddr> {
        let mut bytes = self.bytes.clone();
        let new = try!(multiaddr_from_str(input));
        println!("bytes: {:?}, new: {:?}", bytes, new);
        bytes.extend(new);
        println!("res {:?}", bytes);
        Ok(Multiaddr {
            bytes: bytes
        })
    }

    /// Remove the outer most address from itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt/sctp/5678").unwrap();
    /// let unwrapped = address.decapsulate(Multiaddr::new("/udt").unwrap());
    /// assert_eq!(unwrapped, Multiaddr::new("/ip4/127.0.0.1").unwrap());
    /// ```
    ///
    /// Returns the original if the passed in address is not found
    ///
    /// ```
    /// use multiaddr::Multiaddr;
    ///
    /// let address = Multiaddr::new("/ip4/127.0.0.1/udt/sctp/5678").unwrap();
    /// let unwrapped = address.decapsulate(Multiaddr::new("/ip4/127.0.1.1").unwrap());
    /// assert_eq!(unwrapped, address);
    /// ```
    ///
    pub fn decapsulate(&self, input: Multiaddr) -> Multiaddr {
        let bytes = self.bytes.clone();
        let input = input.to_bytes();
        let bytes_len = bytes.len();
        let input_length = input.len();

        let mut input_pos = 0;
        let mut matches = false;

        for (i, _) in bytes.iter().enumerate() {
            let next = i + input_length;

            if next > bytes_len {
                continue;
            }

            if &bytes[i..next] == &input[..] {
                matches = true;
                input_pos = i;
                break;
            }
        }

        if !matches {
            return Multiaddr {bytes: bytes}
        }

        let mut bytes = bytes;
        bytes.truncate(input_pos);

        Multiaddr {
            bytes: bytes
        }
    }
}


/// A trait for objects which can be converted to a
/// Multiaddr.
///
/// This trait is implemented by default for
///
/// * `SocketAddr`, `SocketAddrV4` and `SocketAddrV6`, assuming that the
///   the given port is a tcp port.
///
/// * `Ipv4Addr`, `Ipv6Addr`
///
/// * `String` and `&str`, requiring the default string format for a Multiaddr.
///
pub trait ToMultiaddr {
    /// Converts this object to a Multiaddr
    ///
    /// # Errors
    ///
    /// Any errors encountered during parsing will be returned
    /// as an `Err`.
    fn to_multiaddr(&self) -> io::Result<Multiaddr>;
}

impl ToMultiaddr for SocketAddr {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        match *self {
            SocketAddr::V4(ref a) => (*a).to_multiaddr(),
            SocketAddr::V6(ref a) => (*a).to_multiaddr(),
        }
    }
}

impl ToMultiaddr for SocketAddrV4 {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        Multiaddr::new(&format!("/ip4/{}/tcp/{}", self.ip(), self.port()))
    }
}

impl ToMultiaddr for SocketAddrV6 {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        // TODO: Should how should we handle `flowinfo` and `scope_id`?
        Multiaddr::new(&format!("/ip6/{}/tcp/{}", self.ip(), self.port()))
    }
}

impl ToMultiaddr for Ipv4Addr {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        Multiaddr::new(&format!("/ip4/{}", &self))
    }
}

impl ToMultiaddr for Ipv6Addr {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        Multiaddr::new(&format!("/ip6/{}", &self))
    }
}

impl ToMultiaddr for String {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        Multiaddr::new(&self)
    }
}

impl<'a> ToMultiaddr for &'a str {
    fn to_multiaddr(&self) -> io::Result<Multiaddr> {
        Multiaddr::new(self)
    }
}
