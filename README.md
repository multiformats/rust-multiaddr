# rust-multiaddr

[![](https://img.shields.io/badge/made%20by-Protocol%20Labs-blue.svg?style=flat-square)](http://ipn.io)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](http://github.com/multiformats/multiformats)
[![](https://img.shields.io/badge/freenode-%23ipfs-blue.svg?style=flat-square)](http://webchat.freenode.net/?channels=%23ipfs)
[![Build Status](https://img.shields.io/travis/multiformats/rust-multiaddr/master.svg?style=flat-square)](https://travis-ci.org/multiformats/rust-multiaddr)
[![Coverage Status](https://coveralls.io/repos/multiformats/rust-multiaddr/badge.svg?style=flat-square&branch=master)](https://coveralls.io/r/multiformats/rust-multiaddr?branch=master)
[![](https://img.shields.io/badge/rust-docs-blue.svg?style=flat-square)](http://multiformats.github.io/rust-multiaddr/multiaddr/struct.Multiaddr.html)
[![crates.io](http://meritbadge.herokuapp.com/multiaddr?style=flat-square)](https://crates.io/crates/multiaddr)

> [multiaddr](https://github.com/multiformats/multiaddr) implementation in Rust.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

```
> TODO
```

## Usage

First add this to your `Cargo.toml`

```toml
[dependencies]
multiaddr = "*"
```

```rust
extern crate multiaddr;

use multiaddr::{Multiaddr, ToMultiaddr};

let address = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();
// or directly from a string
let other = "/ip4/127.0.0.1".to_multiaddr().unwrap();

assert_eq!(address.to_string(), "/ip4/127.0.0.1/udp/1234");
assert_eq!(other.to_string(), "/ip4/127.0.0.1");
```

## Maintainers

Captain: [@dignifiedquire](https://github.com/dignifiedquire).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/multiformats/rust-multiaddr/issues).

Check out our [contributing document](https://github.com/multiformats/multiformats/blob/master/contributing.md) for more information on how we work, and about contributing in general. Please be aware that all interactions related to multiformats are subject to the IPFS [Code of Conduct](https://github.com/ipfs/community/blob/master/code-of-conduct.md).

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE)
