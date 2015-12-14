# rust-multiaddr

[![Build Status](https://img.shields.io/travis/Dignifiedquire/rust-multiaddr/master.svg?style=flat-square)](https://travis-ci.org/Dignifiedquire/rust-multiaddr)

[multiaddr](https://github.com/jbenet/multiaddr) implementation in Rust.


## Example

### Simple

First add this to your `Cargo.toml`

```toml
[dependencies]
multiaddr = "*"
```

```rust
crate extern multiaddr

use multiaddr::Multiaddr;

let address = Multiaddr::new("/ip4/127.0.0.1/udp/1234").unwrap();

assert_eq!(address.to_bytes(), [
  4, 0, 127, 0, 0, 1,
17, 0, 12, 34
]);
```


## License

MIT
