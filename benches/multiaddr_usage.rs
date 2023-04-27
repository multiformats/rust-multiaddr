use std::net::{Ipv4Addr, Ipv6Addr};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use multiaddr::multiaddr;
use rand::{distributions::Standard, Rng};

fn make_ipv4_tcp_multiaddrs(addr: &[Ipv4Addr]) {
    let mut result = Vec::with_capacity(addr.len() * 2);
    for addr in addr {
        result.push(multiaddr!(Ip4(*addr), Tcp(22u16)))
    }
    for i in 0..result.len() {
        result.push(result[i].clone())
    }
    black_box(result);
}

fn make_ipv6_tcp_multiaddrs(addr: &[Ipv6Addr]) {
    let mut result = Vec::with_capacity(addr.len() * 2);
    for addr in addr {
        result.push(multiaddr!(Ip6(*addr), Tcp(22u16)))
    }
    for i in 0..result.len() {
        result.push(result[i].clone())
    }
    black_box(result);
}

fn criterion_benchmark(c: &mut Criterion) {
    let random_ipv4: Vec<Ipv4Addr> = rand::thread_rng()
        .sample_iter(Standard)
        .take(4096)
        .map(|x: [u8; 4]| x.into())
        .collect();
    c.bench_function("4096 ipv4 tcp multiaddrs", |b| {
        b.iter(|| make_ipv4_tcp_multiaddrs(black_box(&random_ipv4)))
    });


    let random_ipv6: Vec<Ipv6Addr> = rand::thread_rng()
        .sample_iter(Standard)
        .take(4096)
        .map(|x: [u8; 16]| x.into())
        .collect();
    c.bench_function("4096 ipv6 tcp multiaddrs", |b| {
        b.iter(|| make_ipv6_tcp_multiaddrs(black_box(&random_ipv6)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
