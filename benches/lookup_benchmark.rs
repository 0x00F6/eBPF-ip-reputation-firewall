//! ⚡ Performance Micro-Benchmarks for eBPF Firewall
//!
//! 🔬 Tests:
//! - 🗺️ O(1) HashMap exact IPv4 lookup throughput
//! - 🌐 CIDR network subnet parsing (LPM Trie prep)
//! - 🔍 IPv4 string address parsing
//! - 🚀 Zero-copy RingBuffer memory transmutation

use criterion::{criterion_group, criterion_main, Criterion};
use firewall_common::{PacketLogEvent, RuleValue, ACTION_DROP};
use ipnet::IpNet;
use std::{collections::HashMap, hint::black_box, net::Ipv4Addr, str::FromStr};

/// 🗺️ Benchmark O(1) BPF HashMap exact IPv4 lookup performance
fn bench_hashmap_lookup(c: &mut Criterion) {
    let mut map: HashMap<[u8; 4], RuleValue> = HashMap::new();
    for i in 0..10_000u32 {
        let octets = i.to_be_bytes();
        map.insert(octets, RuleValue::drop(i));
    }

    let target = 5432u32.to_be_bytes();

    c.bench_function("hashmap_exact_ipv4_lookup", |b| {
        b.iter(|| {
            let res = map.get(black_box(&target));
            black_box(res);
        });
    });
}

/// 🌐 Benchmark CIDR network subnet string parsing
fn bench_cidr_parsing(c: &mut Criterion) {
    let cidrs = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "203.0.113.195/32",
        "2001:db8::/32",
    ];

    c.bench_function("parse_cidr_network", |b| {
        b.iter(|| {
            for cidr in &cidrs {
                let net = IpNet::from_str(black_box(cidr)).unwrap();
                black_box(net);
            }
        });
    });
}

/// 🔍 Benchmark IPv4 address parsing speed
fn bench_ipv4_parsing(c: &mut Criterion) {
    let ips = ["192.168.1.1", "10.20.30.40", "172.16.5.4", "8.8.8.8"];

    c.bench_function("parse_ipv4_address", |b| {
        b.iter(|| {
            for ip in &ips {
                let addr = Ipv4Addr::from_str(black_box(ip)).unwrap();
                black_box(addr);
            }
        });
    });
}

/// 🚀 Benchmark zero-copy PacketLogEvent transmutation from raw Ring Buffer memory
fn bench_event_zero_copy(c: &mut Criterion) {
    let event = PacketLogEvent {
        timestamp_ns: 123456789,
        src_ip: [192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rule_id: 42,
        packet_len: 64,
        ifindex: 2,
        src_port: 54321,
        dst_port: 80,
        protocol: 6,
        ip_version: 4,
        action: ACTION_DROP,
        match_type: 1,
        _pad: [0; 4],
    };

    let raw_bytes: [u8; 64] = unsafe { std::mem::transmute(event) };

    c.bench_function("zero_copy_event_transmute", |b| {
        b.iter(|| {
            let parsed_event: &PacketLogEvent =
                unsafe { &*(black_box(raw_bytes.as_ptr()) as *const PacketLogEvent) };
            black_box(parsed_event.rule_id);
        });
    });
}

criterion_group!(
    benches,
    bench_hashmap_lookup,
    bench_cidr_parsing,
    bench_ipv4_parsing,
    bench_event_zero_copy
);
criterion_main!(benches);
