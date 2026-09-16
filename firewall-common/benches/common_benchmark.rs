use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use firewall_common::{
    FirewallStats, LpmKeyV4, LpmKeyV6, PacketLogEvent, RuleValue, ACTION_DROP, MATCH_EXACT_HASH,
    PROTO_TCP,
};
use std::hint::black_box;

fn bench_rule_value(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_common_rule_value");

    group.bench_function("rule_value_drop_constructor", |b| {
        b.iter(|| {
            let rule = RuleValue::drop(black_box(1042));
            black_box(rule);
        })
    });

    group.bench_function("rule_value_accept_constructor", |b| {
        b.iter(|| {
            let rule = RuleValue::accept(black_box(2048));
            black_box(rule);
        })
    });

    group.finish();
}

fn bench_lpm_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_common_lpm_keys");

    group.bench_function("lpm_key_v4_new", |b| {
        b.iter(|| {
            let key = LpmKeyV4::new(black_box(24), black_box([192, 168, 1, 0]));
            black_box(key);
        })
    });

    group.bench_function("lpm_key_v4_from_u32", |b| {
        b.iter(|| {
            let key = LpmKeyV4::from_u32(black_box(24), black_box(0xC0A80100));
            black_box(key);
        })
    });

    group.bench_function("lpm_key_v6_new", |b| {
        let ip_bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        b.iter(|| {
            let key = LpmKeyV6::new(black_box(64), black_box(ip_bytes));
            black_box(key);
        })
    });

    group.finish();
}

fn bench_packet_log_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_common_packet_log_event");

    group.bench_function("packet_log_event_constructor", |b| {
        b.iter(|| {
            let event = PacketLogEvent {
                timestamp_ns: black_box(1_700_000_000_000_000_000),
                src_ip: black_box([192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                dst_ip: black_box([10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                rule_id: black_box(15),
                packet_len: black_box(64),
                ifindex: black_box(2),
                src_port: black_box(12345),
                dst_port: black_box(80),
                protocol: black_box(PROTO_TCP),
                ip_version: black_box(4),
                action: black_box(ACTION_DROP),
                match_type: black_box(MATCH_EXACT_HASH),
                _pad: [0; 4],
            };
            black_box(event);
        })
    });

    group.bench_function("packet_log_event_zero_copy_transmute", |b| {
        let raw_bytes = [0x42u8; 64];
        b.iter_batched(
            || raw_bytes,
            |bytes| {
                let event: PacketLogEvent = unsafe { core::mem::transmute(bytes) };
                black_box(event);
            },
            BatchSize::SmallInput,
        );
    });

    let sample_event = PacketLogEvent {
        timestamp_ns: 1_700_000_000_000_000_000,
        src_ip: [192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rule_id: 15,
        packet_len: 64,
        ifindex: 2,
        src_port: 12345,
        dst_port: 80,
        protocol: PROTO_TCP,
        ip_version: 4,
        action: ACTION_DROP,
        match_type: MATCH_EXACT_HASH,
        _pad: [0; 4],
    };

    group.bench_function("packet_log_event_src_addr_v4", |b| {
        b.iter(|| {
            let addr = black_box(&sample_event).src_addr();
            black_box(addr);
        })
    });

    group.bench_function("packet_log_event_display_format", |b| {
        b.iter(|| {
            let s = format!("{}", black_box(&sample_event));
            black_box(s);
        })
    });

    group.finish();
}

fn bench_firewall_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_common_stats");

    group.bench_function("firewall_stats_wrapping_update", |b| {
        let mut stats = FirewallStats::default();
        b.iter(|| {
            stats.rx_packets = stats.rx_packets.wrapping_add(black_box(1));
            stats.rx_bytes = stats.rx_bytes.wrapping_add(black_box(64));
            stats.dropped_packets = stats.dropped_packets.wrapping_add(black_box(1));
            stats.dropped_bytes = stats.dropped_bytes.wrapping_add(black_box(64));
            black_box(&stats);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_rule_value,
    bench_lpm_keys,
    bench_packet_log_event,
    bench_firewall_stats
);
criterion_main!(benches);
