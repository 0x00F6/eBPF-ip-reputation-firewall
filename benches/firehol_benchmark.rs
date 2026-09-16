//! Criterion benchmarks for FireHOL line parsing and parallel directory ingestion.

use criterion::{criterion_group, criterion_main, Criterion};
use firewall_lib::firehol::{metadata::normalize_firehol_date, parser::FireholParser};
use std::{fs::File, hint::black_box, io::Write};
use tempfile::tempdir;

fn bench_parse_single_ip(c: &mut Criterion) {
    c.bench_function("firehol_parse_single_ip_exact_v4", |b| {
        b.iter(|| FireholParser::parse_ip_or_cidr(black_box("198.51.100.42")))
    });

    c.bench_function("firehol_parse_single_ip_cidr_v4", |b| {
        b.iter(|| FireholParser::parse_ip_or_cidr(black_box("198.51.100.0/24")))
    });

    c.bench_function("firehol_parse_slash_32_exact_optimization", |b| {
        b.iter(|| FireholParser::parse_ip_or_cidr(black_box("198.51.100.42/32")))
    });

    c.bench_function("firehol_date_normalization", |b| {
        b.iter(|| normalize_firehol_date(black_box("Mon Sep 14 02:22:20 UTC 2026")))
    });
}

fn bench_parallel_parse_directory(c: &mut Criterion) {
    let dir = tempdir().unwrap();

    // Create 5 realistic blocklist files with 1,000 entries each
    for file_idx in 0..5 {
        let path = dir.path().join(format!("blocklist_{}.netset", file_idx));
        let mut f = File::create(&path).unwrap();
        writeln!(f, "# Maintainer: Benchmark Suite").unwrap();
        writeln!(f, "# Category: attacks").unwrap();
        writeln!(f, "# Source File Date: Mon Sep 14 02:22:20 UTC 2026").unwrap();

        for i in 0..1000 {
            if i % 3 == 0 {
                writeln!(
                    f,
                    "10.{}.{}.{}",
                    (i / 65536) % 256,
                    (i / 256) % 256,
                    i % 256
                )
                .unwrap();
            } else if i % 3 == 1 {
                writeln!(f, "172.16.{}.0/24", (i % 250)).unwrap();
            } else {
                writeln!(f, "192.168.{}.{}/32", (i / 256) % 256, i % 256).unwrap();
            }
        }
    }

    c.bench_function("firehol_parallel_parse_5000_entries", |b| {
        b.iter(|| {
            let res = FireholParser::parse_directory(black_box(dir.path()), None).unwrap();
            black_box(res);
        })
    });
}

criterion_group!(
    benches,
    bench_parse_single_ip,
    bench_parallel_parse_directory
);
criterion_main!(benches);
