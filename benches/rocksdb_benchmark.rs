//! 🗄️ RocksDB + rkyv zero-copy benchmarks built on the **production structs and
//! serialization paths** (`CacheRocksDb`).
//!
//! Measures the exact on-disk cache machinery used by the firewall's FireHOL
//! import pipeline and its lazy audit-log reads:
//! - `FireholMetadata` / `RuleBlockContext` rkyv zero-copy access & (de)serialization
//! - RocksDB bulk writes (amortized, via `WriteBatch`), including the production
//!   temporary-import path (WAL disabled)
//! - RocksDB reads (`get_pinned` zero-copy) + rkyv zero-copy access vs full deserialize
//! - Full production `put_*` / `get_*` round trips
//!
//! Everything here reuses the real structs, column families, key encodings and
//! rkyv native zero-copy format — no hand-rolled wire format.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use firewall_lib::cache_rocksdb::{cf, metadata_key, ctx_key_v4_exact, CacheRocksDb};
use firewall_lib::firehol::metadata::{FireholCategory, FireholMetadata, RuleBlockContext};
use rkyv::util::AlignedVec;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

/// Number of metadata records pre-populated for the read benchmarks.
const N_META: u32 = 10_000;
/// Number of rule contexts pre-populated for the read benchmarks.
const N_CTX: usize = 10_000;
/// Ops written/read per iteration for the throughput benchmarks.
const BATCH: u32 = 1_000;
/// Channels (distinct file/line pairs) packed into a single rule context.
const CTX_FILES: usize = 4;

// ---------------------------------------------------------------------------
// Production-like fixtures
// ---------------------------------------------------------------------------

fn sample_metadata(id: u32) -> FireholMetadata {
    FireholMetadata {
        id,
        category: FireholCategory::Malware,
        source_url: Some(Arc::from("https://example.com/feed")),
        maintainer: Some(Arc::from("SANS")),
        maintainer_url: Some(Arc::from("https://isc.sans.edu")),
        source_file_date: Some(Arc::from("2026-09-14T00:00:00+00:00")),
        file_name: Arc::from("dshield.netset"),
        version: Some(Arc::from("1.2")),
        update_frequency: Some(Arc::from("1 day")),
    }
}

fn sample_rule_context(i: usize) -> RuleBlockContext {
    RuleBlockContext {
        files: (0..CTX_FILES)
            .map(|k| Arc::from(format!("blocklist-{k}-{i}.netset")))
            .collect(),
        lines: (0..CTX_FILES as u32).collect(),
        categories: vec![
            FireholCategory::Abuse,
            FireholCategory::Botnet,
            FireholCategory::Malware,
        ],
    }
}

fn open_cache() -> (CacheRocksDb, TempDir) {
    let dir = tempdir().unwrap();
    let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
    (db, dir)
}

// ---------------------------------------------------------------------------
// rkyv (de)serialization & zero-copy access — production structs
// ---------------------------------------------------------------------------

fn bench_rkyv(c: &mut Criterion) {
    let (db, _dir) = open_cache();
    let meta = sample_metadata(u32::MAX);
    let ctx = sample_rule_context(0);

    c.bench_function("rkyv_metadata_serialize", |b| {
        b.iter_batched(
            || AlignedVec::with_capacity(256),
            |mut out| {
                db.serialize_metadata_into(&meta, &mut out).unwrap();
                black_box(&out);
            },
            BatchSize::SmallInput,
        );
    });

    let meta_bytes = {
        let mut out = AlignedVec::with_capacity(256);
        db.serialize_metadata_into(&meta, &mut out).unwrap();
        out
    };

    c.bench_function("rkyv_metadata_access_zero_copy", |b| {
        b.iter(|| {
            let archived = CacheRocksDb::access_metadata(&meta_bytes).unwrap();
            black_box(archived.id);
        });
    });

    c.bench_function("rkyv_metadata_deserialize", |b| {
        b.iter(|| {
            let m = db.deserialize_metadata(&meta_bytes).unwrap();
            black_box(m.id);
        });
    });

    c.bench_function("rkyv_rule_context_serialize", |b| {
        b.iter_batched(
            || AlignedVec::with_capacity(256),
            |mut out| {
                db.serialize_rule_context_into(&ctx, &mut out).unwrap();
                black_box(&out);
            },
            BatchSize::SmallInput,
        );
    });

    let ctx_bytes = {
        let mut out = AlignedVec::with_capacity(256);
        db.serialize_rule_context_into(&ctx, &mut out).unwrap();
        out
    };

    c.bench_function("rkyv_rule_context_access_zero_copy", |b| {
        b.iter(|| {
            let archived = CacheRocksDb::access_rule_context(&ctx_bytes).unwrap();
            black_box(archived.files.len());
        });
    });

    c.bench_function("rkyv_rule_context_deserialize", |b| {
        b.iter(|| {
            let c = db.deserialize_rule_context(&ctx_bytes).unwrap();
            black_box(c.files.len());
        });
    });
}

// ---------------------------------------------------------------------------
// RocksDB bulk writes (WriteBatch), incl. production import (WAL disabled)
// ---------------------------------------------------------------------------

/// Populate `cf::METADATA` with `N` records using a single batched write.
fn populate_metadata(db: &CacheRocksDb, n: u32) {
    let mut batch = db.batch();
    let mut buf = AlignedVec::with_capacity(256);
    for id in 0..n {
        db.serialize_metadata_into(&sample_metadata(id), &mut buf)
            .unwrap();
        db.batch_put(&mut batch, cf::METADATA, &metadata_key(id), &buf)
            .unwrap();
    }
    db.apply_batch(batch).unwrap();
}

/// Populate `cf::RULE_CONTEXT` with `n` entries keyed by a representative IPv4
/// exact target (production `ctx_key_v4_exact`).
fn populate_rule_contexts(db: &CacheRocksDb, n: usize) {
    let mut batch = db.batch();
    let mut buf = AlignedVec::with_capacity(256);
    for i in 0..n {
        let octets = (i as u32).to_be_bytes();
        db.serialize_rule_context_into(&sample_rule_context(i), &mut buf)
            .unwrap();
        db.batch_put(&mut batch, cf::RULE_CONTEXT, &ctx_key_v4_exact(&octets), &buf)
            .unwrap();
    }
    db.apply_batch(batch).unwrap();
}

fn bench_rocksdb_write(c: &mut Criterion) {
    let (db, _dir) = open_cache();
    // Reuse a single fixed payload so the bench isolates RocksDB write cost
    // (cap'n proto encode cost is measured separately above).
    let meta_blob = {
        let mut out = AlignedVec::with_capacity(256);
        db.serialize_metadata_into(&sample_metadata(u32::MAX), &mut out)
            .unwrap();
        out
    };

    let mut wgroup = c.benchmark_group("rocksdb");
    wgroup.throughput(Throughput::Elements(BATCH as u64));

    wgroup.bench_function("metadata_bulk_write", |b| {
        b.iter_batched(
            || (0..BATCH).collect::<Vec<_>>(),
            |ids| {
                let mut batch = db.batch();
                for id in ids {
                    db.batch_put(
                        &mut batch,
                        cf::METADATA,
                        &metadata_key(id),
                        &meta_blob,
                    )
                    .unwrap();
                }
                db.apply_batch(batch).unwrap();
            },
            BatchSize::PerIteration,
        );
    });

    // Production import uses an isolated, temporary generation with WAL disabled.
    let (base, _base_dir) = open_cache();
    let gen = base.import_generation().unwrap();
    wgroup.bench_function("import_generation_bulk_write", |b| {
        b.iter_batched(
            || (0..BATCH).collect::<Vec<_>>(),
            |ids| {
                let mut batch = gen.batch();
                for id in ids {
                    gen.batch_put(
                        &mut batch,
                        cf::METADATA,
                        &metadata_key(id),
                        &meta_blob,
                    )
                    .unwrap();
                }
                gen.apply_batch(batch).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

// ---------------------------------------------------------------------------
// RocksDB reads (zero-copy pinned) + Cap'n Proto decode — production lazy path
// ---------------------------------------------------------------------------

fn bench_rocksdb_read(c: &mut Criterion) {
    let (db, _dir) = open_cache();
    populate_metadata(&db, N_META);
    populate_rule_contexts(&db, N_CTX);

    let meta_id = N_META / 2;
    c.bench_function("rocksdb_metadata_get_zero_copy", |b| {
        b.iter(|| {
            db.with_metadata(meta_id, |m| {
                black_box(m.file_name_str().len());
            })
            .unwrap()
            .unwrap();
        });
    });

    c.bench_function("rocksdb_metadata_get_production", |b| {
        b.iter(|| {
            let m = db.get_metadata(meta_id).unwrap().unwrap();
            black_box(m.file_name);
        });
    });

    let ctx_ip = ((N_CTX / 2) as u32).to_be_bytes();
    let ctx_key = ctx_key_v4_exact(&ctx_ip);
    c.bench_function("rocksdb_rule_context_get_zero_copy", |b| {
        b.iter(|| {
            db.with_rule_context(&ctx_key, |c| {
                black_box(c.files.len());
            })
            .unwrap()
            .unwrap();
        });
    });

    c.bench_function("rocksdb_rule_context_get_production", |b| {
        b.iter(|| {
            let c = db
                .get_rule_context(&ctx_key)
                .unwrap()
                .unwrap();
            black_box(c.files.len());
        });
    });

    let mut rgroup = c.benchmark_group("rocksdb");
    rgroup.throughput(Throughput::Elements(1000));

    rgroup.bench_function("metadata_read_1000", |b| {
        let keys: Vec<u32> = (0..1000u32).map(|i| (i * 7) % N_META).collect();
        b.iter(|| {
            let mut sum = 0u32;
            for &k in &keys {
                if let Some(m) = db.get_metadata(k).unwrap() {
                    sum = sum.wrapping_add(m.id);
                }
            }
            black_box(sum);
        });
    });

    rgroup.bench_function("rule_context_read_1000", |b| {
        let keys: Vec<[u8; 4]> = (0..1000u32)
            .map(|i| ((i * 7) % N_CTX as u32).to_be_bytes())
            .collect();
        b.iter(|| {
            let mut sum = 0usize;
            for k in &keys {
                if let Some(ctx) = db.get_rule_context(&ctx_key_v4_exact(k)).unwrap() {
                    sum += ctx.lines.len();
                }
            }
            black_box(sum);
        });
    });
}

// ---------------------------------------------------------------------------
// Full production round trips (serialize -> RocksDB write -> read -> decode)
// ---------------------------------------------------------------------------

fn bench_rocksdb_roundtrip(c: &mut Criterion) {
    let (db, _dir) = open_cache();

    let meta = sample_metadata(7);
    c.bench_function("rocksdb_metadata_put_get_roundtrip", |b| {
        b.iter(|| {
            db.put_metadata(&meta).unwrap();
            let m = db.get_metadata(7).unwrap().unwrap();
            black_box(m.category);
        });
    });

    let ctx = sample_rule_context(1);
    let octets = [203, 0, 113, 9];
    c.bench_function("rocksdb_rule_context_put_get_roundtrip", |b| {
        b.iter(|| {
            db.put_rule_context(&ctx_key_v4_exact(&octets), &ctx)
                .unwrap();
            let c = db.get_rule_context(&ctx_key_v4_exact(&octets)).unwrap().unwrap();
            black_box(c.files.len());
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion entry point
// ---------------------------------------------------------------------------

criterion_group!(
    name = rocksdb_benches;
    config = Criterion::default();
    targets =
        bench_rkyv,
        bench_rocksdb_write,
        bench_rocksdb_read,
        bench_rocksdb_roundtrip,
);

criterion_main!(rocksdb_benches);
