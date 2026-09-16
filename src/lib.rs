//! Firewall Library
//!
//! Provides the core userspace components for the eBPF IP reputation firewall:
//! - eBPF map management (`MapManager`)
//! - Rule parsing and CIDR classification (`RuleLoader`, `ParsedRuleSet`)
//! - Asynchronous Ring Buffer event consumption (`RingBufConsumer`)
//! - Live performance metrics reporting (`StatsReporter`)
//! - XDP program loading and driver attachment (`XdpFirewall`)
//! - Prometheus metrics exposition and HTTP server (`PrometheusMetrics`, `MetricsServer`)
//! - Top-N blocked IP telemetry and cardinality management (`BlockedIpTopN`, `BlockedIpStats`)
//! - Terminal styling with bold relevant text and colors (`console`)
//! - FireHOL blocklist synchronization, parsing, and eBPF integration (`firehol`)

pub mod cache_rocksdb;
pub mod config;
pub mod console;
pub mod error;
pub mod firehol;
pub mod loader;
pub mod maps;
pub mod metrics;
pub mod ringbuf;
pub mod stats;
pub mod top_n;
pub mod xdp;
