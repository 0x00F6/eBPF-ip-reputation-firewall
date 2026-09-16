// ==============================================================================
// 📊 Prometheus Metrics Collection & HTTP Exposition for eBPF Firewall
// ==============================================================================
// Exposes line-rate packet metrics, eBPF map rule counts, Ring Buffer telemetry,
// and bounded-cardinality Top 100 blocked attacker IP statistics.
// ==============================================================================

use crate::console::*;
use crate::firehol::FireholMetrics;
use crate::top_n::{BlockedIpStats, BlockedIpTopN, BlockedProtocol, RankingCriterion};
use firewall_common::FirewallStats;
use prometheus::{
    histogram_opts, opts, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    TextEncoder,
};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
};
use tracing::{info, warn};

/// Pure helper function to resolve Git reference priority (Tag > Commit > "unknown").
pub fn resolve_git_ref(tag: Option<&str>, commit: Option<&str>) -> String {
    if let Some(t) = tag {
        let trimmed = t.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(c) = commit {
        let trimmed = c.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

/// Centralized Prometheus metrics collection for the eBPF Firewall.
#[derive(Clone)]
pub struct PrometheusMetrics {
    /// Custom Prometheus registry isolated from global state
    pub registry: Registry,

    /// 1 if firewall is running, 0 if terminating
    pub firewall_up: IntGauge,

    /// Build and version information (constant 1) with version, git_ref, aya_version
    pub build_info: IntGaugeVec,

    /// Total ingress packets categorized by action (accept, drop)
    pub packets_total: IntCounterVec,

    /// Blocked packets categorized by protocol (TCP, UDP, ICMP, OTHER) and match type (Exact, LPM)
    pub packets_blocked_total: IntCounterVec,

    /// Packets permitted through the firewall
    pub packets_accepted_total: IntCounter,

    /// Ingress bytes processed categorized by action (accept, drop)
    pub bytes_total: IntCounterVec,

    /// Active reputation blocklist rules in eBPF maps by map type
    pub rules_active: IntGaugeVec,

    /// Total active rules count
    pub rules_total: IntGauge,

    /// Granular eBPF map entries breakdown (labels: map, ip_version, entry_type)
    pub map_entries: IntGaugeVec,

    /// Telemetry events received from the eBPF Ring Buffer
    pub ringbuf_events_total: IntCounter,

    /// Operational and processing errors by component
    pub errors_total: IntCounterVec,

    /// Latency histogram of eBPF map synchronization operations
    pub rule_sync_duration_seconds: Histogram,

    /// Blocked packets for Top-100 IPs categorized by IP and protocol
    pub blocked_ip_packets: IntCounterVec,

    /// Blocked bytes for Top-100 IPs categorized by IP and protocol
    pub blocked_ip_bytes: IntCounterVec,

    /// Total blocked packets for Top-100 IPs categorized by IP across all protocols
    pub blocked_ip_total_packets: IntCounterVec,

    /// Total blocked bytes for Top-100 IPs categorized by IP across all protocols
    pub blocked_ip_total_bytes: IntCounterVec,

    /// Current count of unique IP addresses present in the Top 100
    pub top_blocked_ips_count: IntGauge,

    /// In-memory Top-100 manager with bounded cardinality and dynamic eviction
    pub top_blocked_ips: Arc<Mutex<BlockedIpTopN>>,

    /// Dedicated metrics tracking FireHOL blocklists, synchronization, and categories
    pub firehol: FireholMetrics,

    /// Start timestamp for uptime calculations
    start_time: Instant,
}

pub type FirewallMetrics = PrometheusMetrics;

impl PrometheusMetrics {
    /// Create and register all firewall Prometheus metrics using compile-time Git reference.
    pub fn new() -> Result<Self, prometheus::Error> {
        let git_ref = option_env!("FIREWALL_GIT_REF").unwrap_or("unknown");
        Self::with_git_ref(git_ref)
    }

    /// Create and register all firewall Prometheus metrics with an explicit Git reference.
    pub fn with_git_ref(git_ref: &str) -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // 1. Service state & build info
        let firewall_up = IntGauge::with_opts(opts!(
            "firewall_up",
            "Indicates whether the eBPF firewall daemon is actively running (1) or stopped (0)"
        ))?;
        registry.register(Box::new(firewall_up.clone()))?;
        firewall_up.set(1);

        let build_info = IntGaugeVec::new(
            opts!(
                "firewall_build_info",
                "Firewall version, git reference, and build environment metadata"
            ),
            &["version", "git_ref", "aya_version"],
        )?;
        registry.register(Box::new(build_info.clone()))?;
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), git_ref, "0.14.0"])
            .set(1);

        // 2. Packet counters
        let packets_total = IntCounterVec::new(
            opts!(
                "firewall_packets_total",
                "Total number of ingress network packets processed by XDP hook"
            ),
            &["action"],
        )?;
        registry.register(Box::new(packets_total.clone()))?;
        packets_total.with_label_values(&["accept"]);
        packets_total.with_label_values(&["drop"]);

        let packets_blocked_total = IntCounterVec::new(
            opts!(
                "firewall_packets_blocked_total",
                "Total number of blocked ingress packets by protocol and match type"
            ),
            &["protocol", "match_type"],
        )?;
        registry.register(Box::new(packets_blocked_total.clone()))?;
        packets_blocked_total.with_label_values(&["TCP", "Exact HashMap"]);
        packets_blocked_total.with_label_values(&["UDP", "Exact HashMap"]);
        packets_blocked_total.with_label_values(&["ICMP", "Exact HashMap"]);

        let packets_accepted_total = IntCounter::with_opts(opts!(
            "firewall_packets_accepted_total",
            "Total number of ingress packets accepted through by XDP"
        ))?;
        registry.register(Box::new(packets_accepted_total.clone()))?;

        let bytes_total = IntCounterVec::new(
            opts!(
                "firewall_bytes_total",
                "Total ingress network bytes processed by XDP hook"
            ),
            &["action"],
        )?;
        registry.register(Box::new(bytes_total.clone()))?;
        bytes_total.with_label_values(&["accept"]);
        bytes_total.with_label_values(&["drop"]);

        // 3. eBPF Rule Gauges (Legacy & Aggregate)
        let rules_active = IntGaugeVec::new(
            opts!(
                "firewall_rules_active",
                "Number of active blocking rules loaded in eBPF kernel maps"
            ),
            &["map_type"],
        )?;
        registry.register(Box::new(rules_active.clone()))?;
        rules_active.with_label_values(&["exact_v4"]);
        rules_active.with_label_values(&["exact_v6"]);
        rules_active.with_label_values(&["lpm_v4"]);
        rules_active.with_label_values(&["lpm_v6"]);

        let rules_total = IntGauge::with_opts(opts!(
            "firewall_rules_total",
            "Total number of active reputation blocklist rules across all maps"
        ))?;
        registry.register(Box::new(rules_total.clone()))?;

        // 4. Granular eBPF Map Entries Gauges
        let map_entries = IntGaugeVec::new(
            opts!(
                "firewall_map_entries",
                "Number of active elements currently loaded in eBPF maps by map, IP version, and entry type"
            ),
            &["map", "ip_version", "entry_type"],
        )?;
        registry.register(Box::new(map_entries.clone()))?;
        map_entries.with_label_values(&["lpm_trie", "ipv4", "cidr"]);
        map_entries.with_label_values(&["lpm_trie", "ipv6", "cidr"]);
        map_entries.with_label_values(&["hashmap", "ipv4", "ip"]);
        map_entries.with_label_values(&["hashmap", "ipv6", "ip"]);

        // 5. Ring Buffer & Diagnostics
        let ringbuf_events_total = IntCounter::with_opts(opts!(
            "firewall_ringbuf_events_total",
            "Total security audit events consumed from eBPF Ring Buffer"
        ))?;
        registry.register(Box::new(ringbuf_events_total.clone()))?;

        let errors_total = IntCounterVec::new(
            opts!(
                "firewall_errors_total",
                "Total count of operational errors encountered by the firewall daemon"
            ),
            &["error_type"],
        )?;
        registry.register(Box::new(errors_total.clone()))?;
        errors_total.with_label_values(&["sync"]);
        errors_total.with_label_values(&["ringbuf_poll"]);

        // 6. Latency Histogram for Rule Synchronization
        let sync_opts = histogram_opts!(
            "firewall_rule_sync_duration_seconds",
            "Duration of eBPF map synchronization operations in seconds",
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        );
        let rule_sync_duration_seconds = Histogram::with_opts(sync_opts)?;
        registry.register(Box::new(rule_sync_duration_seconds.clone()))?;

        // 7. Top 100 Blocked IP Metrics (with Cardinality Control)
        let blocked_ip_packets = IntCounterVec::new(
            opts!(
                "firewall_blocked_ip_packets",
                "Total blocked packets per IP address and protocol for the Top 100 blocked IPs"
            ),
            &["ip", "protocol"],
        )?;
        registry.register(Box::new(blocked_ip_packets.clone()))?;

        let blocked_ip_bytes = IntCounterVec::new(
            opts!(
                "firewall_blocked_ip_bytes",
                "Total blocked traffic volume in bytes per IP address and protocol for the Top 100 blocked IPs"
            ),
            &["ip", "protocol"],
        )?;
        registry.register(Box::new(blocked_ip_bytes.clone()))?;

        let blocked_ip_total_packets = IntCounterVec::new(
            opts!(
                "firewall_blocked_ip_total_packets",
                "Total blocked packets per IP address across all protocols for the Top 100 blocked IPs"
            ),
            &["ip"],
        )?;
        registry.register(Box::new(blocked_ip_total_packets.clone()))?;

        let blocked_ip_total_bytes = IntCounterVec::new(
            opts!(
                "firewall_blocked_ip_total_bytes",
                "Total blocked traffic volume in bytes per IP address across all protocols for the Top 100 blocked IPs"
            ),
            &["ip"],
        )?;
        registry.register(Box::new(blocked_ip_total_bytes.clone()))?;

        let top_blocked_ips_count = IntGauge::with_opts(opts!(
            "firewall_top_blocked_ips_count",
            "Current number of high-risk IP addresses present in the Top 100 blocked list"
        ))?;
        registry.register(Box::new(top_blocked_ips_count.clone()))?;

        let top_blocked_ips = Arc::new(Mutex::new(BlockedIpTopN::new(
            100,
            RankingCriterion::Packets,
        )));

        // 8. FireHOL Blocklist Metrics
        let firehol = FireholMetrics::new(&registry)?;

        Ok(Self {
            registry,
            firewall_up,
            build_info,
            packets_total,
            packets_blocked_total,
            packets_accepted_total,
            bytes_total,
            rules_active,
            rules_total,
            map_entries,
            ringbuf_events_total,
            errors_total,
            rule_sync_duration_seconds,
            blocked_ip_packets,
            blocked_ip_bytes,
            blocked_ip_total_packets,
            blocked_ip_total_bytes,
            top_blocked_ips_count,
            top_blocked_ips,
            firehol,
            start_time: Instant::now(),
        })
    }

    /// Record a packet blocked by eBPF.
    pub fn record_blocked_packet(&self, proto: &str, match_type: &str, byte_len: u64) {
        self.packets_total.with_label_values(&["drop"]).inc();
        self.packets_blocked_total
            .with_label_values(&[proto, match_type])
            .inc();
        self.bytes_total
            .with_label_values(&["drop"])
            .inc_by(byte_len);
    }

    /// Record a blocked packet event for Top-N IP tracking.
    pub fn record_blocked_ip(&self, ip: IpAddr, protocol: BlockedProtocol, bytes: u64) {
        if let Ok(mut top) = self.top_blocked_ips.lock() {
            top.record_event(ip, protocol, bytes);
        }
    }

    /// Synchronize the in-memory Top-N blocked IPs to Prometheus metrics.
    ///
    /// Removes series for evicted IPs and registers / increments series for active Top-N IPs.
    pub fn sync_top_blocked_ips(&self) {
        if let Ok(mut top) = self.top_blocked_ips.lock() {
            top.sync_to_metrics(
                &self.blocked_ip_packets,
                &self.blocked_ip_bytes,
                &self.blocked_ip_total_packets,
                &self.blocked_ip_total_bytes,
                &self.top_blocked_ips_count,
            );
        }
    }

    /// Update the ranking criterion for Top-N classification (e.g. Packets or Bytes).
    pub fn set_top_n_criterion(&self, criterion: RankingCriterion) {
        if let Ok(mut top) = self.top_blocked_ips.lock() {
            top.set_criterion(criterion);
        }
    }

    /// Return the active ranking criterion.
    pub fn top_n_criterion(&self) -> RankingCriterion {
        self.top_blocked_ips
            .lock()
            .map(|t| t.criterion())
            .unwrap_or_default()
    }

    /// Retrieve the current Top-N IP statistics.
    pub fn top_n_stats(&self) -> Vec<BlockedIpStats> {
        self.top_blocked_ips
            .lock()
            .map(|t| t.top_n_stats())
            .unwrap_or_default()
    }

    /// Return the total number of distinct blocked IPs tracked in memory.
    pub fn tracked_blocked_ips_count(&self) -> usize {
        self.top_blocked_ips
            .lock()
            .map(|t| t.tracked_count())
            .unwrap_or(0)
    }

    /// Return the set of IP strings currently exposed in Prometheus series.
    pub fn currently_exported_top_ips(&self) -> HashSet<String> {
        self.top_blocked_ips
            .lock()
            .map(|t| t.currently_exported_ips().clone())
            .unwrap_or_default()
    }

    /// Record a packet accepted by eBPF.
    pub fn record_accepted_packet(&self, byte_len: u64) {
        self.packets_total.with_label_values(&["accept"]).inc();
        self.packets_accepted_total.inc();
        self.bytes_total
            .with_label_values(&["accept"])
            .inc_by(byte_len);
    }

    #[inline(always)]
    pub fn record_passed_packet(&self, byte_len: u64) {
        self.record_accepted_packet(byte_len);
    }

    /// Record an event received from the BPF Ring Buffer.
    pub fn record_ringbuf_event(&self) {
        self.ringbuf_events_total.inc();
    }

    /// Record an error event.
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Synchronize counts of all eBPF map entries.
    pub fn update_map_entries(
        &self,
        exact_v4: usize,
        exact_v6: usize,
        lpm_v4: usize,
        lpm_v6: usize,
    ) {
        self.map_entries
            .with_label_values(&["hashmap", "ipv4", "ip"])
            .set(exact_v4 as i64);
        self.map_entries
            .with_label_values(&["hashmap", "ipv6", "ip"])
            .set(exact_v6 as i64);
        self.map_entries
            .with_label_values(&["lpm_trie", "ipv4", "cidr"])
            .set(lpm_v4 as i64);
        self.map_entries
            .with_label_values(&["lpm_trie", "ipv6", "cidr"])
            .set(lpm_v6 as i64);

        self.update_rules_count(exact_v4, exact_v6, lpm_v4, lpm_v6);
    }

    /// Increment count for a specific map entry type.
    pub fn inc_map_entry(&self, map: &str, ip_version: &str, entry_type: &str) {
        self.map_entries
            .with_label_values(&[map, ip_version, entry_type])
            .inc();
        self.rules_total.inc();
    }

    /// Decrement count for a specific map entry type.
    pub fn dec_map_entry(&self, map: &str, ip_version: &str, entry_type: &str) {
        self.map_entries
            .with_label_values(&[map, ip_version, entry_type])
            .dec();
        self.rules_total.dec();
    }

    /// Get current value for a specific map entry breakdown.
    pub fn get_map_entries(&self, map: &str, ip_version: &str, entry_type: &str) -> i64 {
        self.map_entries
            .with_label_values(&[map, ip_version, entry_type])
            .get()
    }

    /// Total entries currently loaded in the LPM Trie (IPv4 + IPv6 CIDRs).
    pub fn lpm_trie_entries(&self) -> i64 {
        self.get_map_entries("lpm_trie", "ipv4", "cidr")
            + self.get_map_entries("lpm_trie", "ipv6", "cidr")
    }

    /// Total entries currently loaded in the BPF HashMap (IPv4 + IPv6 individual IPs).
    pub fn hashmap_entries(&self) -> i64 {
        self.get_map_entries("hashmap", "ipv4", "ip")
            + self.get_map_entries("hashmap", "ipv6", "ip")
    }

    /// Total IPv4 entries across both HashMap and LPM Trie.
    pub fn ipv4_entries(&self) -> i64 {
        self.get_map_entries("hashmap", "ipv4", "ip")
            + self.get_map_entries("lpm_trie", "ipv4", "cidr")
    }

    /// Total IPv6 entries across both HashMap and LPM Trie.
    pub fn ipv6_entries(&self) -> i64 {
        self.get_map_entries("hashmap", "ipv6", "ip")
            + self.get_map_entries("lpm_trie", "ipv6", "cidr")
    }

    /// IPv4 individual IP entries in HashMap.
    pub fn ipv4_ip_entries(&self) -> i64 {
        self.get_map_entries("hashmap", "ipv4", "ip")
    }

    /// IPv6 individual IP entries in HashMap.
    pub fn ipv6_ip_entries(&self) -> i64 {
        self.get_map_entries("hashmap", "ipv6", "ip")
    }

    /// IPv4 CIDR subnet entries in LPM Trie.
    pub fn ipv4_cidr_entries(&self) -> i64 {
        self.get_map_entries("lpm_trie", "ipv4", "cidr")
    }

    /// IPv6 CIDR subnet entries in LPM Trie.
    pub fn ipv6_cidr_entries(&self) -> i64 {
        self.get_map_entries("lpm_trie", "ipv6", "cidr")
    }

    /// Update the number of active rules in legacy eBPF maps gauges.
    pub fn update_rules_count(
        &self,
        exact_v4: usize,
        exact_v6: usize,
        lpm_v4: usize,
        lpm_v6: usize,
    ) {
        self.rules_active
            .with_label_values(&["exact_v4"])
            .set(exact_v4 as i64);
        self.rules_active
            .with_label_values(&["exact_v6"])
            .set(exact_v6 as i64);
        self.rules_active
            .with_label_values(&["lpm_v4"])
            .set(lpm_v4 as i64);
        self.rules_active
            .with_label_values(&["lpm_v6"])
            .set(lpm_v6 as i64);

        let total = exact_v4 + exact_v6 + lpm_v4 + lpm_v6;
        self.rules_total.set(total as i64);
    }

    /// Observe duration of rule synchronization into eBPF maps.
    pub fn observe_rule_sync_duration(&self, duration: Duration) {
        self.rule_sync_duration_seconds
            .observe(duration.as_secs_f64());
    }

    /// Synchronize kernel-level aggregate stats read from the eBPF STATS map.
    pub fn update_from_ebpf_stats(&self, stats: &FirewallStats) {
        let current_accepted = self.packets_accepted_total.get();
        if stats.accepted_packets > current_accepted {
            let diff_pkts = stats.accepted_packets - current_accepted;
            self.packets_accepted_total.inc_by(diff_pkts);
            self.packets_total
                .with_label_values(&["accept"])
                .inc_by(diff_pkts);
        }

        let current_accepted_bytes = self.bytes_total.with_label_values(&["accept"]).get();
        if stats.accepted_bytes > current_accepted_bytes {
            let diff_bytes = stats.accepted_bytes - current_accepted_bytes;
            self.bytes_total
                .with_label_values(&["accept"])
                .inc_by(diff_bytes);
        }
    }

    /// Uptime duration since firewall metrics initialization.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Export metrics formatted in standard Prometheus text format.
    ///
    /// Automatically synchronizes the Top 100 blocked IPs before encoding.
    pub fn encode(&self) -> Result<String, prometheus::Error> {
        self.sync_top_blocked_ips();
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        encoder.encode_to_string(&metric_families)
    }
}

/// Lightweight HTTP server serving Prometheus metrics on `/metrics`.
pub struct MetricsServer {
    metrics: Arc<PrometheusMetrics>,
    listen_addr: SocketAddr,
    drop_logs_enabled: Option<Arc<AtomicBool>>,
}

impl MetricsServer {
    /// Create a new Prometheus metrics HTTP server.
    pub fn new(metrics: Arc<PrometheusMetrics>, listen_addr: SocketAddr) -> Self {
        Self {
            metrics,
            listen_addr,
            drop_logs_enabled: None,
        }
    }

    /// Attach a shared atomic flag controlling console drop logs.
    pub fn with_drop_logs_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.drop_logs_enabled = Some(flag);
        self
    }

    /// Run the HTTP server until the shutdown signal is triggered.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) -> io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(
            "{}",
            green_bold(format!(
                "📈 Prometheus metrics server listening on http://{} 🚀 (endpoint: /metrics)",
                bold(self.listen_addr)
            ))
        );

        let drop_logs_flag = self.drop_logs_enabled;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("{}", yellow_bold("🛑 Metrics server received shutdown signal."));
                    break;
                }
                res = listener.accept() => {
                    match res {
                        Ok((mut socket, _peer_addr)) => {
                            let metrics = Arc::clone(&self.metrics);
                            let drop_flag = drop_logs_flag.clone();
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                if let Ok(n) = socket.read(&mut buf).await {
                                    let req = String::from_utf8_lossy(&buf[..n]);
                                    if req.starts_with("GET /metrics") || req.starts_with("GET / ") {
                                        let body = metrics.encode().unwrap_or_else(|e| format!("# Error gathering metrics: {e}\n"));
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            body.len(),
                                            body
                                        );
                                        let _ = socket.write_all(response.as_bytes()).await;
                                    } else if req.starts_with("GET /health") {
                                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                                        let _ = socket.write_all(response.as_bytes()).await;
                                    } else if req.starts_with("POST /telemetry/drop-logs")
                                        || req.starts_with("GET /telemetry/drop-logs")
                                    {
                                        let new_state = !req.contains("enabled=false")
                                            && !req.contains("enable=false")
                                            && !req.contains("/disable")
                                            && (req.contains("enabled=true")
                                                || req.contains("enable=true")
                                                || req.contains("/enable"));

                                        if let Some(flag) = &drop_flag {
                                            flag.store(new_state, Ordering::Relaxed);
                                            if new_state {
                                                info!("{}", green_bold("🔊 Console drop logging enabled via HTTP API."));
                                            } else {
                                                info!("{}", yellow_bold("🤫 Console drop logging disabled via HTTP API (benchmark mode)."));
                                            }
                                        }

                                        let body = format!(r#"{{"drop_logs_enabled":{}}}"#, new_state);
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            body.len(),
                                            body
                                        );
                                        let _ = socket.write_all(response.as_bytes()).await;
                                    } else {
                                        let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
                                        let _ = socket.write_all(response.as_bytes()).await;
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("⚠️ Failed to accept metrics connection: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_git_ref_priority() {
        // Tag has priority
        assert_eq!(resolve_git_ref(Some("v1.0.0"), Some("abcdef1")), "v1.0.0");
        // Fallback to commit hash when tag is None
        assert_eq!(resolve_git_ref(None, Some("abcdef1")), "abcdef1");
        // Fallback to commit hash when tag is empty
        assert_eq!(resolve_git_ref(Some("   "), Some("abcdef1")), "abcdef1");
        // Fallback to unknown when neither exists
        assert_eq!(resolve_git_ref(None, None), "unknown");
        assert_eq!(resolve_git_ref(Some(""), Some("")), "unknown");
    }

    #[test]
    fn test_prometheus_metrics_creation_and_registration() {
        let metrics = PrometheusMetrics::new().expect("Metrics initialization failed");
        let encoded = metrics.encode().expect("Metrics encoding failed");

        assert!(encoded.contains("firewall_up 1"));
        assert!(encoded.contains("firewall_build_info"));
        assert!(encoded.contains("firewall_map_entries"));
        assert!(encoded.contains("git_ref"));
        assert!(encoded.contains("firewall_top_blocked_ips_count"));
    }

    #[tokio::test]
    async fn test_metrics_http_server_response() {
        let metrics = Arc::new(PrometheusMetrics::new().expect("Metrics init failed"));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let listen_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = MetricsServer::new(Arc::clone(&metrics), listen_addr);

        let _server_handle = tokio::spawn(server.run(shutdown_rx));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("firewall_up 1"));
        assert!(response.contains("firewall_top_blocked_ips_count"));
    }

    #[tokio::test]
    async fn test_metrics_http_server_toggle_drop_logs() {
        let metrics = Arc::new(PrometheusMetrics::new().expect("Metrics init failed"));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let drop_flag = Arc::new(AtomicBool::new(true));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let listen_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = MetricsServer::new(Arc::clone(&metrics), listen_addr)
            .with_drop_logs_flag(Arc::clone(&drop_flag));

        let _server_handle = tokio::spawn(server.run(shutdown_rx));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. Disable drop logs
        let mut stream = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        let request = "POST /telemetry/drop-logs?enabled=false HTTP/1.1
Host: localhost

";
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains(r#"{"drop_logs_enabled":false}"#));
        assert!(!drop_flag.load(Ordering::Relaxed));

        // 2. Enable drop logs
        let mut stream2 = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        let request2 = "POST /telemetry/drop-logs?enabled=true HTTP/1.1
Host: localhost

";
        stream2.write_all(request2.as_bytes()).await.unwrap();

        let mut buf2 = vec![0u8; 1024];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let response2 = String::from_utf8_lossy(&buf2[..n2]);

        assert!(response2.contains("HTTP/1.1 200 OK"));
        assert!(response2.contains(r#"{"drop_logs_enabled":true}"#));
        assert!(drop_flag.load(Ordering::Relaxed));
    }

    #[test]
    fn test_top_n_criterion_and_aux_metrics() {
        let metrics = PrometheusMetrics::new().expect("Metrics init failed");

        // Default criterion is Packets.
        assert_eq!(metrics.top_n_criterion(), RankingCriterion::Packets);

        // Record blocked traffic, then flip the ranking criterion to Bytes.
        metrics.record_blocked_ip(IpAddr::from([198, 51, 100, 14]), BlockedProtocol::Tcp, 1500);
        metrics.record_blocked_ip(IpAddr::from([198, 51, 100, 14]), BlockedProtocol::Udp, 512);
        metrics.sync_top_blocked_ips();

        metrics.set_top_n_criterion(RankingCriterion::Bytes);
        assert_eq!(metrics.top_n_criterion(), RankingCriterion::Bytes);

        let stats = metrics.top_n_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].ip, IpAddr::from([198, 51, 100, 14]));
        assert_eq!(stats[0].total_packets, 2);
        assert_eq!(stats[0].total_bytes, 2012);

        assert!(metrics.tracked_blocked_ips_count() >= 1);
        assert!(!metrics.currently_exported_top_ips().is_empty());

        // Accepted-packet alias and uptime.
        metrics.record_passed_packet(128);
        assert!(metrics.uptime() >= Duration::ZERO);
    }

    #[tokio::test]
    async fn test_metrics_http_server_health_and_toggle_variants() {
        let metrics = Arc::new(PrometheusMetrics::new().expect("Metrics init failed"));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let drop_flag = Arc::new(AtomicBool::new(true));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let listen_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = MetricsServer::new(Arc::clone(&metrics), listen_addr)
            .with_drop_logs_flag(Arc::clone(&drop_flag));

        let _server_handle = tokio::spawn(server.run(shutdown_rx));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. GET /health returns the short OK body.
        let mut stream = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\r\n\r\nOK"));

        // 2. GET telemetry toggle via the path variant (enable true).
        let mut stream2 = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        stream2
            .write_all(b"GET /telemetry/drop-logs/enable HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf2 = vec![0u8; 256];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let response2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(response2.contains(r#"{"drop_logs_enabled":true}"#));
        assert!(drop_flag.load(Ordering::Relaxed));

        // 3. POST toggle via the enable=true query-variant (disable first, then enable).
        let mut stream3 = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        stream3
            .write_all(b"POST /telemetry/drop-logs?enable=false HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf3 = vec![0u8; 256];
        let n3 = stream3.read(&mut buf3).await.unwrap();
        let response3 = String::from_utf8_lossy(&buf3[..n3]);
        assert!(response3.contains(r#"{"drop_logs_enabled":false}"#));
        assert!(!drop_flag.load(Ordering::Relaxed));

        // 4. enable=true query variant on a fresh connection re-enables logs.
        let mut stream4 = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        stream4
            .write_all(b"POST /telemetry/drop-logs?enable=true HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf4 = vec![0u8; 256];
        let n4 = stream4.read(&mut buf4).await.unwrap();
        let response4 = String::from_utf8_lossy(&buf4[..n4]);
        assert!(response4.contains(r#"{"drop_logs_enabled":true}"#));
        assert!(drop_flag.load(Ordering::Relaxed));
    }
}
