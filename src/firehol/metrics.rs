//! Prometheus metrics tracking FireHOL Git synchronization, parsing, rule installation, and blocked telemetry.

use prometheus::{
    histogram_opts, opts, Gauge, GaugeVec, Histogram, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Registry,
};

/// Dedicated Prometheus metrics for FireHOL synchronization, parsing, and telemetry.
#[derive(Clone)]
pub struct FireholMetrics {
    // -------------------------------------------------------------------------
    // 1. Git Synchronization Metrics
    // -------------------------------------------------------------------------
    /// Number of git clone operations performed
    pub git_clones_total: IntCounter,
    /// Number of git fetch operations performed
    pub git_fetches_total: IntCounter,
    /// Number of synchronizations where the local repository was already up-to-date
    pub git_up_to_date_total: IntCounter,
    /// Total number of Git synchronization failures
    pub git_errors_total: IntCounter,
    /// Latency histogram of git clone operations
    pub git_clone_duration_seconds: Histogram,
    /// Latency histogram of git fetch operations
    pub git_fetch_duration_seconds: Histogram,
    /// Total duration of the repository synchronization step
    pub git_sync_duration_seconds: Histogram,
    /// Unix timestamp of the last successful synchronization
    pub git_last_sync_timestamp: IntGauge,
    /// Unix timestamp of the latest synchronized Git commit
    pub git_last_commit_timestamp: IntGauge,

    // -------------------------------------------------------------------------
    // 2. Parsing & Compilation Metrics
    // -------------------------------------------------------------------------
    /// Duration of parallel parsing of all .ipset and .netset files
    pub parse_duration_seconds: Histogram,
    pub import_stage_seconds: GaugeVec,
    pub import_throughput_bytes_per_second: GaugeVec,
    pub import_entries_per_second: Gauge,
    pub import_written_bytes: IntGauge,
    pub import_files: IntGauge,
    /// Duration of populating eBPF HashMaps and LPM Tries with FireHOL entries
    pub map_load_duration_seconds: Histogram,
    /// Total number of active blocklists loaded
    pub blocklists_total: IntGauge,
    /// Total number of active FireHOL IP and CIDR entries loaded
    pub total_entries: IntGauge,
    /// Total number of active IPv4 entries
    pub ipv4_total: IntGauge,
    /// Total number of active IPv6 entries
    pub ipv6_total: IntGauge,
    /// Total number of exact single-host IP entries (routed to HashMaps)
    pub exact_total: IntGauge,
    /// Total number of CIDR subnet entries (routed to LPM Tries)
    pub cidr_total: IntGauge,
    /// Total entries currently inserted in eBPF HashMaps
    pub hashmap_entries: IntGauge,
    /// Total entries currently inserted in eBPF LPM Tries
    pub lpm_entries: IntGauge,
    /// Total number of invalid IP or CIDR entries encountered
    pub invalid_entries_total: IntCounter,
    /// Unix timestamp of the last successful parse and rule preparation
    pub last_compile_timestamp: IntGauge,
    /// Total file bytes read across all FireHOL blocklists
    pub loaded_bytes_total: IntGauge,

    // -------------------------------------------------------------------------
    // 3. Category & Telemetry Metrics
    // -------------------------------------------------------------------------
    /// Active FireHOL entries labeled by category, ip_version, and entry_type
    pub entries_by_category: IntGaugeVec,
    /// Active FireHOL entries labeled by blocklist name
    pub entries_by_blocklist: IntGaugeVec,
    /// Total blocked packets labeled by FireHOL category and L4 protocol
    pub blocked_packets_total: IntCounterVec,
    /// Total blocked wire bytes labeled by FireHOL category
    pub blocked_bytes_total: IntCounterVec,

    // -------------------------------------------------------------------------
    // 4. Cron Scheduler Metrics
    // -------------------------------------------------------------------------
    /// Total number of FireHOL cron scheduler job executions
    pub cron_executions_total: IntCounter,
    /// Total number of successful FireHOL updates triggered by cron
    pub cron_success_total: IntCounter,
    /// Total number of FireHOL cron executions where no remote Git change was detected
    pub cron_no_change_total: IntCounter,
    /// Total number of FireHOL cron synchronization failures
    pub cron_failures_total: IntCounter,
    /// Indicates whether the last FireHOL cron job execution failed (1) or succeeded (0)
    pub cron_last_error: IntGauge,
    /// Total number of FireHOL cron runs skipped because another sync was running
    pub cron_skipped_total: IntCounter,
    /// Duration of the last FireHOL synchronization in seconds
    pub cron_last_duration_seconds: Gauge,
    /// Unix timestamp of the last successful FireHOL synchronization
    pub cron_last_success_timestamp_seconds: IntGauge,
    /// Unix timestamp of the last FireHOL cron job launch
    pub cron_last_run_timestamp_seconds: IntGauge,
}

impl FireholMetrics {
    /// Register all FireHOL metrics into the provided Prometheus registry.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        // 1. Git
        let git_clones_total = IntCounter::with_opts(opts!(
            "firewall_firehol_git_clones_total",
            "Total number of fresh shallow clone operations of the FireHOL repository"
        ))?;
        registry.register(Box::new(git_clones_total.clone()))?;

        let git_fetches_total = IntCounter::with_opts(opts!(
            "firewall_firehol_git_fetches_total",
            "Total number of shallow fetch operations of the FireHOL repository"
        ))?;
        registry.register(Box::new(git_fetches_total.clone()))?;

        let git_up_to_date_total = IntCounter::with_opts(opts!(
            "firewall_firehol_git_up_to_date_total",
            "Total number of synchronizations where the repository was already up-to-date"
        ))?;
        registry.register(Box::new(git_up_to_date_total.clone()))?;

        let git_errors_total = IntCounter::with_opts(opts!(
            "firewall_firehol_git_errors_total",
            "Total number of Git synchronization errors (network, filesystem, corruption)"
        ))?;
        registry.register(Box::new(git_errors_total.clone()))?;

        let git_clone_duration_seconds = Histogram::with_opts(histogram_opts!(
            "firewall_firehol_git_clone_duration_seconds",
            "Duration in seconds of Git clone operations",
            vec![0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
        ))?;
        registry.register(Box::new(git_clone_duration_seconds.clone()))?;

        let git_fetch_duration_seconds = Histogram::with_opts(histogram_opts!(
            "firewall_firehol_git_fetch_duration_seconds",
            "Duration in seconds of Git fetch operations",
            vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        ))?;
        registry.register(Box::new(git_fetch_duration_seconds.clone()))?;

        let git_sync_duration_seconds = Histogram::with_opts(histogram_opts!(
            "firewall_firehol_git_sync_duration_seconds",
            "Total duration in seconds of FireHOL repository synchronization",
            vec![0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 15.0, 30.0]
        ))?;
        registry.register(Box::new(git_sync_duration_seconds.clone()))?;

        let git_last_sync_timestamp = IntGauge::with_opts(opts!(
            "firewall_firehol_git_last_sync_timestamp",
            "Unix timestamp of the last successful FireHOL synchronization"
        ))?;
        registry.register(Box::new(git_last_sync_timestamp.clone()))?;

        let git_last_commit_timestamp = IntGauge::with_opts(opts!(
            "firewall_firehol_git_last_commit_timestamp",
            "Unix timestamp of the latest synchronized Git commit"
        ))?;
        registry.register(Box::new(git_last_commit_timestamp.clone()))?;

        // 2. Parsing & Compilation
        let parse_duration_seconds = Histogram::with_opts(histogram_opts!(
            "firewall_firehol_parse_duration_seconds",
            "Total duration in seconds of parallel parsing of FireHOL blocklists",
            vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        ))?;
        registry.register(Box::new(parse_duration_seconds.clone()))?;

        let import_stage_seconds = GaugeVec::new(opts!(
            "firewall_firehol_import_stage_seconds", "Last import stage seconds; read/parse/queue_wait are summed worker times, stages overlap"), &["stage"])?;
        registry.register(Box::new(import_stage_seconds.clone()))?;
        let import_throughput_bytes_per_second = GaugeVec::new(opts!(
            "firewall_firehol_import_throughput_bytes_per_second", "Last import throughput; parsing uses total wall time, rocksdb uses logical batch bytes / write time"), &["kind"])?;
        registry.register(Box::new(import_throughput_bytes_per_second.clone()))?;
        let import_entries_per_second = Gauge::with_opts(opts!(
            "firewall_firehol_import_entries_per_second",
            "Entries / total import wall time"
        ))?;
        registry.register(Box::new(import_entries_per_second.clone()))?;
        let import_written_bytes = IntGauge::with_opts(opts!(
            "firewall_firehol_import_written_bytes",
            "Logical RocksDB batch bytes in last import, not physical disk bytes"
        ))?;
        registry.register(Box::new(import_written_bytes.clone()))?;
        let import_files = IntGauge::with_opts(opts!(
            "firewall_firehol_import_files",
            "Files processed in last successful import"
        ))?;
        registry.register(Box::new(import_files.clone()))?;

        let map_load_duration_seconds = Histogram::with_opts(histogram_opts!(
            "firewall_firehol_map_load_duration_seconds",
            "Total duration in seconds of populating eBPF HashMaps and LPM Tries with FireHOL entries",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        ))?;
        registry.register(Box::new(map_load_duration_seconds.clone()))?;

        let blocklists_total = IntGauge::with_opts(opts!(
            "firewall_firehol_blocklists_total",
            "Total number of unique FireHOL blocklists loaded"
        ))?;
        registry.register(Box::new(blocklists_total.clone()))?;

        let total_entries = IntGauge::with_opts(opts!(
            "firewall_firehol_total_entries",
            "Total number of active FireHOL IP and CIDR entries loaded into the firewall"
        ))?;
        registry.register(Box::new(total_entries.clone()))?;

        let ipv4_total = IntGauge::with_opts(opts!(
            "firewall_firehol_ipv4_total",
            "Total number of active IPv4 FireHOL entries (exact + CIDR)"
        ))?;
        registry.register(Box::new(ipv4_total.clone()))?;

        let ipv6_total = IntGauge::with_opts(opts!(
            "firewall_firehol_ipv6_total",
            "Total number of active IPv6 FireHOL entries (exact + CIDR)"
        ))?;
        registry.register(Box::new(ipv6_total.clone()))?;

        let exact_total = IntGauge::with_opts(opts!(
            "firewall_firehol_exact_total",
            "Total number of exact single-host IP entries loaded"
        ))?;
        registry.register(Box::new(exact_total.clone()))?;

        let cidr_total = IntGauge::with_opts(opts!(
            "firewall_firehol_cidr_total",
            "Total number of CIDR subnet entries loaded"
        ))?;
        registry.register(Box::new(cidr_total.clone()))?;

        let hashmap_entries = IntGauge::with_opts(opts!(
            "firewall_firehol_hashmap_entries",
            "Total number of entries inserted into eBPF exact match HashMaps"
        ))?;
        registry.register(Box::new(hashmap_entries.clone()))?;

        let lpm_entries = IntGauge::with_opts(opts!(
            "firewall_firehol_lpm_entries",
            "Total number of entries inserted into eBPF LPM Tries"
        ))?;
        registry.register(Box::new(lpm_entries.clone()))?;

        let invalid_entries_total = IntCounter::with_opts(opts!(
            "firewall_firehol_invalid_entries_total",
            "Total number of invalid IP or CIDR entries encountered"
        ))?;
        registry.register(Box::new(invalid_entries_total.clone()))?;

        let last_compile_timestamp = IntGauge::with_opts(opts!(
            "firewall_firehol_last_compile_timestamp",
            "Unix timestamp of the last successful FireHOL rule compile and preparation"
        ))?;
        registry.register(Box::new(last_compile_timestamp.clone()))?;

        let loaded_bytes_total = IntGauge::with_opts(opts!(
            "firewall_firehol_loaded_bytes_total",
            "Total size in bytes of all processed FireHOL blocklist files"
        ))?;
        registry.register(Box::new(loaded_bytes_total.clone()))?;

        // 3. Category & Telemetry
        let entries_by_category = IntGaugeVec::new(
            opts!(
                "firewall_firehol_entries",
                "Number of active FireHOL entries partitioned by category, ip_version, and entry_type"
            ),
            &["category", "ip_version", "entry_type"],
        )?;
        registry.register(Box::new(entries_by_category.clone()))?;

        let entries_by_blocklist = IntGaugeVec::new(
            opts!(
                "firewall_firehol_blocklist_entries",
                "Number of active FireHOL entries partitioned by blocklist name"
            ),
            &["blocklist"],
        )?;
        registry.register(Box::new(entries_by_blocklist.clone()))?;

        let blocked_packets_total = IntCounterVec::new(
            opts!(
                "firewall_firehol_blocked_packets_total",
                "Total packets dropped by FireHOL rules partitioned by threat category and protocol"
            ),
            &["category", "protocol"],
        )?;
        registry.register(Box::new(blocked_packets_total.clone()))?;

        let blocked_bytes_total = IntCounterVec::new(
            opts!(
                "firewall_firehol_blocked_bytes_total",
                "Total wire bytes dropped by FireHOL rules partitioned by threat category"
            ),
            &["category"],
        )?;
        registry.register(Box::new(blocked_bytes_total.clone()))?;

        // 4. Cron Scheduler
        let cron_executions_total = IntCounter::with_opts(opts!(
            "firewall_firehol_cron_executions_total",
            "Total number of FireHOL cron scheduler job executions"
        ))?;
        registry.register(Box::new(cron_executions_total.clone()))?;

        let cron_success_total = IntCounter::with_opts(opts!(
            "firewall_firehol_cron_success_total",
            "Total number of successful FireHOL updates triggered by cron"
        ))?;
        registry.register(Box::new(cron_success_total.clone()))?;

        let cron_no_change_total = IntCounter::with_opts(opts!(
            "firewall_firehol_cron_no_change_total",
            "Total number of FireHOL cron executions with no upstream changes"
        ))?;
        registry.register(Box::new(cron_no_change_total.clone()))?;

        let cron_failures_total = IntCounter::with_opts(opts!(
            "firewall_firehol_cron_failures_total",
            "Total number of FireHOL cron synchronization failures"
        ))?;
        registry.register(Box::new(cron_failures_total.clone()))?;

        let cron_last_error = IntGauge::with_opts(opts!(
            "firewall_firehol_cron_last_error",
            "Indicates whether the last FireHOL cron execution failed (1) or succeeded (0)"
        ))?;
        registry.register(Box::new(cron_last_error.clone()))?;

        let cron_skipped_total = IntCounter::with_opts(opts!(
            "firewall_firehol_cron_skipped_total",
            "Total number of FireHOL cron runs skipped because another sync was running"
        ))?;
        registry.register(Box::new(cron_skipped_total.clone()))?;

        let cron_last_duration_seconds = Gauge::with_opts(opts!(
            "firewall_firehol_cron_last_duration_seconds",
            "Duration in seconds of the last FireHOL synchronization"
        ))?;
        registry.register(Box::new(cron_last_duration_seconds.clone()))?;

        let cron_last_success_timestamp_seconds = IntGauge::with_opts(opts!(
            "firewall_firehol_cron_last_success_timestamp_seconds",
            "Unix timestamp of the last successful FireHOL synchronization"
        ))?;
        registry.register(Box::new(cron_last_success_timestamp_seconds.clone()))?;

        let cron_last_run_timestamp_seconds = IntGauge::with_opts(opts!(
            "firewall_firehol_cron_last_run_timestamp_seconds",
            "Unix timestamp of the last FireHOL cron job launch"
        ))?;
        registry.register(Box::new(cron_last_run_timestamp_seconds.clone()))?;

        Ok(Self {
            git_clones_total,
            git_fetches_total,
            git_up_to_date_total,
            git_errors_total,
            git_clone_duration_seconds,
            git_fetch_duration_seconds,
            git_sync_duration_seconds,
            git_last_sync_timestamp,
            git_last_commit_timestamp,
            parse_duration_seconds,
            import_stage_seconds,
            import_throughput_bytes_per_second,
            import_entries_per_second,
            import_written_bytes,
            import_files,
            map_load_duration_seconds,
            blocklists_total,
            total_entries,
            ipv4_total,
            ipv6_total,
            exact_total,
            cidr_total,
            hashmap_entries,
            lpm_entries,
            invalid_entries_total,
            last_compile_timestamp,
            loaded_bytes_total,
            entries_by_category,
            entries_by_blocklist,
            blocked_packets_total,
            blocked_bytes_total,
            cron_executions_total,
            cron_success_total,
            cron_no_change_total,
            cron_failures_total,
            cron_last_error,
            cron_skipped_total,
            cron_last_duration_seconds,
            cron_last_success_timestamp_seconds,
            cron_last_run_timestamp_seconds,
        })
    }

    /// Record blocked telemetry event.
    pub fn record_drop(&self, category: &str, protocol: &str, bytes: u32) {
        self.blocked_packets_total
            .with_label_values(&[category, protocol])
            .inc();
        self.blocked_bytes_total
            .with_label_values(&[category])
            .inc_by(bytes as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn test_firehol_metrics_new_and_record_drop() {
        let registry = Registry::new();
        let metrics = FireholMetrics::new(&registry).expect("FireholMetrics init failed");

        metrics.record_drop("malware", "tcp", 1500);
        metrics.record_drop("abuse", "udp", 512);

        let families = registry.gather();
        let blocked_packets = families
            .iter()
            .find(|f| f.name() == "firewall_firehol_blocked_packets_total")
            .expect("blocked_packets_total present");
        let labels: Vec<String> = blocked_packets
            .get_metric()
            .iter()
            .map(|m| {
                let mut parts: Vec<_> = m
                    .get_label()
                    .iter()
                    .map(|l| (l.name().to_string(), l.value().to_string()))
                    .collect();
                parts.sort();
                format!("{parts:?}")
            })
            .collect();
        assert!(labels.contains(&r#"[("category", "abuse"), ("protocol", "udp")]"#.to_string()));
        assert!(labels.contains(&r#"[("category", "malware"), ("protocol", "tcp")]"#.to_string()));

        let blocked_bytes = families
            .iter()
            .find(|f| f.name() == "firewall_firehol_blocked_bytes_total")
            .expect("blocked_bytes_total present");
        for m in blocked_bytes.get_metric() {
            let cat = m
                .get_label()
                .iter()
                .find(|l| l.name() == "category")
                .map(|l| l.value())
                .unwrap_or("");
            let value = m.get_counter().value() as u64;
            match cat {
                "malware" => assert_eq!(value, 1500),
                "abuse" => assert_eq!(value, 512),
                _ => panic!("unexpected category label: {cat}"),
            }
        }
    }
}
