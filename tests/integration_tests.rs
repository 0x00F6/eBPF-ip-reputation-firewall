use clap::Parser;
use firewall_common::{
    FirewallStats, LpmKeyV4, LpmKeyV6, PacketLogEvent, RuleValue, ACTION_ACCEPT, ACTION_DROP,
    PROTO_TCP, PROTO_UDP,
};
use firewall_lib::{
    config::Config,
    loader::RuleLoader,
    metrics::{resolve_git_ref, MetricsServer, PrometheusMetrics},
};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[test]
fn test_packet_log_event_size_and_alignment() {
    assert_eq!(std::mem::size_of::<PacketLogEvent>(), 64);
    assert_eq!(std::mem::align_of::<PacketLogEvent>(), 8);
}

#[test]
fn test_lpm_key_v4_creation() {
    let key = LpmKeyV4::new(24, [192, 168, 1, 0]);
    assert_eq!(key.prefixlen, 24);
    assert_eq!(key.data, [192, 168, 1, 0]);
}

#[test]
fn test_lpm_key_v6_creation() {
    let mut ip = [0u8; 16];
    ip[0] = 0x20;
    ip[1] = 0x01;
    let key = LpmKeyV6::new(64, ip);
    assert_eq!(key.prefixlen, 64);
    assert_eq!(key.data[0], 0x20);
    assert_eq!(key.data[1], 0x01);
}

#[test]
fn test_packet_log_event_helpers_ipv4() {
    let mut src_ip = [0u8; 16];
    src_ip[..4].copy_from_slice(&[192, 0, 2, 1]);
    let mut dst_ip = [0u8; 16];
    dst_ip[..4].copy_from_slice(&[192, 0, 2, 2]);

    let event = PacketLogEvent {
        timestamp_ns: 1000,
        src_ip,
        dst_ip,
        rule_id: 1,
        action: ACTION_DROP,
        protocol: PROTO_TCP,
        ip_version: 4,
        match_type: 1,
        src_port: 443,
        dst_port: 80,
        packet_len: 1500,
        ifindex: 2,
        _pad: [0; 4],
    };

    assert_eq!(event.src_addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(event.dst_addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(event.protocol_name(), "TCP");
    assert_eq!(event.action_name(), "DROP");
    assert_eq!(event.match_type_name(), "Exact HashMap");
}

#[test]
fn test_packet_log_event_helpers_ipv6() {
    let src: Ipv6Addr = "2001:db8::42".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let event = PacketLogEvent {
        timestamp_ns: 2000,
        src_ip: src.octets(),
        dst_ip: dst.octets(),
        rule_id: 2,
        action: ACTION_ACCEPT,
        protocol: PROTO_UDP,
        ip_version: 6,
        match_type: 2,
        src_port: 5353,
        dst_port: 53,
        packet_len: 512,
        ifindex: 1,
        _pad: [0; 4],
    };

    assert_eq!(event.src_addr().to_string(), "2001:db8::42");
    assert_eq!(event.dst_addr().to_string(), "2001:db8::1");
    assert_eq!(event.protocol_name(), "UDP");
    assert_eq!(event.action_name(), "ACCEPT");
    assert_eq!(event.match_type_name(), "LPM Trie CIDR");
}

#[test]
fn test_event_serde_json() {
    let mut src_ip = [0u8; 16];
    src_ip[..4].copy_from_slice(&[10, 0, 0, 1]);
    let mut dst_ip = [0u8; 16];
    dst_ip[..4].copy_from_slice(&[10, 0, 0, 2]);

    let event = PacketLogEvent {
        timestamp_ns: 123456789,
        src_ip,
        dst_ip,
        rule_id: 7,
        packet_len: 60,
        ..Default::default()
    };

    let json = serde_json::to_string(&event).expect("Serialize to JSON");
    let deserialized: PacketLogEvent = serde_json::from_str(&json).expect("Deserialize from JSON");

    assert_eq!(event.timestamp_ns, deserialized.timestamp_ns);
    assert_eq!(event.rule_id, deserialized.rule_id);
    assert_eq!(event.packet_len, deserialized.packet_len);
}

#[test]
fn test_stats_default_and_calculation() {
    let mut stats = FirewallStats::default();
    assert_eq!(stats.rx_packets, 0);
    assert_eq!(stats.dropped_packets, 0);

    stats.rx_packets += 1000;
    stats.rx_bytes += 1_000_000;
    stats.dropped_packets += 250;
    stats.dropped_bytes += 250_000;
    stats.accepted_packets += 750;
    stats.accepted_bytes += 750_000;
    stats.ringbuf_events += 250;

    assert_eq!(
        stats.rx_packets,
        stats.dropped_packets + stats.accepted_packets
    );
    assert_eq!(stats.rx_bytes, stats.dropped_bytes + stats.accepted_bytes);
}

#[test]
fn test_rule_value_constructors() {
    let drop_rule = RuleValue::drop(42);
    assert_eq!(drop_rule.rule_id, 42);
    assert_eq!(drop_rule.action, ACTION_DROP);

    let accept_rule = RuleValue::accept(84);
    assert_eq!(accept_rule.rule_id, 84);
    assert_eq!(accept_rule.action, ACTION_ACCEPT);
}

#[test]
fn test_rule_loader_from_file() {
    let mut tmp_file = NamedTempFile::new().unwrap();
    writeln!(tmp_file, "# Blocklist sample").unwrap();
    writeln!(tmp_file, "192.168.1.50 # Attacker single IP").unwrap();
    writeln!(tmp_file, "10.0.0.0/8 # Internal subnet block").unwrap();
    writeln!(tmp_file, "2001:db8::1 # IPv6 single IP").unwrap();
    writeln!(tmp_file, "2001:db8:bad::/48 # IPv6 bad range").unwrap();
    writeln!(tmp_file, "   ").unwrap();
    writeln!(tmp_file, "# Invalid line below").unwrap();
    writeln!(tmp_file, "999.999.999.999").unwrap();
    tmp_file.flush().unwrap();

    let rules = RuleLoader::load_file(tmp_file.path()).unwrap();
    assert_eq!(rules.exact_v4.len(), 1);
    assert!(rules.exact_v4.contains_key(&[192, 168, 1, 50]));

    assert_eq!(rules.lpm_v4.len(), 1);
    assert_eq!(rules.lpm_v4[0].0, 8);
    assert_eq!(rules.lpm_v4[0].1, [10, 0, 0, 0]);

    assert_eq!(rules.exact_v6.len(), 1);
    assert_eq!(rules.lpm_v6.len(), 1);
    assert_eq!(rules.lpm_v6[0].0, 48);

    assert_eq!(rules.skipped_rules, 1); // 999.999.999.999 was skipped
}

#[test]
fn test_sample_rule_files_parsing() {
    let paths = [
        Path::new("rules/blocklist.txt"),
        Path::new("rules/blocklist_v6.txt"),
        Path::new("rules/cidr_ranges.txt"),
    ];

    let rules = RuleLoader::load_from_paths(&paths).expect("Failed to load sample rule files");
    assert!(
        rules.exact_v4.len() >= 6,
        "Expected at least 6 exact IPv4 rules"
    );
    assert!(
        rules.lpm_v4.len() >= 4,
        "Expected at least 4 IPv4 LPM rules"
    );
    assert!(
        rules.exact_v6.len() >= 3,
        "Expected at least 3 exact IPv6 rules"
    );
    assert!(
        rules.lpm_v6.len() >= 3,
        "Expected at least 3 IPv6 LPM rules"
    );
}

// =============================================================================
// PROMETHEUS METRICS TESTS
// =============================================================================

#[test]
fn test_prometheus_metrics_registration() {
    let metrics = PrometheusMetrics::new().expect("Failed to initialize PrometheusMetrics");
    let families = metrics.registry.gather();

    let metric_names: Vec<&str> = families.iter().map(|f| f.name()).collect();
    assert!(metric_names.contains(&"firewall_up"));
    assert!(metric_names.contains(&"firewall_build_info"));
    assert!(metric_names.contains(&"firewall_packets_total"));
    assert!(metric_names.contains(&"firewall_packets_blocked_total"));
    assert!(metric_names.contains(&"firewall_packets_accepted_total"));
    assert!(metric_names.contains(&"firewall_bytes_total"));
    assert!(metric_names.contains(&"firewall_rules_active"));
    assert!(metric_names.contains(&"firewall_rules_total"));
    assert!(metric_names.contains(&"firewall_map_entries"));
    assert!(metric_names.contains(&"firewall_ringbuf_events_total"));
    assert!(metric_names.contains(&"firewall_errors_total"));
    assert!(metric_names.contains(&"firewall_rule_sync_duration_seconds"));
}

#[test]
fn test_git_tag_and_commit_fallback_in_build_info() {
    // 1. Priority to tag when tag is present
    assert_eq!(resolve_git_ref(Some("v1.2.3"), Some("c847888")), "v1.2.3");

    // 2. Fallback to commit hash when tag is None
    assert_eq!(resolve_git_ref(None, Some("c847888")), "c847888");

    // 3. Fallback to commit hash when tag is whitespace
    assert_eq!(resolve_git_ref(Some("  "), Some("c847888")), "c847888");

    // 4. Fallback to "unknown" when neither exists
    assert_eq!(resolve_git_ref(None, None), "unknown");

    // 5. Test metrics with Git tag
    let metrics_tag =
        PrometheusMetrics::with_git_ref("v1.2.3").expect("Failed to build with git tag");
    let encoded_tag = metrics_tag.encode().expect("Failed to encode");
    assert!(
        encoded_tag.contains("git_ref=\"v1.2.3\""),
        "Encoded metrics should contain git_ref=\"v1.2.3\""
    );

    // 6. Test metrics with commit fallback
    let metrics_commit =
        PrometheusMetrics::with_git_ref("abcdef0").expect("Failed to build with git commit");
    let encoded_commit = metrics_commit.encode().expect("Failed to encode");
    assert!(
        encoded_commit.contains("git_ref=\"abcdef0\""),
        "Encoded metrics should contain git_ref=\"abcdef0\""
    );
}

#[test]
fn test_map_entries_counting_and_breakdown() {
    let metrics = PrometheusMetrics::new().expect("Failed to initialize PrometheusMetrics");

    // Update with initial counts: 8 exact IPv4, 3 exact IPv6, 5 LPM IPv4, 2 LPM IPv6
    metrics.update_map_entries(8, 3, 5, 2);

    // 1. LPM Trie Total
    assert_eq!(metrics.lpm_trie_entries(), 7);

    // 2. BPF HashMap Total
    assert_eq!(metrics.hashmap_entries(), 11);

    // 3. Total IPv4 (exact + CIDR)
    assert_eq!(metrics.ipv4_entries(), 13);

    // 4. Total IPv6 (exact + CIDR)
    assert_eq!(metrics.ipv6_entries(), 5);

    // 5. Specific individual IPs and CIDR counts
    assert_eq!(metrics.ipv4_ip_entries(), 8);
    assert_eq!(metrics.ipv6_ip_entries(), 3);
    assert_eq!(metrics.ipv4_cidr_entries(), 5);
    assert_eq!(metrics.ipv6_cidr_entries(), 2);

    // 6. Total aggregate rules
    assert_eq!(metrics.rules_total.get(), 18);

    // 7. Test adding a new entry
    metrics.inc_map_entry("hashmap", "ipv4", "ip");
    assert_eq!(metrics.ipv4_ip_entries(), 9);
    assert_eq!(metrics.hashmap_entries(), 12);
    assert_eq!(metrics.rules_total.get(), 19);

    metrics.inc_map_entry("lpm_trie", "ipv6", "cidr");
    assert_eq!(metrics.ipv6_cidr_entries(), 3);
    assert_eq!(metrics.lpm_trie_entries(), 8);
    assert_eq!(metrics.rules_total.get(), 20);

    // 8. Test removing an entry
    metrics.dec_map_entry("hashmap", "ipv4", "ip");
    assert_eq!(metrics.ipv4_ip_entries(), 8);
    assert_eq!(metrics.rules_total.get(), 19);

    metrics.dec_map_entry("lpm_trie", "ipv6", "cidr");
    assert_eq!(metrics.ipv6_cidr_entries(), 2);
    assert_eq!(metrics.rules_total.get(), 18);
}

#[test]
fn test_prometheus_counters_incrementation() {
    let metrics = PrometheusMetrics::new().expect("Failed to initialize PrometheusMetrics");

    // Test blocked packet counters
    metrics.record_blocked_packet("TCP", "Exact HashMap", 128);
    metrics.record_blocked_packet("UDP", "LPM Trie CIDR", 64);
    metrics.record_blocked_packet("TCP", "Exact HashMap", 128);

    assert_eq!(
        metrics
            .packets_blocked_total
            .with_label_values(&["TCP", "Exact HashMap"])
            .get(),
        2
    );
    assert_eq!(
        metrics
            .packets_blocked_total
            .with_label_values(&["UDP", "LPM Trie CIDR"])
            .get(),
        1
    );
    assert_eq!(metrics.packets_total.with_label_values(&["drop"]).get(), 3);
    assert_eq!(metrics.bytes_total.with_label_values(&["drop"]).get(), 320);

    // Test accepted packet counters
    metrics.record_accepted_packet(1024);
    metrics.record_accepted_packet(512);

    assert_eq!(metrics.packets_accepted_total.get(), 2);
    assert_eq!(
        metrics.packets_total.with_label_values(&["accept"]).get(),
        2
    );
    assert_eq!(
        metrics.bytes_total.with_label_values(&["accept"]).get(),
        1536
    );

    // Test ringbuf and error counters
    metrics.record_ringbuf_event();
    metrics.record_ringbuf_event();
    assert_eq!(metrics.ringbuf_events_total.get(), 2);

    metrics.record_error("sync");
    metrics.record_error("sync");
    metrics.record_error("watcher");
    assert_eq!(metrics.errors_total.with_label_values(&["sync"]).get(), 2);
    assert_eq!(
        metrics.errors_total.with_label_values(&["watcher"]).get(),
        1
    );
}

#[test]
fn test_prometheus_gauges_values() {
    let metrics = PrometheusMetrics::new().expect("Failed to initialize PrometheusMetrics");

    // Gauge firewall_up is initially 1
    assert_eq!(metrics.firewall_up.get(), 1);

    // Update rule counts
    metrics.update_rules_count(100, 20, 50, 5);
    assert_eq!(metrics.rules_total.get(), 175);
    assert_eq!(
        metrics.rules_active.with_label_values(&["exact_v4"]).get(),
        100
    );
    assert_eq!(
        metrics.rules_active.with_label_values(&["exact_v6"]).get(),
        20
    );
    assert_eq!(
        metrics.rules_active.with_label_values(&["lpm_v4"]).get(),
        50
    );
    assert_eq!(metrics.rules_active.with_label_values(&["lpm_v6"]).get(), 5);

    // Shutdown state
    metrics.firewall_up.set(0);
    assert_eq!(metrics.firewall_up.get(), 0);
}

#[tokio::test]
async fn test_metrics_endpoint_valid_prometheus_format() {
    let metrics = Arc::new(
        PrometheusMetrics::with_git_ref("v0.1.0-test")
            .expect("Failed to build PrometheusMetrics with git_ref"),
    );
    metrics.update_map_entries(42, 10, 5, 2);
    metrics.record_blocked_packet("TCP", "Exact HashMap", 74);
    metrics.record_accepted_packet(1500);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Bind ephemeral port for testing
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let local_addr = listener.local_addr().expect("Failed to get local addr");
    drop(listener);

    let server = MetricsServer::new(Arc::clone(&metrics), local_addr);
    let handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and make HTTP request
    let mut stream = TcpStream::connect(local_addr)
        .await
        .expect("Failed to connect to metrics server");
    stream
        .write_all(
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Prometheus/2.45\r\n\r\n",
        )
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response = String::from_utf8_lossy(&response_bytes);

    // Verify HTTP response headers
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"));

    // Verify build info with git_ref
    assert!(response.contains("firewall_build_info"));
    assert!(response.contains("git_ref=\"v0.1.0-test\""));

    // Verify map entries metrics
    assert!(response.contains("# HELP firewall_map_entries"));
    assert!(response.contains("# TYPE firewall_map_entries gauge"));
    assert!(response.contains(
        "firewall_map_entries{entry_type=\"ip\",ip_version=\"ipv4\",map=\"hashmap\"} 42"
    ));
    assert!(response.contains(
        "firewall_map_entries{entry_type=\"ip\",ip_version=\"ipv6\",map=\"hashmap\"} 10"
    ));
    assert!(response.contains(
        "firewall_map_entries{entry_type=\"cidr\",ip_version=\"ipv4\",map=\"lpm_trie\"} 5"
    ));
    assert!(response.contains(
        "firewall_map_entries{entry_type=\"cidr\",ip_version=\"ipv6\",map=\"lpm_trie\"} 2"
    ));

    // Verify Prometheus exposition format syntax
    assert!(response.contains("# HELP firewall_up"));
    assert!(response.contains("# TYPE firewall_up gauge"));
    assert!(response.contains("firewall_up 1"));

    assert!(response.contains("# HELP firewall_rules_total"));
    assert!(response.contains("# TYPE firewall_rules_total gauge"));
    assert!(response.contains("firewall_rules_total 59"));

    assert!(response.contains(
        "firewall_packets_blocked_total{match_type=\"Exact HashMap\",protocol=\"TCP\"} 1"
    ));
    assert!(response.contains("firewall_packets_accepted_total 1"));

    let _ = shutdown_tx.send(true);
    let _ = handle.await;
}

#[test]
fn test_metrics_listen_address_env_var_configuration() {
    // 1. Default configuration
    let default_config = Config::parse_from(["firewall"]);
    assert_eq!(default_config.metrics_listen_addr, "0.0.0.0:9100");
    assert!(!default_config.no_metrics);

    // 2. Override via CLI
    let cli_config = Config::parse_from(["firewall", "--metrics-listen-addr", "127.0.0.1:9090"]);
    assert_eq!(cli_config.metrics_listen_addr, "127.0.0.1:9090");

    // 3. Override via Environment Variable
    std::env::set_var("METRICS_LISTEN_ADDRESS", "10.10.10.10:9191");
    let env_config = Config::parse_from(["firewall"]);
    assert_eq!(env_config.metrics_listen_addr, "10.10.10.10:9191");
    std::env::remove_var("METRICS_LISTEN_ADDRESS");

    // 4. CLI takes precedence over Environment Variable
    std::env::set_var("METRICS_LISTEN_ADDRESS", "10.10.10.10:9191");
    let override_config =
        Config::parse_from(["firewall", "--metrics-listen-addr", "192.168.1.1:8080"]);
    assert_eq!(override_config.metrics_listen_addr, "192.168.1.1:8080");
    std::env::remove_var("METRICS_LISTEN_ADDRESS");
}

// ============================================================================
// 🎯 Top 100 Blocked IP Telemetry & Cardinality Management Integration Tests
// ============================================================================

use firewall_lib::top_n::{BlockedIpTopN, BlockedProtocol, RankingCriterion};

#[test]
fn test_top_100_ip_entry_and_protocol_breakdown() {
    let metrics = PrometheusMetrics::new().expect("Failed to build PrometheusMetrics");

    let ip_v4: IpAddr = "198.51.100.22".parse().unwrap();
    let ip_v6: IpAddr = "2001:db8::cafe".parse().unwrap();

    // Send packets across all 5 protocols
    metrics.record_blocked_ip(ip_v4, BlockedProtocol::Tcp, 64);
    metrics.record_blocked_ip(ip_v4, BlockedProtocol::Tcp, 64);
    metrics.record_blocked_ip(ip_v4, BlockedProtocol::Udp, 128);
    metrics.record_blocked_ip(ip_v4, BlockedProtocol::Icmp, 84);
    metrics.record_blocked_ip(ip_v4, BlockedProtocol::Other, 50);

    metrics.record_blocked_ip(ip_v6, BlockedProtocol::Icmpv6, 104);
    metrics.record_blocked_ip(ip_v6, BlockedProtocol::Tcp, 120);

    // Sync and encode metrics
    let encoded = metrics.encode().expect("Failed to encode metrics");

    // Verify presence of Top-N metrics headers
    assert!(encoded.contains("# HELP firewall_blocked_ip_packets"));
    assert!(encoded.contains("# TYPE firewall_blocked_ip_packets counter"));
    assert!(encoded.contains("# HELP firewall_blocked_ip_bytes"));
    assert!(encoded.contains("# TYPE firewall_blocked_ip_bytes counter"));
    assert!(encoded.contains("# HELP firewall_blocked_ip_total_packets"));
    assert!(encoded.contains("# HELP firewall_blocked_ip_total_bytes"));
    assert!(encoded.contains("# HELP firewall_top_blocked_ips_count"));
    assert!(encoded.contains("firewall_top_blocked_ips_count 2"));

    // Verify IPv4 protocol breakdown
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"198.51.100.22\",protocol=\"tcp\"} 2")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_bytes{ip=\"198.51.100.22\",protocol=\"tcp\"} 128")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"198.51.100.22\",protocol=\"udp\"} 1")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_bytes{ip=\"198.51.100.22\",protocol=\"udp\"} 128")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"198.51.100.22\",protocol=\"icmp\"} 1")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_bytes{ip=\"198.51.100.22\",protocol=\"icmp\"} 84")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"198.51.100.22\",protocol=\"icmpv6\"} 0")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"198.51.100.22\",protocol=\"other\"} 1")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_bytes{ip=\"198.51.100.22\",protocol=\"other\"} 50")
    );

    // Verify IPv4 totals
    assert!(encoded.contains("firewall_blocked_ip_total_packets{ip=\"198.51.100.22\"} 5"));
    assert!(encoded.contains("firewall_blocked_ip_total_bytes{ip=\"198.51.100.22\"} 390"));

    // Verify IPv6 protocol breakdown
    assert!(encoded
        .contains("firewall_blocked_ip_packets{ip=\"2001:db8::cafe\",protocol=\"icmpv6\"} 1"));
    assert!(encoded
        .contains("firewall_blocked_ip_bytes{ip=\"2001:db8::cafe\",protocol=\"icmpv6\"} 104"));
    assert!(
        encoded.contains("firewall_blocked_ip_packets{ip=\"2001:db8::cafe\",protocol=\"tcp\"} 1")
    );
    assert!(
        encoded.contains("firewall_blocked_ip_bytes{ip=\"2001:db8::cafe\",protocol=\"tcp\"} 120")
    );
    assert!(encoded.contains("firewall_blocked_ip_total_packets{ip=\"2001:db8::cafe\"} 2"));
    assert!(encoded.contains("firewall_blocked_ip_total_bytes{ip=\"2001:db8::cafe\"} 224"));
}

#[test]
fn test_top_100_eviction_and_zero_stale_series() {
    let metrics = PrometheusMetrics::new().expect("Failed to build PrometheusMetrics");

    // Configure a small capacity Top-2 to test eviction cleanly
    {
        let mut top = metrics.top_blocked_ips.lock().unwrap();
        *top = BlockedIpTopN::new(2, RankingCriterion::Packets);
    }

    let ip_1: IpAddr = "192.0.2.1".parse().unwrap();
    let ip_2: IpAddr = "192.0.2.2".parse().unwrap();
    let ip_3: IpAddr = "192.0.2.3".parse().unwrap();

    // IP 1 gets 2 packets, IP 2 gets 5 packets
    metrics.record_blocked_ip(ip_1, BlockedProtocol::Tcp, 100);
    metrics.record_blocked_ip(ip_1, BlockedProtocol::Tcp, 100);

    for _ in 0..5 {
        metrics.record_blocked_ip(ip_2, BlockedProtocol::Udp, 50);
    }

    let out1 = metrics.encode().expect("Failed encode 1");
    assert!(out1.contains("firewall_top_blocked_ips_count 2"));
    assert!(out1.contains("192.0.2.1"));
    assert!(out1.contains("192.0.2.2"));
    assert!(!out1.contains("192.0.2.3"));

    // Now IP 3 arrives with 10 packets -> should evict IP 1 (which only has 2 packets)
    for _ in 0..10 {
        metrics.record_blocked_ip(ip_3, BlockedProtocol::Icmp, 60);
    }

    let out2 = metrics.encode().expect("Failed encode 2");
    assert!(out2.contains("firewall_top_blocked_ips_count 2"));
    // IP 1 MUST BE GONE FROM ALL METRICS
    assert!(
        !out2.contains("192.0.2.1"),
        "Evicted IP 1 must not appear in metrics output!"
    );
    // IP 2 and IP 3 must be present
    assert!(out2.contains("192.0.2.2"));
    assert!(out2.contains("192.0.2.3"));

    // Verify that NO lingering series for IP 1 remain
    assert!(!out2.contains("firewall_blocked_ip_packets{ip=\"192.0.2.1\""));
    assert!(!out2.contains("firewall_blocked_ip_bytes{ip=\"192.0.2.1\""));
    assert!(!out2.contains("firewall_blocked_ip_total_packets{ip=\"192.0.2.1\"}"));
    assert!(!out2.contains("firewall_blocked_ip_total_bytes{ip=\"192.0.2.1\"}"));
}

#[test]
fn test_top_100_strict_capacity_bound() {
    let metrics = PrometheusMetrics::new().expect("Failed to build PrometheusMetrics");

    // Insert 150 distinct IP addresses into default Top-100 tracker
    for i in 1..=150u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, i / 100, i % 100));
        // IP i gets i packets so ranking is deterministic
        for _ in 0..i {
            metrics.record_blocked_ip(ip, BlockedProtocol::Tcp, 64);
        }
    }

    assert_eq!(metrics.tracked_blocked_ips_count(), 150);

    let encoded = metrics.encode().expect("Failed encode");
    let active_count = metrics.top_blocked_ips_count.get();
    assert_eq!(
        active_count, 100,
        "Top-100 count must never exceed capacity 100"
    );

    let top_ips = metrics.currently_exported_top_ips();
    assert_eq!(top_ips.len(), 100);

    // IPs with packets 1..=50 should have been evicted; IPs 51..=150 must be present
    let evicted_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)).to_string();
    assert!(
        !top_ips.contains(&evicted_ip),
        "Lowest IP must be evicted from Top-100"
    );
    assert!(!encoded.contains(&evicted_ip));

    let top_king_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)).to_string();
    assert!(
        top_ips.contains(&top_king_ip),
        "Highest packet IP must be in Top-100"
    );
    assert!(encoded.contains(&top_king_ip));
}

#[test]
fn test_top_100_ranking_criterion_packets_vs_bytes() {
    let mut top_n = BlockedIpTopN::new(1, RankingCriterion::Packets);

    let ip_packets = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip_bytes = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // ip_packets: 10 packets, 100 bytes
    for _ in 0..10 {
        top_n.record_event(ip_packets, BlockedProtocol::Tcp, 10);
    }

    // ip_bytes: 1 packet, 100,000 bytes
    top_n.record_event(ip_bytes, BlockedProtocol::Udp, 100_000);

    // 1. When ranked by Packets -> ip_packets wins
    top_n.set_criterion(RankingCriterion::Packets);
    let top_by_pkts = top_n.top_n_stats();
    assert_eq!(top_by_pkts.len(), 1);
    assert_eq!(top_by_pkts[0].ip, ip_packets);

    // 2. When ranked by Bytes -> ip_bytes wins
    top_n.set_criterion(RankingCriterion::Bytes);
    let top_by_bytes = top_n.top_n_stats();
    assert_eq!(top_by_bytes.len(), 1);
    assert_eq!(top_by_bytes[0].ip, ip_bytes);
}

#[test]
fn test_top_100_concurrent_updates() {
    use std::sync::Barrier;
    use std::thread;

    let metrics = Arc::new(PrometheusMetrics::new().expect("Failed to build PrometheusMetrics"));
    let num_threads = 8;
    let iterations_per_thread = 500;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = Vec::new();

    for thread_id in 0..num_threads {
        let metrics_clone = Arc::clone(&metrics);
        let barrier_clone = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            for i in 0..iterations_per_thread {
                let ip_last = ((thread_id * 10 + (i % 20)) % 50) as u8 + 1;
                let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, ip_last));
                let proto = match i % 5 {
                    0 => BlockedProtocol::Tcp,
                    1 => BlockedProtocol::Udp,
                    2 => BlockedProtocol::Icmp,
                    3 => BlockedProtocol::Icmpv6,
                    _ => BlockedProtocol::Other,
                };
                metrics_clone.record_blocked_ip(ip, proto, 100);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Ensure metrics can be encoded without deadlock and that all values are coherent
    let encoded = metrics
        .encode()
        .expect("Failed to encode concurrent metrics");
    assert!(encoded.contains("firewall_top_blocked_ips_count"));
    let active_count = metrics.top_blocked_ips_count.get();
    assert!(active_count > 0 && active_count <= 100);
}

#[test]
fn test_update_from_ebpf_stats_accept_and_block_ratio() {
    let metrics = PrometheusMetrics::new().expect("Failed to initialize metrics");

    // Initially 0
    assert_eq!(metrics.packets_accepted_total.get(), 0);
    assert_eq!(
        metrics.packets_total.with_label_values(&["accept"]).get(),
        0
    );
    assert_eq!(metrics.bytes_total.with_label_values(&["accept"]).get(), 0);

    // Record 1 blocked packet of 100 bytes
    metrics.record_blocked_packet("TCP", "Exact HashMap", 100);
    assert_eq!(metrics.packets_total.with_label_values(&["drop"]).get(), 1);
    assert_eq!(metrics.bytes_total.with_label_values(&["drop"]).get(), 100);

    // Synchronize 3 accepted packets from eBPF STATS map (e.g. 300 bytes)
    let mut stats = FirewallStats {
        accepted_packets: 3,
        accepted_bytes: 300,
        ..Default::default()
    };
    metrics.update_from_ebpf_stats(&stats);

    // Verify both single-counter and labeled vectors were synchronized
    assert_eq!(metrics.packets_accepted_total.get(), 3);
    assert_eq!(
        metrics.packets_total.with_label_values(&["accept"]).get(),
        3
    );
    assert_eq!(
        metrics.bytes_total.with_label_values(&["accept"]).get(),
        300
    );

    // Verify Block Ratio formula: 1 blocked / (1 drop + 3 accept = 4 total) = 25%
    let total_blocked = metrics.packets_total.with_label_values(&["drop"]).get();
    let total_accepted = metrics.packets_total.with_label_values(&["accept"]).get();
    let total = total_blocked + total_accepted;
    let ratio = (total_blocked as f64 / total as f64) * 100.0;
    assert_eq!(ratio, 25.0);

    // Synchronize another 2 accepted packets (total 5)
    stats.accepted_packets = 5;
    stats.accepted_bytes = 500;
    metrics.update_from_ebpf_stats(&stats);

    assert_eq!(metrics.packets_accepted_total.get(), 5);
    assert_eq!(
        metrics.packets_total.with_label_values(&["accept"]).get(),
        5
    );
    assert_eq!(
        metrics.bytes_total.with_label_values(&["accept"]).get(),
        500
    );

    // New ratio: 1 / (1 + 5) = 16.666...%
    let total_accepted_new = metrics.packets_total.with_label_values(&["accept"]).get();
    let ratio_new = (total_blocked as f64 / (total_blocked + total_accepted_new) as f64) * 100.0;
    assert!((ratio_new - 16.666666666666668).abs() < 1e-6);
}
