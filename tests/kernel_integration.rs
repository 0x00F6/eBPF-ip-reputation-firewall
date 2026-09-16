//! Real kernel maps, XDP test-run and telemetry. No host interface is used.
//! Run the ignored tests using scripts/run_kernel_test.sh (network-isolated Docker).
mod support;
use firewall_common::{PacketLogEvent, RuleValue, MATCH_EXACT_HASH, MATCH_LPM_TRIE};
use firewall_lib::{
    config::XdpModeChoice,
    firehol::{FireholBlockList, FireholConfig},
    loader::{ParsedRuleSet, RuleLoader, StaticRuleRegistry, STATIC_RULE_BASE},
    maps::MapManager,
    metrics::PrometheusMetrics,
    ringbuf::RingBufConsumer,
    stats::StatsReporter,
    xdp::XdpFirewall,
};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use support::*;
use tokio::sync::{watch, Mutex};

#[test]
#[ignore = "isolated Linux BPF integration"]
fn differential_sync_preserves_other_rule_namespace_for_all_four_maps() {
    let mut bpf = load(16);
    let mut maps = MapManager::new(&mut bpf).unwrap();
    assert_eq!(counts(&maps), [0; 4]);
    let static_rules = rules(1, STATIC_RULE_BASE);
    let feeds = rules(2, 1);
    let report = maps.sync_rules(&static_rules).unwrap();
    assert_eq!(
        [
            report.ipv4_exact_inserted,
            report.ipv6_exact_inserted,
            report.ipv4_lpm_inserted,
            report.ipv6_lpm_inserted
        ],
        [1; 4]
    );
    assert_eq!(maps.sync_firehol_rules(&feeds).unwrap().entries_removed, 0);
    assert_eq!(counts(&maps), [2; 4]);
    assert_eq!(maps.sync_rules(&static_rules).unwrap().entries_removed, 0);
    assert_eq!(
        maps.sync_firehol_rules(&rules(3, 5))
            .unwrap()
            .entries_removed,
        4
    );
    assert_eq!(counts(&maps), [2; 4]);
    assert_eq!(run_packet(&bpf, &packet_v4([192, 0, 2, 1], 6, 1234, 80)), 1);
    assert_eq!(run_packet(&bpf, &packet_v4([192, 0, 2, 2], 6, 1234, 80)), 2);
    assert_eq!(run_packet(&bpf, &packet_v6(v6(3), 17)), 1);
    assert_eq!(
        maps.sync_rules(&ParsedRuleSet::new())
            .unwrap()
            .entries_removed,
        4
    );
    assert_eq!(counts(&maps), [1; 4]);
    assert_eq!(
        maps.sync_firehol_rules(&ParsedRuleSet::new())
            .unwrap()
            .entries_removed,
        4
    );
    assert_eq!(counts(&maps), [0; 4]);
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn capacity_exhaustion_reports_only_successful_insertions() {
    for firehol in [false, true] {
        let mut bpf = load(1);
        let mut maps = MapManager::new(&mut bpf).unwrap();
        let mut input = rules(1, 1);
        input.merge(rules(2, 5));
        input.merge(rules(3, 9));
        let report = if firehol {
            maps.sync_firehol_rules(&input)
        } else {
            maps.sync_rules(&input)
        }
        .unwrap();
        assert_eq!(
            [
                report.ipv4_exact_inserted,
                report.ipv6_exact_inserted,
                report.ipv4_lpm_inserted,
                report.ipv6_lpm_inserted
            ],
            [1; 4]
        );
        assert_eq!(counts(&maps), [1; 4]);
        let removed = if firehol {
            maps.sync_firehol_rules(&ParsedRuleSet::new())
        } else {
            maps.sync_rules(&ParsedRuleSet::new())
        }
        .unwrap();
        assert_eq!(removed.entries_removed, 4);
        assert_eq!(counts(&maps), [0; 4]);
    }
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn exact_precedence_lpm_fallback_and_telemetry_wire_layout() {
    let mut bpf = load(16);
    let mut events = aya::maps::RingBuf::try_from(bpf.take_map("EVENTS").unwrap()).unwrap();
    let mut maps = MapManager::new(&mut bpf).unwrap();
    maps.insert_lpm_v4(24, [192, 0, 2, 0], RuleValue::drop(10))
        .unwrap();
    maps.insert_exact_v4([192, 0, 2, 1], RuleValue::accept(11))
        .unwrap();
    let packet = packet_v4([192, 0, 2, 1], 6, 12345, 80);
    assert_eq!(
        run_packet(&bpf, &packet),
        2,
        "exact accept overrides subnet drop"
    );
    assert!(events.next().is_none());
    maps.insert_exact_v4([192, 0, 2, 1], RuleValue::drop(12))
        .unwrap();
    assert_eq!(run_packet(&bpf, &packet), 1);
    {
        let bytes = events.next().unwrap();
        assert_eq!(bytes.len(), 64);
        let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketLogEvent>()) };
        assert_eq!(event.rule_id, 12);
        assert_eq!(event.match_type, MATCH_EXACT_HASH);
        assert_eq!(event.packet_len, packet.len() as u32);
        assert_eq!((event.src_port, event.dst_port), (12345, 80));
        assert_eq!(event.src_addr().to_string(), "192.0.2.1");
    }
    maps.remove_exact_v4(&[192, 0, 2, 1]).unwrap();
    assert_eq!(run_packet(&bpf, &packet), 1);
    {
        let bytes = events.next().unwrap();
        let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketLogEvent>()) };
        assert_eq!((event.rule_id, event.match_type), (10, MATCH_LPM_TRIE));
    }
    maps.remove_lpm_v4(24, [192, 0, 2, 0]).unwrap();
    assert_eq!(run_packet(&bpf, &packet), 2);
    assert!(maps.remove_exact_v4(&[192, 0, 2, 1]).is_err());
    assert!(maps.remove_lpm_v4(24, [192, 0, 2, 0]).is_err());

    let source = v6(1);
    maps.insert_lpm_v6(64, source, RuleValue::drop(20)).unwrap();
    maps.insert_exact_v6(source, RuleValue::accept(21)).unwrap();
    let packet6 = packet_v6(source, 17);
    assert_eq!(run_packet(&bpf, &packet6), 2);
    maps.remove_exact_v6(&source).unwrap();
    assert_eq!(run_packet(&bpf, &packet6), 1);
    {
        let bytes = events.next().unwrap();
        let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketLogEvent>()) };
        assert_eq!(event.ip_version, 6);
        assert_eq!(event.src_ip, source);
        assert_eq!((event.rule_id, event.match_type), (20, MATCH_LPM_TRIE));
    }
    maps.remove_lpm_v6(64, source).unwrap();
    assert_eq!(run_packet(&bpf, &packet6), 2);
    assert!(maps.remove_exact_v6(&source).is_err());
    assert!(maps.remove_lpm_v6(64, source).is_err());
    let stats = maps.get_stats().unwrap();
    assert_eq!(
        (
            stats.rx_packets,
            stats.dropped_packets,
            stats.accepted_packets,
            stats.ringbuf_events
        ),
        (7, 3, 4, 3)
    );
    maps.reset_stats().unwrap();
    assert_eq!(maps.get_stats().unwrap().rx_packets, 0);
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn infrastructure_bypass_and_truncated_packets_are_fail_open() {
    let mut bpf = load(16);
    let mut maps = MapManager::new(&mut bpf).unwrap();
    maps.insert_lpm_v4(0, [0; 4], RuleValue::drop(1)).unwrap();
    for protocol in [6, 17] {
        assert_eq!(
            run_packet(&bpf, &packet_v4([192, 0, 2, 1], protocol, 53, 1234)),
            2
        );
        assert_eq!(
            run_packet(&bpf, &packet_v4([192, 0, 2, 1], protocol, 1234, 80)),
            1
        );
    }
    for src in [
        [140, 82, 112, 0],
        [140, 82, 127, 255],
        [192, 30, 252, 1],
        [185, 199, 108, 1],
        [143, 55, 64, 1],
        [20, 201, 28, 151],
        [20, 205, 243, 166],
        [4, 237, 23, 1],
    ] {
        assert_eq!(run_packet(&bpf, &packet_v4(src, 6, 443, 1234)), 2);
        assert_eq!(run_packet(&bpf, &packet_v4(src, 6, 80, 1234)), 1);
    }
    let mut packet = packet_v4([192, 0, 2, 1], 6, 1234, 80);
    packet[14] = 0x44;
    assert_eq!(run_packet(&bpf, &packet), 2);
    packet[14] = 0x4f;
    assert_eq!(run_packet(&bpf, &packet[..40]), 2);
    packet[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    assert_eq!(run_packet(&bpf, &packet[..16]), 2);
    packet[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert_eq!(run_packet(&bpf, &packet), 2);
}

#[tokio::test]
#[ignore = "isolated Linux BPF integration"]
async fn real_ring_buffer_updates_metrics_and_stops_cleanly() {
    for (json, log_drops) in [(false, true), (true, true), (false, false)] {
        let mut bpf = load(16);
        let metrics = Arc::new(PrometheusMetrics::new().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("static.rules");
        std::fs::write(&file, "192.0.2.1\n2001:db8:1::1\n").unwrap();
        let (rules, meta) = RuleLoader::load_from_paths_with_meta(&[file]).unwrap();
        let registry = Arc::new(StaticRuleRegistry::new());
        registry.set(meta);
        let consumer = RingBufConsumer::new(&mut bpf, json)
            .unwrap()
            .with_metrics(metrics.clone())
            .with_static_registry(registry)
            .with_firehol_registry(Arc::new(FireholBlockList::new(
                FireholConfig::default(),
                None,
            )))
            .with_log_drops_flag(Arc::new(AtomicBool::new(log_drops)));
        let mut maps = MapManager::new(&mut bpf).unwrap();
        maps.sync_rules(&rules).unwrap();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(consumer.run(rx));
        for packet in [packet_v4([192, 0, 2, 1], 6, 1234, 80), packet_v6(v6(1), 17)] {
            assert_eq!(run_packet(&bpf, &packet), 1);
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while metrics.ringbuf_events_total.get() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("consumer drained both events");
        assert_eq!(metrics.packets_total.with_label_values(&["drop"]).get(), 2);
        assert_eq!(metrics.tracked_blocked_ips_count(), 2);
        assert_eq!(
            metrics
                .firehol
                .blocked_packets_total
                .with_label_values(&["malware", "TCP"])
                .get(),
            0,
            "static IDs must not be attributed to FireHOL"
        );
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated Linux BPF integration"]
async fn stats_reporter_publishes_kernel_counters_and_handles_shutdown() {
    for interval in [0, 1] {
        let mut bpf = load(8);
        let mut maps = MapManager::new(&mut bpf).unwrap();
        maps.insert_exact_v4([192, 0, 2, 1], RuleValue::drop(1))
            .unwrap();
        run_packet(&bpf, &packet_v4([192, 0, 2, 2], 6, 1234, 80));
        let metrics = Arc::new(PrometheusMetrics::new().unwrap());
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(
            StatsReporter::new(Arc::new(Mutex::new(maps)), interval)
                .with_metrics(metrics.clone())
                .run(rx),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if metrics.packets_accepted_total.get() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        // Allow one paced reporting tick, including the zero-traffic delta path.
        if interval > 0 {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn xdp_attachment_modes_and_missing_maps_return_errors() {
    let path = bpf_path();
    for mode in [
        XdpModeChoice::Driver,
        XdpModeChoice::Hardware,
        XdpModeChoice::Generic,
        XdpModeChoice::Auto,
    ] {
        let mut fw = XdpFirewall::load(Some(&path)).unwrap();
        assert!(fw.attach("missing-test", mode).is_err());
        assert_eq!(fw.iface(), "");
    }
    for mode in [XdpModeChoice::Generic, XdpModeChoice::Auto] {
        let fw = XdpFirewall::load_and_attach("lo", mode, Some(&path)).unwrap();
        assert_eq!(fw.iface(), "lo");
        drop(fw); // Detaches the link before the next case.
    }
    for name in [
        "IPV4_EXACT_MAP",
        "IPV6_EXACT_MAP",
        "IPV4_LPM_MAP",
        "IPV6_LPM_MAP",
        "STATS",
    ] {
        let mut bpf = load(1);
        bpf.take_map(name).unwrap();
        let err = MapManager::new(&mut bpf)
            .err()
            .expect("missing map rejected");
        assert!(err.to_string().contains(name));
    }
}
