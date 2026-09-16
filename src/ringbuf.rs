use crate::console::*;
use crate::firehol::blocklist::FireholBlockList;
use crate::firehol::metadata::RuleBlockContext;
use crate::loader::StaticRuleRegistry;
use crate::{
    error::{FirewallError, Result},
    metrics::PrometheusMetrics,
    top_n::BlockedProtocol,
};
use aya::{
    maps::{MapData, RingBuf},
    Ebpf,
};
use firewall_common::PacketLogEvent;
use std::{
    borrow::Cow,
    mem,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// High-performance asynchronous consumer of eBPF Ring Buffer events.
pub struct RingBufConsumer {
    async_fd: AsyncFd<RingBuf<MapData>>,
    json_mode: bool,
    log_drops: Arc<AtomicBool>,
    metrics: Option<Arc<PrometheusMetrics>>,
    firehol_blocklist: Option<Arc<FireholBlockList>>,
    static_registry: Option<Arc<StaticRuleRegistry>>,
}

impl RingBufConsumer {
    /// Create a new RingBufConsumer by taking the "EVENTS" map from Ebpf.
    pub fn new(ebpf: &mut Ebpf, json_mode: bool) -> Result<Self> {
        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| FirewallError::Config("Map EVENTS not found".into()))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::new(ring_buf)
            .map_err(|e| FirewallError::RingBuf(format!("Failed to register AsyncFd: {e}")))?;

        Ok(Self {
            async_fd,
            json_mode,
            log_drops: Arc::new(AtomicBool::new(true)),
            metrics: None,
            firehol_blocklist: None,
            static_registry: None,
        })
    }

    /// Attach a Prometheus metrics instance to record telemetry events.
    pub fn with_metrics(mut self, metrics: Arc<PrometheusMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Configure a shared atomic flag to toggle console drop logging.
    pub fn with_log_drops_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.log_drops = flag;
        self
    }

    /// Attach the FireHOL blocklist manager so drop events resolve the *current*
    /// (possibly hot-reloaded) metadata registry instead of a stale startup snapshot.
    pub fn with_firehol_registry(mut self, blocklist: Arc<FireholBlockList>) -> Self {
        self.firehol_blocklist = Some(blocklist);
        self
    }

    /// Attach the static rule metadata registry so a match against a static rule
    /// still prints the correct `file:line` (it lives in the disjoint namespace and
    /// is therefore not present in the FireHOL registry).
    pub fn with_static_registry(mut self, registry: Arc<StaticRuleRegistry>) -> Self {
        self.static_registry = Some(registry);
        self
    }

    /// Asynchronously poll and consume events from the eBPF Ring Buffer
    /// until a cancellation signal is received.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        info!("{}", green_bold("📡 Ring Buffer telemetry consumer started. Waiting for dropped packet events... 🛡️"));

        let expected_size = mem::size_of::<PacketLogEvent>();
        let json_mode = self.json_mode;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("{}", yellow_bold("🛑 Ring Buffer consumer received shutdown signal."));
                    break;
                }
                guard_res = self.async_fd.readable_mut() => {
                    match guard_res {
                        Ok(mut guard) => {
                            let ring_buf = guard.get_inner_mut();
                            let mut count = 0;

                            // Snapshot the current FireHOL registry once per batch. The registry is
                            // swapped atomically on (re)load, so reading it here reflects hot reloads.
                            let registry = self
                                .firehol_blocklist
                                .as_ref()
                                .map(|b| b.registry());

                            // Drain all available events from the ring buffer
                            while let Some(item) = ring_buf.next() {
                                count += 1;
                                if let Some(m) = &self.metrics {
                                    m.record_ringbuf_event();
                                }

                                if item.len() != expected_size {
                                    warn!(
                                        "⚠️ Malformed RingBuf item size: got {} bytes, expected {}",
                                        item.len(),
                                        expected_size
                                    );
                                    if let Some(m) = &self.metrics {
                                        m.record_error("ringbuf_malformed");
                                    }
                                    continue;
                                }

                                // Zero-copy transmutation from raw byte slice to PacketLogEvent
                                let event: &PacketLogEvent = unsafe {
                                    &*(item.as_ptr() as *const PacketLogEvent)
                                };

                                let rule_info = registry
                                    .as_ref()
                                    .and_then(|r| r.resolve_rule(event.rule_id));

                                if let Some(m) = &self.metrics {
                                    let byte_len = event.packet_len as u64;
                                    m.record_blocked_packet(
                                        event.protocol_name(),
                                        event.match_type_name(),
                                        byte_len,
                                    );
                                    m.record_blocked_ip(
                                        event.src_addr(),
                                        BlockedProtocol::from_u8(event.protocol),
                                        byte_len,
                                    );
                                    if let Some(info) = rule_info {
                                        m.firehol.record_drop(
                                            info.category.as_str(),
                                            event.protocol_name(),
                                            event.packet_len,
                                        );
                                    }
                                }

                                if self.log_drops.load(Ordering::Relaxed) {
                                    // Only resolve the (potentially lazily built) block context on
                                    // the logging path, which is not on the hot telemetry path.
                                    // Prefer the FireHOL registry (dense 1..N namespace); fall back
                                    // to the static registry (STATIC_RULE_BASE namespace) so a match
                                    // against a static rule still shows its correct file:line.
                                    let winning = registry
                                        .as_ref()
                                        .and_then(|r| r.resolve_rule_block(event.rule_id))
                                        .or_else(|| {
                                            self.static_registry
                                                .as_ref()
                                                .and_then(|s| s.get(event.rule_id))
                                                .map(|info| Cow::Owned(RuleBlockContext {
                                                    files: vec![info.file],
                                                    lines: vec![info.line],
                                                    categories: Vec::new(),
                                                }))
                                        });

                                    // Enrich the winning rule with every FireHOL file whose target
                                    // also contains the blocked (source) IP, so a static-rule winner
                                    // lists all matching threat feeds in addition to its own file.
                                    let mut block = RuleBlockContext::default();
                                    if let Some(w) = &winning {
                                        Self::merge_into(&mut block, w);
                                    }
                                    if let Some(r) = &registry {
                                        let src = match event.src_addr() {
                                            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                                            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                                        };
                                        for ctx in r.lookup_ip(event.ip_version, &src) {
                                            Self::merge_into(&mut block, ctx.as_ref());
                                        }
                                    }
                                    Self::log_event(json_mode, event, Some(&block));
                                }
                            }

                            guard.clear_ready();
                            if count > 0 {
                                tracing::trace!("⚡ Processed {} events from RingBuf batch", format_int_with_spaces(count as u64));
                            }
                        }
                        Err(e) => {
                            error!("❌ Error waiting for RingBuf readiness: {}", e);
                            if let Some(m) = &self.metrics {
                                m.record_error("ringbuf_poll");
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }

        info!("{}", green_bold("✅ Ring Buffer consumer stopped cleanly."));
        Ok(())
    }

    /// Merge `src` into `dst`, deduplicating by `(file, line)` and by category.
    fn merge_into(dst: &mut RuleBlockContext, src: &RuleBlockContext) {
        for (i, f) in src.files.iter().enumerate() {
            let l = src.lines.get(i).copied().unwrap_or_default();
            let dup = dst
                .files
                .iter()
                .enumerate()
                .any(|(j, x)| x == f && dst.lines.get(j).copied().unwrap_or_default() == l);
            if !dup {
                dst.files.push(Arc::clone(f));
                dst.lines.push(l);
            }
        }
        for c in &src.categories {
            if !dst.categories.contains(c) {
                dst.categories.push(*c);
            }
        }
    }

    /// Format and log a blocked packet event.
    fn log_event(json_mode: bool, event: &PacketLogEvent, block: Option<&RuleBlockContext>) {
        if json_mode {
            let mut json_val = serde_json::json!({
                "timestamp_ns": event.timestamp_ns,
                "action": event.action_name(),
                "ip_version": event.ip_version,
                "src_ip": event.src_addr().to_string(),
                "dst_ip": event.dst_addr().to_string(),
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "protocol": event.protocol_name(),
                "rule_id": event.rule_id,
                "match_type": event.match_type_name(),
                "packet_len": event.packet_len,
                "ifindex": event.ifindex,
            });
            if let Some(block) = block {
                if let Some(obj) = json_val.as_object_mut() {
                    obj.insert(
                        "rule_files".into(),
                        serde_json::json!(block
                            .files
                            .iter()
                            .enumerate()
                            .map(|(i, f)| {
                                let line = block.lines.get(i).copied().unwrap_or_default();
                                if line > 0 {
                                    format!("{}:{}", f, line)
                                } else {
                                    f.as_ref().to_string()
                                }
                            })
                            .collect::<Vec<_>>()),
                    );
                    obj.insert(
                        "categories".into(),
                        serde_json::json!(block
                            .categories
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()),
                    );
                }
            }
            println!("{}", json_val);
        } else {
            warn!("{}", RingBufConsumer::format_human_event(event, block));
        }
    }

    /// Render the human-readable structured log line (no trailing newline).
    fn format_human_event(event: &PacketLogEvent, block: Option<&RuleBlockContext>) -> String {
        let rule_label = match block {
            Some(block) if !block.files.is_empty() => {
                let mut s = String::new();
                for (i, f) in block.files.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(f);
                    let line = block.lines.get(i).copied().unwrap_or_default();
                    if line > 0 {
                        s.push(':');
                        s.push_str(&line.to_string());
                    }
                }
                s
            }
            _ => "-".to_string(),
        };

        let category_label = match block {
            Some(block) if !block.categories.is_empty() => {
                let mut s = String::new();
                for (i, c) in block.categories.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(c.as_str());
                }
                s
            }
            _ => "-".to_string(),
        };

        format!(
            "{} | 🌐 IPv{} {}:{} -> {}:{} | 🔌 Proto: {} | 📋 Rule: {} | 🏷️ Category: {} | 🎯 Match: {}",
            red_bold(format!("🚫 [BLOCKED] {}", event.action_name())),
            bold(event.ip_version),
            bold(event.src_addr()),
            bold(event.src_port),
            bold(event.dst_addr()),
            bold(event.dst_port),
            bold(format!("{:<5}", event.protocol_name())),
            bold(&rule_label),
            bold(&category_label),
            bold(format!("{:<14}", event.match_type_name())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehol::metadata::FireholCategory;
    use firewall_common::PacketLogEvent;

    /// Strip ANSI escape sequences (e.g. [`ESC`]`[1m` produced by `pretty_console`)
    /// from a formatted line so content assertions match the plain-text output.
    fn strip_ansi(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if !n.is_ascii_digit() && n != ';' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[allow(clippy::field_reassign_with_default)]
    fn sample_event() -> PacketLogEvent {
        let mut e = PacketLogEvent::default();
        e.ip_version = 4;
        e.protocol = 17; // UDP
        e.src_port = 56484;
        e.dst_port = 53;
        e.packet_len = 81;
        e.ifindex = 1;
        e.action = 1; // ACTION_DROP
        e.match_type = 2; // LPM Trie
                          // 127.0.0.1
        e.src_ip[0] = 127;
        e.src_ip[3] = 1;
        // 127.0.0.53
        e.dst_ip[0] = 127;
        e.dst_ip[3] = 53;
        e
    }

    #[test]
    fn test_format_human_event_renders_files_and_categories_together() {
        let block = RuleBlockContext {
            files: vec![
                Arc::from("stopforumspam_180d.ipset"),
                Arc::from("blocklist_net_ua.ipset"),
                Arc::from("firehol_abusers_30d.netset"),
            ],
            lines: vec![100, 37, 42],
            categories: vec![
                FireholCategory::Abuse,
                FireholCategory::Unroutable,
                FireholCategory::Attacks,
            ],
        };

        let line = RingBufConsumer::format_human_event(&sample_event(), Some(&block));

        // File names (all of them, comma-separated) with their source line numbers must appear
        // right after the file name in the Rule field.
        assert!(line.contains(
            "stopforumspam_180d.ipset:100, blocklist_net_ua.ipset:37, firehol_abusers_30d.netset:42"
        ));
        // Categories must be present, comma-separated, without duplicates.
        assert!(line.contains("abuse, unroutable, attacks"));
        // Category must appear right after the Rule field.
        let rule_idx = line.find("Rule:").unwrap();
        let cat_idx = line.find("🏷️ Category:").unwrap();
        let match_idx = line.find("Match:").unwrap();
        assert!(rule_idx < cat_idx && cat_idx < match_idx);
        // The internal rule id must not be printed.
        assert!(!line.contains("#"));
    }

    #[test]
    fn test_format_human_event_falls_back_without_context() {
        let line = RingBufConsumer::format_human_event(&sample_event(), None);
        assert!(line.contains("BLOCKED"));
        // No file name and no category value when there is no rule context.
        assert!(!line.contains("stopforumspam_180d.ipset"));
        assert!(!line.contains("🏷️ Category: abuse"));
    }

    #[test]
    fn test_merge_into_deduplication() {
        let mut dst = RuleBlockContext {
            files: vec![Arc::from("f1.ipset")],
            lines: vec![10],
            categories: vec![FireholCategory::Abuse],
        };
        let src = RuleBlockContext {
            files: vec![Arc::from("f1.ipset"), Arc::from("f2.ipset")],
            lines: vec![10, 20],
            categories: vec![FireholCategory::Abuse, FireholCategory::Attacks],
        };
        RingBufConsumer::merge_into(&mut dst, &src);
        assert_eq!(dst.files.len(), 2);
        assert_eq!(dst.lines.len(), 2);
        assert_eq!(dst.categories.len(), 2);
    }

    #[test]
    fn test_log_event_human_and_json() {
        let ev = sample_event();
        let block = RuleBlockContext {
            files: vec![Arc::from("f1.ipset"), Arc::from("f2.ipset")],
            lines: vec![10, 0],
            categories: vec![FireholCategory::Malware],
        };

        // Exercise human mode
        RingBufConsumer::log_event(false, &ev, None);
        RingBufConsumer::log_event(false, &ev, Some(&block));

        // Exercise JSON mode
        RingBufConsumer::log_event(true, &ev, None);
        RingBufConsumer::log_event(true, &ev, Some(&block));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_format_human_event_ipv6_and_unknown_proto() {
        let mut e6 = PacketLogEvent::default();
        e6.ip_version = 6;
        e6.protocol = 99; // unknown proto
        e6.src_port = 443;
        e6.dst_port = 54321;
        e6.packet_len = 120;
        e6.action = 1;
        e6.match_type = 1; // HashMap
        e6.src_ip[0] = 0x20;
        e6.src_ip[1] = 0x01;
        e6.src_ip[2] = 0x0d;
        e6.src_ip[3] = 0xb8;
        e6.src_ip[15] = 0x01;
        e6.dst_ip[0] = 0x20;
        e6.dst_ip[1] = 0x01;
        e6.dst_ip[2] = 0x0d;
        e6.dst_ip[3] = 0xb8;
        e6.dst_ip[15] = 0x02;

        let line = strip_ansi(&RingBufConsumer::format_human_event(&e6, None));
        assert!(line.contains("IPv6"));
        assert!(line.contains("2001:db8::1"));
        assert!(line.contains("2001:db8::2"));
        assert!(line.contains("UNKNOWN"));
    }

    #[test]
    fn test_format_human_event_empty_block_and_no_lines() {
        let empty_block = RuleBlockContext {
            files: vec![],
            lines: vec![],
            categories: vec![],
        };
        let line = strip_ansi(&RingBufConsumer::format_human_event(&sample_event(), Some(&empty_block)));
        assert!(line.contains("Rule: -"));
        assert!(line.contains("Category: -"));

        let no_lines_block = RuleBlockContext {
            files: vec![Arc::from("test.ipset")],
            lines: vec![0],
            categories: vec![],
        };
        let line2 = strip_ansi(&RingBufConsumer::format_human_event(&sample_event(), Some(&no_lines_block)));
        assert!(line2.contains("Rule: test.ipset |"));
        assert!(!line2.contains("test.ipset:"));
    }
}
