// ==============================================================================
// 🛡️ High-Performance Top-N Blocked IP Statistics & Cardinality Management
// ==============================================================================
// Tracks blocked IP activity in user space with bounded cardinality, protocol
// distribution (TCP, UDP, ICMP, ICMPv6, other), and dynamic eviction of stale
// series from Prometheus to prevent metric cardinality explosion.
// ==============================================================================

use prometheus::{IntCounterVec, IntGauge};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

/// Canonical network protocols tracked for blocked IP traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockedProtocol {
    /// Transmission Control Protocol (IPPROTO_TCP = 6)
    Tcp,
    /// User Datagram Protocol (IPPROTO_UDP = 17)
    Udp,
    /// Internet Control Message Protocol v4 (IPPROTO_ICMP = 1)
    Icmp,
    /// Internet Control Message Protocol v6 (IPPROTO_ICMPV6 = 58)
    Icmpv6,
    /// Any other L4 protocol (e.g. GRE, ESP, SCTP, IGMP)
    Other,
}

impl BlockedProtocol {
    /// Return the canonical lowercase string identifier used in Prometheus labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Other => "other",
        }
    }

    /// Map raw IP protocol number to canonical `BlockedProtocol`.
    pub const fn from_u8(proto: u8) -> Self {
        match proto {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            58 => Self::Icmpv6,
            _ => Self::Other,
        }
    }

    /// Map protocol string to `BlockedProtocol` with case-insensitive matching.
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "icmpv6" | "icmp6" => Self::Icmpv6,
            _ => Self::Other,
        }
    }

    /// All five canonical protocols tracked by the firewall.
    pub const ALL: [Self; 5] = [Self::Tcp, Self::Udp, Self::Icmp, Self::Icmpv6, Self::Other];
}

/// Statistics aggregated for a single blocked IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedIpStats {
    /// IP address (IPv4 or IPv6)
    pub ip: IpAddr,
    /// Total blocked packets
    pub total_packets: u64,
    /// Total blocked bytes
    pub total_bytes: u64,
    /// Blocked TCP packets
    pub tcp_packets: u64,
    /// Blocked UDP packets
    pub udp_packets: u64,
    /// Blocked ICMP packets
    pub icmp_packets: u64,
    /// Blocked ICMPv6 packets
    pub icmpv6_packets: u64,
    /// Blocked packets for other protocols
    pub other_packets: u64,
    /// Blocked TCP bytes
    pub tcp_bytes: u64,
    /// Blocked UDP bytes
    pub udp_bytes: u64,
    /// Blocked ICMP bytes
    pub icmp_bytes: u64,
    /// Blocked ICMPv6 bytes
    pub icmpv6_bytes: u64,
    /// Blocked bytes for other protocols
    pub other_bytes: u64,
}

impl BlockedIpStats {
    /// Create fresh stats for a newly encountered IP address.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            total_packets: 0,
            total_bytes: 0,
            tcp_packets: 0,
            udp_packets: 0,
            icmp_packets: 0,
            icmpv6_packets: 0,
            other_packets: 0,
            tcp_bytes: 0,
            udp_bytes: 0,
            icmp_bytes: 0,
            icmpv6_bytes: 0,
            other_bytes: 0,
        }
    }

    /// Record an incoming blocked packet and update protocol-specific counters.
    pub fn record_packet(&mut self, protocol: BlockedProtocol, bytes: u64) {
        self.total_packets += 1;
        self.total_bytes += bytes;
        match protocol {
            BlockedProtocol::Tcp => {
                self.tcp_packets += 1;
                self.tcp_bytes += bytes;
            }
            BlockedProtocol::Udp => {
                self.udp_packets += 1;
                self.udp_bytes += bytes;
            }
            BlockedProtocol::Icmp => {
                self.icmp_packets += 1;
                self.icmp_bytes += bytes;
            }
            BlockedProtocol::Icmpv6 => {
                self.icmpv6_packets += 1;
                self.icmpv6_bytes += bytes;
            }
            BlockedProtocol::Other => {
                self.other_packets += 1;
                self.other_bytes += bytes;
            }
        }
    }

    /// Retrieve packet count for a specific protocol.
    pub const fn packets_for_protocol(&self, protocol: BlockedProtocol) -> u64 {
        match protocol {
            BlockedProtocol::Tcp => self.tcp_packets,
            BlockedProtocol::Udp => self.udp_packets,
            BlockedProtocol::Icmp => self.icmp_packets,
            BlockedProtocol::Icmpv6 => self.icmpv6_packets,
            BlockedProtocol::Other => self.other_packets,
        }
    }

    /// Retrieve byte count for a specific protocol.
    pub const fn bytes_for_protocol(&self, protocol: BlockedProtocol) -> u64 {
        match protocol {
            BlockedProtocol::Tcp => self.tcp_bytes,
            BlockedProtocol::Udp => self.udp_bytes,
            BlockedProtocol::Icmp => self.icmp_bytes,
            BlockedProtocol::Icmpv6 => self.icmpv6_bytes,
            BlockedProtocol::Other => self.other_bytes,
        }
    }
}

/// Ranking criterion used to determine which blocked IPs belong in the Top-N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RankingCriterion {
    /// Rank primarily by total blocked packets descending (default)
    #[default]
    Packets,
    /// Rank primarily by total blocked bytes descending
    Bytes,
}

/// Top-N blocked IP manager with bounded Prometheus label cardinality.
///
/// Keeps track of blocked IP traffic in memory and dynamically adds / removes
/// time-series from Prometheus so that only the top N active IPs are exposed.
#[derive(Debug, Clone)]
pub struct BlockedIpTopN {
    /// Maximum number of IPs to expose in Prometheus (e.g. 100)
    capacity: usize,
    /// Sorting criterion (Packets or Bytes)
    criterion: RankingCriterion,
    /// In-memory statistics per IP address
    stats: HashMap<IpAddr, BlockedIpStats>,
    /// Set of IP strings currently exposed in Prometheus series
    currently_exported: HashSet<String>,
    /// Last exported packet counts per (IP string, protocol) to calculate deltas
    last_exported_packets: HashMap<(String, &'static str), u64>,
    /// Last exported byte counts per (IP string, protocol) to calculate deltas
    last_exported_bytes: HashMap<(String, &'static str), u64>,
    /// Last exported total packets per IP
    last_exported_total_packets: HashMap<String, u64>,
    /// Last exported total bytes per IP
    last_exported_total_bytes: HashMap<String, u64>,
    /// Hard cap on tracked IPs in memory to protect against memory exhaustion
    max_tracked_ips: usize,
}

impl Default for BlockedIpTopN {
    fn default() -> Self {
        Self::new(100, RankingCriterion::Packets)
    }
}

impl BlockedIpTopN {
    /// Create a new Top-N manager with the specified capacity and ranking criterion.
    pub fn new(capacity: usize, criterion: RankingCriterion) -> Self {
        Self {
            capacity,
            criterion,
            stats: HashMap::new(),
            currently_exported: HashSet::new(),
            last_exported_packets: HashMap::new(),
            last_exported_bytes: HashMap::new(),
            last_exported_total_packets: HashMap::new(),
            last_exported_total_bytes: HashMap::new(),
            max_tracked_ips: 10_000,
        }
    }

    /// Record a blocked packet event in user-space statistics.
    ///
    /// This is optimized for low overhead in the Ring Buffer consumption path.
    pub fn record_event(&mut self, ip: IpAddr, protocol: BlockedProtocol, bytes: u64) {
        self.stats
            .entry(ip)
            .or_insert_with(|| BlockedIpStats::new(ip))
            .record_packet(protocol, bytes);

        // Periodically prune stale entries if memory limit reached
        if self.stats.len() > self.max_tracked_ips {
            self.prune_low_volume_entries();
        }
    }

    /// Get current statistics for a given IP address, if tracked.
    pub fn get_stats(&self, ip: &IpAddr) -> Option<&BlockedIpStats> {
        self.stats.get(ip)
    }

    /// Retrieve the current Top-N IP statistics sorted by the active ranking criterion.
    pub fn top_n_stats(&self) -> Vec<BlockedIpStats> {
        let mut entries: Vec<BlockedIpStats> = self.stats.values().cloned().collect();
        self.sort_entries(&mut entries);
        entries.truncate(self.capacity);
        entries
    }

    /// Update the ranking criterion (e.g. switch between Packets and Bytes).
    pub fn set_criterion(&mut self, criterion: RankingCriterion) {
        self.criterion = criterion;
    }

    /// Return the active ranking criterion.
    pub const fn criterion(&self) -> RankingCriterion {
        self.criterion
    }

    /// Return the configured capacity (maximum number of Top IPs).
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return the count of currently tracked unique blocked IPs.
    pub fn tracked_count(&self) -> usize {
        self.stats.len()
    }

    /// Return the set of IP strings currently exposed in Prometheus series.
    pub const fn currently_exported_ips(&self) -> &HashSet<String> {
        &self.currently_exported
    }

    /// Synchronize the Top-N blocked IPs with the Prometheus MetricVecs.
    ///
    /// - Adds / increments series for IPs newly entering or continuing in the Top-N.
    /// - Removes all series for IPs that dropped out of the Top-N.
    /// - Updates the gauge tracking active Top-N count.
    pub fn sync_to_metrics(
        &mut self,
        packets_vec: &IntCounterVec,
        bytes_vec: &IntCounterVec,
        total_packets_vec: &IntCounterVec,
        total_bytes_vec: &IntCounterVec,
        count_gauge: &IntGauge,
    ) {
        // 1. Identify the Top-N stats based on the ranking criterion
        let top_stats = self.top_n_stats();
        let new_top_ips: HashSet<String> = top_stats.iter().map(|s| s.ip.to_string()).collect();

        // 2. Eviction: Remove all series for IPs no longer in the Top-N
        let evicted_ips: Vec<String> = self
            .currently_exported
            .difference(&new_top_ips)
            .cloned()
            .collect();

        for old_ip in &evicted_ips {
            for protocol in BlockedProtocol::ALL {
                let proto_str = protocol.as_str();
                let _ = packets_vec.remove_label_values(&[old_ip, proto_str]);
                let _ = bytes_vec.remove_label_values(&[old_ip, proto_str]);
                self.last_exported_packets
                    .remove(&(old_ip.clone(), proto_str));
                self.last_exported_bytes
                    .remove(&(old_ip.clone(), proto_str));
            }
            let _ = total_packets_vec.remove_label_values(&[old_ip]);
            let _ = total_bytes_vec.remove_label_values(&[old_ip]);
            self.last_exported_total_packets.remove(old_ip);
            self.last_exported_total_bytes.remove(old_ip);
        }

        // 3. Inclusion & Delta Updates: Export metrics for all current Top-N IPs
        for stat in &top_stats {
            let ip_str = stat.ip.to_string();

            // 3.1 Per-protocol packet and byte counters
            for protocol in BlockedProtocol::ALL {
                let proto_str = protocol.as_str();
                let cur_pkts = stat.packets_for_protocol(protocol);
                let cur_bytes = stat.bytes_for_protocol(protocol);

                // Update packets counter
                let last_pkts = self
                    .last_exported_packets
                    .entry((ip_str.clone(), proto_str))
                    .or_insert(0);
                if cur_pkts > *last_pkts {
                    let delta = cur_pkts - *last_pkts;
                    packets_vec
                        .with_label_values(&[&ip_str, proto_str])
                        .inc_by(delta);
                    *last_pkts = cur_pkts;
                } else if *last_pkts == 0 && cur_pkts == 0 {
                    // Pre-initialize series so that 0 is explicitly represented
                    packets_vec.with_label_values(&[&ip_str, proto_str]);
                }

                // Update bytes counter
                let last_bytes = self
                    .last_exported_bytes
                    .entry((ip_str.clone(), proto_str))
                    .or_insert(0);
                if cur_bytes > *last_bytes {
                    let delta = cur_bytes - *last_bytes;
                    bytes_vec
                        .with_label_values(&[&ip_str, proto_str])
                        .inc_by(delta);
                    *last_bytes = cur_bytes;
                } else if *last_bytes == 0 && cur_bytes == 0 {
                    // Pre-initialize series
                    bytes_vec.with_label_values(&[&ip_str, proto_str]);
                }
            }

            // 3.2 Total packets per IP
            let last_tot_pkts = self
                .last_exported_total_packets
                .entry(ip_str.clone())
                .or_insert(0);
            if stat.total_packets > *last_tot_pkts {
                let delta = stat.total_packets - *last_tot_pkts;
                total_packets_vec
                    .with_label_values(&[&ip_str])
                    .inc_by(delta);
                *last_tot_pkts = stat.total_packets;
            } else if *last_tot_pkts == 0 && stat.total_packets == 0 {
                total_packets_vec.with_label_values(&[&ip_str]);
            }

            // 3.3 Total bytes per IP
            let last_tot_bytes = self
                .last_exported_total_bytes
                .entry(ip_str.clone())
                .or_insert(0);
            if stat.total_bytes > *last_tot_bytes {
                let delta = stat.total_bytes - *last_tot_bytes;
                total_bytes_vec.with_label_values(&[&ip_str]).inc_by(delta);
                *last_tot_bytes = stat.total_bytes;
            } else if *last_tot_bytes == 0 && stat.total_bytes == 0 {
                total_bytes_vec.with_label_values(&[&ip_str]);
            }
        }

        // 4. Update the exported set and the Top-N count gauge
        count_gauge.set(new_top_ips.len() as i64);
        self.currently_exported = new_top_ips;
    }

    /// Sort stats according to the configured ranking criterion with deterministic tie-breaking.
    fn sort_entries(&self, entries: &mut [BlockedIpStats]) {
        match self.criterion {
            RankingCriterion::Packets => {
                entries.sort_by(|a, b| {
                    b.total_packets
                        .cmp(&a.total_packets)
                        .then_with(|| b.total_bytes.cmp(&a.total_bytes))
                        .then_with(|| a.ip.cmp(&b.ip))
                });
            }
            RankingCriterion::Bytes => {
                entries.sort_by(|a, b| {
                    b.total_bytes
                        .cmp(&a.total_bytes)
                        .then_with(|| b.total_packets.cmp(&a.total_packets))
                        .then_with(|| a.ip.cmp(&b.ip))
                });
            }
        }
    }

    /// Prune lower-volume entries if in-memory table exceeds safety threshold.
    fn prune_low_volume_entries(&mut self) {
        let keep_count = self.max_tracked_ips / 2;
        let mut entries: Vec<BlockedIpStats> = self.stats.values().cloned().collect();
        self.sort_entries(&mut entries);
        entries.truncate(keep_count);

        let retain_set: HashSet<IpAddr> = entries.into_iter().map(|s| s.ip).collect();
        self.stats.retain(|ip, _| retain_set.contains(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{opts, Registry};
    use std::net::Ipv4Addr;

    fn make_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn test_blocked_protocol_from_u8_and_from_str() {
        assert_eq!(BlockedProtocol::from_u8(6), BlockedProtocol::Tcp);
        assert_eq!(BlockedProtocol::from_u8(17), BlockedProtocol::Udp);
        assert_eq!(BlockedProtocol::from_u8(1), BlockedProtocol::Icmp);
        assert_eq!(BlockedProtocol::from_u8(58), BlockedProtocol::Icmpv6);
        assert_eq!(BlockedProtocol::from_u8(47), BlockedProtocol::Other);
        assert_eq!(BlockedProtocol::from_u8(0xff), BlockedProtocol::Other);

        assert_eq!(BlockedProtocol::from_str_loose("tcp"), BlockedProtocol::Tcp);
        assert_eq!(BlockedProtocol::from_str_loose("UDP"), BlockedProtocol::Udp);
        assert_eq!(BlockedProtocol::from_str_loose("IcMp"), BlockedProtocol::Icmp);
        assert_eq!(
            BlockedProtocol::from_str_loose("icmpv6"),
            BlockedProtocol::Icmpv6
        );
        assert_eq!(
            BlockedProtocol::from_str_loose("icmp6"),
            BlockedProtocol::Icmpv6
        );
        assert_eq!(BlockedProtocol::from_str_loose("gre"), BlockedProtocol::Other);
        assert_eq!(BlockedProtocol::from_str_loose(""), BlockedProtocol::Other);
    }

    #[test]
    fn test_blocked_protocol_as_str_and_default_topn() {
        let mut labels = Vec::new();
        for p in BlockedProtocol::ALL {
            labels.push(p.as_str());
            // Every canonical protocol's string round-trips into itself.
            assert_eq!(BlockedProtocol::from_str_loose(p.as_str()), p);
        }
        // Only IANA protocol numbers 1, 6, 17 and 58 map to a blockable protocol;
        // every other protocol number must fall through to `Other`.
        for raw in [0u8, 2, 3, 4, 5, 7, 47, 100, 255] {
            assert_eq!(BlockedProtocol::from_u8(raw), BlockedProtocol::Other);
        }
        assert_eq!(
            labels,
            vec!["tcp", "udp", "icmp", "icmpv6", "other"]
        );

        // Default constructs with capacity 100 and Packets criterion.
        let default = BlockedIpTopN::default();
        assert_eq!(default.capacity(), 100);
        assert_eq!(default.criterion(), RankingCriterion::Packets);
        assert_eq!(default.tracked_count(), 0);
    }

    #[test]
    fn ranking_switches_criterion_with_deterministic_ties() {
        let mut tracker = BlockedIpTopN::new(4, RankingCriterion::Packets);
        for (ip, sizes) in [
            (4, vec![10, 10]),
            (3, vec![20]),
            (2, vec![20]),
            (1, vec![100]),
        ] {
            for size in sizes {
                tracker.record_event(make_ip(ip), BlockedProtocol::Tcp, size);
            }
        }
        let ranked = |tracker: &BlockedIpTopN| {
            tracker
                .top_n_stats()
                .iter()
                .map(|s| s.ip)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ranked(&tracker),
            [make_ip(4), make_ip(1), make_ip(2), make_ip(3)]
        );
        tracker.set_criterion(RankingCriterion::Bytes);
        assert_eq!(tracker.criterion(), RankingCriterion::Bytes);
        assert_eq!(
            ranked(&tracker),
            [make_ip(1), make_ip(4), make_ip(2), make_ip(3)]
        );
        assert_eq!(tracker.get_stats(&make_ip(4)).unwrap().total_packets, 2);
    }

    #[test]
    fn cardinality_pruning_keeps_highest_ranked_ips() {
        for criterion in [RankingCriterion::Packets, RankingCriterion::Bytes] {
            let mut tracker = BlockedIpTopN::new(2, criterion);
            // Lower the production safety threshold to exercise pruning with a small fixture.
            tracker.max_tracked_ips = 4;
            for _ in 0..3 {
                tracker.record_event(make_ip(1), BlockedProtocol::Tcp, 1);
            }
            tracker.record_event(make_ip(2), BlockedProtocol::Udp, 100);
            tracker.record_event(make_ip(3), BlockedProtocol::Other, 0);
            tracker.record_event(make_ip(4), BlockedProtocol::Other, 0);
            assert_eq!(tracker.tracked_count(), 4);
            tracker.record_event(make_ip(5), BlockedProtocol::Other, 0);
            assert_eq!(tracker.tracked_count(), 2);
            assert!(tracker.get_stats(&make_ip(1)).is_some());
            assert!(tracker.get_stats(&make_ip(2)).is_some());
            for ip in 3..=5 {
                assert!(tracker.get_stats(&make_ip(ip)).is_none());
            }
            tracker.record_event(make_ip(1), BlockedProtocol::Tcp, 7);
            assert_eq!(tracker.get_stats(&make_ip(1)).unwrap().total_bytes, 10);
        }
    }

    #[test]
    fn zero_capacity_exports_no_ips_but_keeps_statistics() {
        let mut tracker = BlockedIpTopN::new(0, RankingCriterion::Bytes);
        tracker.record_event(make_ip(1), BlockedProtocol::Udp, 128);
        assert_eq!(tracker.capacity(), 0);
        assert!(tracker.top_n_stats().is_empty());
        assert_eq!(tracker.tracked_count(), 1);
        assert_eq!(tracker.get_stats(&make_ip(1)).unwrap().total_bytes, 128);
    }

    #[test]
    fn test_stats_record_protocols() {
        let mut stats = BlockedIpStats::new(make_ip(1));
        stats.record_packet(BlockedProtocol::Tcp, 64);
        stats.record_packet(BlockedProtocol::Udp, 128);
        stats.record_packet(BlockedProtocol::Icmp, 32);
        stats.record_packet(BlockedProtocol::Icmpv6, 48);
        stats.record_packet(BlockedProtocol::Other, 100);

        assert_eq!(stats.total_packets, 5);
        assert_eq!(stats.total_bytes, 372);
        assert_eq!(stats.tcp_packets, 1);
        assert_eq!(stats.tcp_bytes, 64);
        assert_eq!(stats.udp_packets, 1);
        assert_eq!(stats.udp_bytes, 128);
        assert_eq!(stats.icmp_packets, 1);
        assert_eq!(stats.icmp_bytes, 32);
        assert_eq!(stats.icmpv6_packets, 1);
        assert_eq!(stats.icmpv6_bytes, 48);
        assert_eq!(stats.other_packets, 1);
        assert_eq!(stats.other_bytes, 100);
    }

    #[test]
    fn repeated_metric_sync_exports_only_deltas_and_restores_evicted_series() {
        let packets =
            IntCounterVec::new(opts!("test_packets", "test"), &["ip", "protocol"]).unwrap();
        let bytes = IntCounterVec::new(opts!("test_bytes", "test"), &["ip", "protocol"]).unwrap();
        let total_packets =
            IntCounterVec::new(opts!("test_total_packets", "test"), &["ip"]).unwrap();
        let total_bytes = IntCounterVec::new(opts!("test_total_bytes", "test"), &["ip"]).unwrap();
        let count = IntGauge::new("test_count", "test").unwrap();
        let mut tracker = BlockedIpTopN::new(1, RankingCriterion::Packets);
        let sync = |tracker: &mut BlockedIpTopN| {
            tracker.sync_to_metrics(&packets, &bytes, &total_packets, &total_bytes, &count);
        };
        let ip = make_ip(1).to_string();
        tracker.record_event(make_ip(1), BlockedProtocol::Tcp, 100);
        sync(&mut tracker);
        sync(&mut tracker);
        assert_eq!(packets.with_label_values(&[&ip, "tcp"]).get(), 1);
        assert_eq!(bytes.with_label_values(&[&ip, "tcp"]).get(), 100);
        assert_eq!(total_packets.with_label_values(&[&ip]).get(), 1);
        assert_eq!(total_bytes.with_label_values(&[&ip]).get(), 100);

        tracker.record_event(make_ip(1), BlockedProtocol::Udp, 200);
        sync(&mut tracker);
        assert_eq!(packets.with_label_values(&[&ip, "tcp"]).get(), 1);
        assert_eq!(packets.with_label_values(&[&ip, "udp"]).get(), 1);
        assert_eq!(bytes.with_label_values(&[&ip, "udp"]).get(), 200);
        assert_eq!(total_packets.with_label_values(&[&ip]).get(), 2);
        assert_eq!(total_bytes.with_label_values(&[&ip]).get(), 300);

        for _ in 0..3 {
            tracker.record_event(make_ip(2), BlockedProtocol::Tcp, 100);
        }
        sync(&mut tracker);
        assert!(!tracker.currently_exported_ips().contains(&ip));
        // Re-entering the Top-N must recreate counters from retained totals.
        for _ in 0..2 {
            tracker.record_event(make_ip(1), BlockedProtocol::Tcp, 50);
        }
        sync(&mut tracker);
        sync(&mut tracker);
        assert_eq!(count.get(), 1);
        assert!(tracker.currently_exported_ips().contains(&ip));
        assert_eq!(packets.with_label_values(&[&ip, "tcp"]).get(), 3);
        assert_eq!(bytes.with_label_values(&[&ip, "tcp"]).get(), 200);
        assert_eq!(packets.with_label_values(&[&ip, "udp"]).get(), 1);
        assert_eq!(total_packets.with_label_values(&[&ip]).get(), 4);
        assert_eq!(total_bytes.with_label_values(&[&ip]).get(), 400);
    }

    #[test]
    fn test_top_n_capacity_and_sorting() {
        let mut top_n = BlockedIpTopN::new(3, RankingCriterion::Packets);

        // IP 1: 10 packets
        for _ in 0..10 {
            top_n.record_event(make_ip(1), BlockedProtocol::Tcp, 100);
        }
        // IP 2: 25 packets
        for _ in 0..25 {
            top_n.record_event(make_ip(2), BlockedProtocol::Udp, 100);
        }
        // IP 3: 5 packets
        for _ in 0..5 {
            top_n.record_event(make_ip(3), BlockedProtocol::Icmp, 100);
        }
        // IP 4: 50 packets
        for _ in 0..50 {
            top_n.record_event(make_ip(4), BlockedProtocol::Tcp, 100);
        }

        let top = top_n.top_n_stats();
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].ip, make_ip(4)); // 50
        assert_eq!(top[1].ip, make_ip(2)); // 25
        assert_eq!(top[2].ip, make_ip(1)); // 10
    }

    #[test]
    fn test_eviction_from_prometheus_metrics() {
        let registry = Registry::new();
        let packets_vec = IntCounterVec::new(
            opts!("firewall_blocked_ip_packets", "test"),
            &["ip", "protocol"],
        )
        .unwrap();
        let bytes_vec = IntCounterVec::new(
            opts!("firewall_blocked_ip_bytes", "test"),
            &["ip", "protocol"],
        )
        .unwrap();
        let total_packets_vec =
            IntCounterVec::new(opts!("firewall_blocked_ip_total_packets", "test"), &["ip"])
                .unwrap();
        let total_bytes_vec =
            IntCounterVec::new(opts!("firewall_blocked_ip_total_bytes", "test"), &["ip"]).unwrap();
        let count_gauge = IntGauge::new("firewall_top_blocked_ips_count", "test count").unwrap();

        registry.register(Box::new(packets_vec.clone())).unwrap();
        registry.register(Box::new(bytes_vec.clone())).unwrap();
        registry
            .register(Box::new(total_packets_vec.clone()))
            .unwrap();
        registry
            .register(Box::new(total_bytes_vec.clone()))
            .unwrap();
        registry.register(Box::new(count_gauge.clone())).unwrap();

        let mut top_n = BlockedIpTopN::new(2, RankingCriterion::Packets);

        // Step 1: Add IP 1 and IP 2
        top_n.record_event(make_ip(1), BlockedProtocol::Tcp, 100);
        top_n.record_event(make_ip(2), BlockedProtocol::Udp, 200);

        top_n.sync_to_metrics(
            &packets_vec,
            &bytes_vec,
            &total_packets_vec,
            &total_bytes_vec,
            &count_gauge,
        );
        assert_eq!(count_gauge.get(), 2);
        assert!(top_n
            .currently_exported_ips()
            .contains(&make_ip(1).to_string()));
        assert!(top_n
            .currently_exported_ips()
            .contains(&make_ip(2).to_string()));

        // Step 2: Add IP 3 with 50 packets -> displaces IP 1 (which has only 1 packet)
        for _ in 0..50 {
            top_n.record_event(make_ip(3), BlockedProtocol::Icmp, 100);
        }

        top_n.sync_to_metrics(
            &packets_vec,
            &bytes_vec,
            &total_packets_vec,
            &total_bytes_vec,
            &count_gauge,
        );

        assert_eq!(count_gauge.get(), 2);
        assert!(!top_n
            .currently_exported_ips()
            .contains(&make_ip(1).to_string()));
        assert!(top_n
            .currently_exported_ips()
            .contains(&make_ip(3).to_string()));
        assert!(top_n
            .currently_exported_ips()
            .contains(&make_ip(2).to_string()));

        // Verify IP 1 series were truly removed from Prometheus
        let encoder = prometheus::TextEncoder::new();
        let text = encoder.encode_to_string(&registry.gather()).unwrap();
        assert!(!text.contains(&make_ip(1).to_string()));
        assert!(text.contains(&make_ip(3).to_string()));
    }
}
