#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Action constants for firewall filtering.
pub const ACTION_ACCEPT: u8 = 0;
pub const ACTION_PASS: u8 = ACTION_ACCEPT;
pub const ACTION_DROP: u8 = 1;

/// Match type classification: how the rule was triggered.
pub const MATCH_NONE: u8 = 0;
pub const MATCH_EXACT_HASH: u8 = 1;
pub const MATCH_LPM_TRIE: u8 = 2;

/// Common IP protocol numbers (RFC 790 / IANA).
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// Map maximum entries configuration.
pub const MAX_IPV4_HASH_ENTRIES: u32 = 4_194_304;
pub const MAX_IPV6_HASH_ENTRIES: u32 = 262_144;
pub const MAX_IPV4_LPM_ENTRIES: u32 = 524_288;
pub const MAX_IPV6_LPM_ENTRIES: u32 = 65_536;
pub const RING_BUF_SIZE_BYTES: u32 = 512 * 1024; // 512 KiB ring buffer

/// Value stored in the eBPF maps for matched rules.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleValue {
    /// Identifier of the rule or line in the blocklist
    pub rule_id: u32,
    /// Action to take (ACTION_DROP, ACTION_ACCEPT)
    pub action: u8,
    /// Reserved flags for future extensions (e.g. rate-limiting, deep inspection)
    pub flags: u8,
    /// Padding for 32-bit alignment
    pub _pad: [u8; 2],
}

impl RuleValue {
    pub const fn drop(rule_id: u32) -> Self {
        Self {
            rule_id,
            action: ACTION_DROP,
            flags: 0,
            _pad: [0; 2],
        }
    }

    pub const fn accept(rule_id: u32) -> Self {
        Self {
            rule_id,
            action: ACTION_ACCEPT,
            flags: 0,
            _pad: [0; 2],
        }
    }

    #[inline(always)]
    pub const fn pass(rule_id: u32) -> Self {
        Self::accept(rule_id)
    }
}

/// Key structure for IPv4 Longest Prefix Match (LPM) Trie.
/// Required layout for Linux BPF_MAP_TYPE_LPM_TRIE:
/// - 32-bit prefix length
/// - N bytes of key data (network byte order)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LpmKeyV4 {
    /// CIDR prefix length (0 to 32)
    pub prefixlen: u32,
    /// IPv4 address in network byte order (big-endian)
    pub data: [u8; 4],
}

impl LpmKeyV4 {
    /// Create a new IPv4 LPM key.
    pub const fn new(prefixlen: u32, data: [u8; 4]) -> Self {
        Self { prefixlen, data }
    }

    /// Create a key from a raw u32 in host or network order.
    pub const fn from_u32(prefixlen: u32, addr_be: u32) -> Self {
        Self {
            prefixlen,
            data: addr_be.to_be_bytes(),
        }
    }
}

/// Key structure for IPv6 Longest Prefix Match (LPM) Trie.
/// Required layout for Linux BPF_MAP_TYPE_LPM_TRIE:
/// - 32-bit prefix length
/// - 16 bytes of key data (network byte order)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LpmKeyV6 {
    /// CIDR prefix length (0 to 128)
    pub prefixlen: u32,
    /// IPv6 address in network byte order
    pub data: [u8; 16],
}

impl LpmKeyV6 {
    /// Create a new IPv6 LPM key.
    pub const fn new(prefixlen: u32, data: [u8; 16]) -> Self {
        Self { prefixlen, data }
    }
}

/// Telemetry event emitted by the eBPF kernel program via the Ring Buffer
/// whenever a packet matches a firewall rule.
///
/// Designed to be exactly 64 bytes (1 cache line) to maximize memory
/// throughput and ensure atomic zero-copy access without unaligned reads.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PacketLogEvent {
    /// Kernel timestamp in nanoseconds (bpf_ktime_get_ns())
    pub timestamp_ns: u64,
    /// Source IP address:
    /// - IPv4: first 4 bytes used (or IPv4-mapped)
    /// - IPv6: all 16 bytes used
    pub src_ip: [u8; 16],
    /// Destination IP address
    pub dst_ip: [u8; 16],
    /// Rule ID that triggered the match
    pub rule_id: u32,
    /// Total wire packet length in bytes
    pub packet_len: u32,
    /// Linux network interface index (ifindex)
    pub ifindex: u32,
    /// L4 source port (TCP/UDP) or 0
    pub src_port: u16,
    /// L4 destination port (TCP/UDP) or 0
    pub dst_port: u16,
    /// IP protocol (6 = TCP, 17 = UDP, 1 = ICMP, 58 = ICMPv6, etc.)
    pub protocol: u8,
    /// IP version: 4 or 6
    pub ip_version: u8,
    /// Action taken: ACTION_DROP (1) or ACTION_ACCEPT (0)
    pub action: u8,
    /// Lookup match source: MATCH_EXACT_HASH (1) or MATCH_LPM_TRIE (2)
    pub match_type: u8,
    /// Explicit padding to ensure total size is exactly 64 bytes
    pub _pad: [u8; 4],
}

// Compile-time assertion that PacketLogEvent is exactly 64 bytes
const _: () = assert!(core::mem::size_of::<PacketLogEvent>() == 64);

impl Default for PacketLogEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            rule_id: 0,
            packet_len: 0,
            ifindex: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            ip_version: 4,
            action: ACTION_DROP,
            match_type: MATCH_NONE,
            _pad: [0; 4],
        }
    }
}

/// Aggregated statistics counters updated in eBPF kernel space.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FirewallStats {
    /// Total incoming packets inspected
    pub rx_packets: u64,
    /// Total incoming bytes inspected
    pub rx_bytes: u64,
    /// Dropped packets
    pub dropped_packets: u64,
    /// Dropped bytes
    pub dropped_bytes: u64,
    /// Accepted packets
    pub accepted_packets: u64,
    /// Accepted bytes
    pub accepted_bytes: u64,
    /// Events successfully sent to the Ring Buffer
    pub ringbuf_events: u64,
    /// Ring Buffer drops (buffer full / overrun)
    pub ringbuf_drops: u64,
}

#[cfg(feature = "aya")]
unsafe impl aya::Pod for RuleValue {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for FirewallStats {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for PacketLogEvent {}

// Safe conversions and display utilities for std / userspace
#[cfg(feature = "std")]
impl PacketLogEvent {
    /// Get the source IP address as a standard `std::net::IpAddr`.
    pub fn src_addr(&self) -> std::net::IpAddr {
        if self.ip_version == 4 {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&self.src_ip[..4]);
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.src_ip))
        }
    }

    /// Get the destination IP address as a standard `std::net::IpAddr`.
    pub fn dst_addr(&self) -> std::net::IpAddr {
        if self.ip_version == 4 {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&self.dst_ip[..4]);
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.dst_ip))
        }
    }

    /// Get human-readable protocol string.
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            PROTO_TCP => "TCP",
            PROTO_UDP => "UDP",
            PROTO_ICMP => "ICMP",
            PROTO_ICMPV6 => "ICMPv6",
            _ => "UNKNOWN",
        }
    }

    /// Get human-readable action string.
    pub fn action_name(&self) -> &'static str {
        match self.action {
            ACTION_DROP => "DROP",
            ACTION_ACCEPT => "ACCEPT",
            _ => "OTHER",
        }
    }

    /// Get human-readable match type string.
    pub fn match_type_name(&self) -> &'static str {
        match self.match_type {
            MATCH_EXACT_HASH => "Exact HashMap",
            MATCH_LPM_TRIE => "LPM Trie CIDR",
            _ => "None",
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for PacketLogEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[{}] IPv{} {}:{} -> {}:{} proto={} rule_id={} len={}B match='{}' ifindex={}",
            self.action_name(),
            self.ip_version,
            self.src_addr(),
            self.src_port,
            self.dst_addr(),
            self.dst_port,
            self.protocol_name(),
            self.rule_id,
            self.packet_len,
            self.match_type_name(),
            self.ifindex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;
    #[cfg(feature = "std")]
    use std::{format, string::ToString};

    #[test]
    fn test_action_and_match_constants() {
        assert_eq!(ACTION_ACCEPT, 0);
        assert_eq!(ACTION_PASS, ACTION_ACCEPT);
        assert_eq!(ACTION_DROP, 1);

        assert_eq!(MATCH_NONE, 0);
        assert_eq!(MATCH_EXACT_HASH, 1);
        assert_eq!(MATCH_LPM_TRIE, 2);
    }

    #[test]
    fn test_protocol_and_map_constants() {
        assert_eq!(PROTO_ICMP, 1);
        assert_eq!(PROTO_TCP, 6);
        assert_eq!(PROTO_UDP, 17);
        assert_eq!(PROTO_ICMPV6, 58);

        assert_eq!(MAX_IPV4_HASH_ENTRIES, 4_194_304);
        assert_eq!(MAX_IPV6_HASH_ENTRIES, 262_144);
        assert_eq!(MAX_IPV4_LPM_ENTRIES, 524_288);
        assert_eq!(MAX_IPV6_LPM_ENTRIES, 65_536);
        assert_eq!(RING_BUF_SIZE_BYTES, 524_288);
    }

    #[test]
    fn test_rule_value_constructors_and_defaults() {
        let drop_rule = RuleValue::drop(42);
        assert_eq!(drop_rule.rule_id, 42);
        assert_eq!(drop_rule.action, ACTION_DROP);
        assert_eq!(drop_rule.flags, 0);
        assert_eq!(drop_rule._pad, [0, 0]);

        let accept_rule = RuleValue::accept(100);
        assert_eq!(accept_rule.rule_id, 100);
        assert_eq!(accept_rule.action, ACTION_ACCEPT);
        assert_eq!(accept_rule.flags, 0);

        let pass_rule = RuleValue::pass(100);
        assert_eq!(accept_rule, pass_rule);

        let def = RuleValue::default();
        assert_eq!(def.rule_id, 0);
        assert_eq!(def.action, 0);
    }

    #[test]
    fn test_lpm_key_v4_constructors_and_hashing() {
        let key1 = LpmKeyV4::new(24, [192, 168, 1, 0]);
        let key2 = LpmKeyV4::from_u32(24, 0xC0A80100);
        assert_eq!(key1, key2);
        assert_eq!(key1.prefixlen, 24);
        assert_eq!(key1.data, [192, 168, 1, 0]);

        #[cfg(feature = "std")]
        {
            use std::collections::HashSet;
            let mut set = HashSet::new();
            set.insert(key1);
            assert!(set.contains(&key2));
        }
    }

    #[test]
    fn test_lpm_key_v6_constructors() {
        let ip_bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let key = LpmKeyV6::new(64, ip_bytes);
        assert_eq!(key.prefixlen, 64);
        assert_eq!(key.data, ip_bytes);

        #[cfg(feature = "std")]
        {
            use std::collections::HashSet;
            let mut set = HashSet::new();
            set.insert(key);
            assert!(set.contains(&key));
        }
    }

    #[test]
    fn test_packet_log_event_size_and_alignment() {
        assert_eq!(mem::size_of::<PacketLogEvent>(), 64);
        assert_eq!(mem::align_of::<PacketLogEvent>(), 8);

        // Verify memory field offsets
        let event = PacketLogEvent::default();
        let base_ptr = &event as *const _ as usize;

        {
            assert_eq!(&event.timestamp_ns as *const _ as usize - base_ptr, 0);
            assert_eq!(&event.src_ip as *const _ as usize - base_ptr, 8);
            assert_eq!(&event.dst_ip as *const _ as usize - base_ptr, 24);
            assert_eq!(&event.rule_id as *const _ as usize - base_ptr, 40);
            assert_eq!(&event.packet_len as *const _ as usize - base_ptr, 44);
            assert_eq!(&event.ifindex as *const _ as usize - base_ptr, 48);
            assert_eq!(&event.src_port as *const _ as usize - base_ptr, 52);
            assert_eq!(&event.dst_port as *const _ as usize - base_ptr, 54);
            assert_eq!(&event.protocol as *const _ as usize - base_ptr, 56);
            assert_eq!(&event.ip_version as *const _ as usize - base_ptr, 57);
            assert_eq!(&event.action as *const _ as usize - base_ptr, 58);
            assert_eq!(&event.match_type as *const _ as usize - base_ptr, 59);
            assert_eq!(&event._pad as *const _ as usize - base_ptr, 60);
        }
    }

    #[test]
    fn test_packet_log_event_zero_copy_transmute() {
        let raw_bytes = [0x55u8; 64];
        let event: PacketLogEvent = unsafe { mem::transmute(raw_bytes) };
        assert_eq!(event.rule_id, 0x55555555);
        assert_eq!(event.packet_len, 0x55555555);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_packet_log_event_display_and_helpers() {
        let mut event = PacketLogEvent {
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

        assert_eq!(event.src_addr().to_string(), "192.168.1.10");
        assert_eq!(event.dst_addr().to_string(), "10.0.0.1");
        assert_eq!(event.protocol_name(), "TCP");
        assert_eq!(event.action_name(), "DROP");
        assert_eq!(event.match_type_name(), "Exact HashMap");

        let display_str = format!("{}", event);
        assert!(display_str.contains("[DROP]"));
        assert!(display_str.contains("IPv4 192.168.1.10:12345 -> 10.0.0.1:80"));
        assert!(display_str.contains("proto=TCP"));
        assert!(display_str.contains("rule_id=15"));
        assert!(display_str.contains("match='Exact HashMap'"));

        // Test IPv6 formatting
        event.ip_version = 6;
        event.src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        event.dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        event.protocol = PROTO_UDP;
        event.action = ACTION_ACCEPT;
        event.match_type = MATCH_LPM_TRIE;

        assert_eq!(event.src_addr().to_string(), "2001:db8::1");
        assert_eq!(event.dst_addr().to_string(), "2001:db8::2");
        assert_eq!(event.protocol_name(), "UDP");
        assert_eq!(event.action_name(), "ACCEPT");
        assert_eq!(event.match_type_name(), "LPM Trie CIDR");

        event.protocol = PROTO_ICMP;
        assert_eq!(event.protocol_name(), "ICMP");
        event.protocol = PROTO_ICMPV6;
        assert_eq!(event.protocol_name(), "ICMPv6");
        event.protocol = 255;
        assert_eq!(event.protocol_name(), "UNKNOWN");
        event.action = 255;
        assert_eq!(event.action_name(), "OTHER");
        event.match_type = 0;
        assert_eq!(event.match_type_name(), "None");
    }

    #[test]
    fn test_firewall_stats_wrapping_math() {
        let mut stats = FirewallStats::default();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.accepted_packets, 0);

        stats.rx_packets = u64::MAX;
        stats.rx_packets = stats.rx_packets.wrapping_add(1);
        assert_eq!(stats.rx_packets, 0);

        stats.accepted_packets = 100;
        stats.dropped_packets = 20;
        assert_eq!(stats.accepted_packets + stats.dropped_packets, 120);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_json_roundtrip() {
        let rule = RuleValue::drop(77);
        let rule_json = serde_json::to_string(&rule).expect("serialize rule");
        let rule_de: RuleValue = serde_json::from_str(&rule_json).expect("deserialize rule");
        assert_eq!(rule, rule_de);

        let key_v4 = LpmKeyV4::new(16, [172, 16, 0, 0]);
        let key_v4_json = serde_json::to_string(&key_v4).expect("serialize key_v4");
        let key_v4_de: LpmKeyV4 = serde_json::from_str(&key_v4_json).expect("deserialize key_v4");
        assert_eq!(key_v4, key_v4_de);

        let key_v6 = LpmKeyV6::new(
            48,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let key_v6_json = serde_json::to_string(&key_v6).expect("serialize key_v6");
        let key_v6_de: LpmKeyV6 = serde_json::from_str(&key_v6_json).expect("deserialize key_v6");
        assert_eq!(key_v6, key_v6_de);

        let stats = FirewallStats {
            rx_packets: 1000,
            rx_bytes: 64000,
            dropped_packets: 100,
            dropped_bytes: 6400,
            accepted_packets: 900,
            accepted_bytes: 57600,
            ringbuf_events: 100,
            ringbuf_drops: 0,
        };
        let stats_json = serde_json::to_string(&stats).expect("serialize stats");
        let stats_de: FirewallStats = serde_json::from_str(&stats_json).expect("deserialize stats");
        assert_eq!(stats, stats_de);
    }
}
