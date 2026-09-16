#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC},
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, RingBuf},
    programs::XdpContext,
};
use core::mem;
use firewall_common::{
    FirewallStats, PacketLogEvent, RuleValue, ACTION_DROP, MATCH_EXACT_HASH, MATCH_LPM_TRIE,
    MATCH_NONE, MAX_IPV4_HASH_ENTRIES, MAX_IPV4_LPM_ENTRIES, MAX_IPV6_HASH_ENTRIES,
    MAX_IPV6_LPM_ENTRIES, PROTO_TCP, PROTO_UDP, RING_BUF_SIZE_BYTES,
};

/// ---------------------------------------------------------------------------
/// eBPF MAP DEFINITIONS
/// ---------------------------------------------------------------------------

/// BPF HashMap for O(1) exact match lookup of IPv4 addresses (/32).
/// Key: IPv4 address in network byte order ([u8; 4]).
/// Value: Rule configuration (action, rule ID, flags).
#[map]
static IPV4_EXACT_MAP: HashMap<[u8; 4], RuleValue> =
    HashMap::with_max_entries(MAX_IPV4_HASH_ENTRIES, BPF_F_NO_PREALLOC);

/// BPF HashMap for O(1) exact match lookup of IPv6 addresses (/128).
/// Key: IPv6 address in network byte order ([u8; 16]).
/// Value: Rule configuration (action, rule ID, flags).
#[map]
static IPV6_EXACT_MAP: HashMap<[u8; 16], RuleValue> =
    HashMap::with_max_entries(MAX_IPV6_HASH_ENTRIES, BPF_F_NO_PREALLOC);

/// BPF Longest Prefix Match (LPM) Trie for IPv4 CIDR blocks (e.g. 10.0.0.0/8).
/// Key: aya_ebpf::maps::lpm_trie::Key<[u8; 4]> (prefix length + IPv4 bytes).
/// Value: Rule configuration.
///
/// BPF_F_NO_PREALLOC is strictly required by the Linux kernel for LPM Trie maps.
#[map]
static IPV4_LPM_MAP: LpmTrie<[u8; 4], RuleValue> =
    LpmTrie::with_max_entries(MAX_IPV4_LPM_ENTRIES, BPF_F_NO_PREALLOC);

/// BPF Longest Prefix Match (LPM) Trie for IPv6 CIDR blocks (e.g. 2001:db8::/32).
/// Key: aya_ebpf::maps::lpm_trie::Key<[u8; 16]> (prefix length + IPv6 bytes).
/// Value: Rule configuration.
#[map]
static IPV6_LPM_MAP: LpmTrie<[u8; 16], RuleValue> =
    LpmTrie::with_max_entries(MAX_IPV6_LPM_ENTRIES, BPF_F_NO_PREALLOC);

/// BPF Ring Buffer for streaming high-performance telemetry events
/// from kernel space to user space.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE_BYTES, 0);

/// Global firewall packet and byte statistics counters.
/// Stored in an Array with 1 element for fast indexed lookup.
#[map]
static STATS: Array<FirewallStats> = Array::with_max_entries(1, 0);

/// ---------------------------------------------------------------------------
/// PACKET PARSING STRUCTURES & CONSTANTS
/// ---------------------------------------------------------------------------

const ETH_P_IP: u16 = 0x0800; // IPv4 Ethernet Protocol ID (big-endian 0x0800)
const ETH_P_IPV6: u16 = 0x86DD; // IPv6 Ethernet Protocol ID (big-endian 0x86DD)
const ETH_P_8021Q: u16 = 0x8100; // 802.1Q VLAN tag
const ETH_P_8021AD: u16 = 0x88A8; // 802.1ad QinQ VLAN tag

const ETH_HDR_LEN: usize = 14;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthernetHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv4Header {
    vhl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6Header {
    vtc_fl: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TransportPorts {
    src_port: u16,
    dst_port: u16,
}

/// ---------------------------------------------------------------------------
/// HELPER FUNCTIONS
/// ---------------------------------------------------------------------------

/// Verifier-safe pointer boundary checker.
///
/// eBPF verifier requires proving that all memory accesses fall strictly
/// between ctx.data() and ctx.data_end(). Any unverified dereference will
/// cause the verifier to reject loading the program with Err(-EACCES).
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// Update global counter statistics in the STATS array map.
#[inline(always)]
fn update_stats(rx_bytes: u64, dropped: bool, dropped_bytes: u64, ringbuf_emitted: bool) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            let stats = &mut *stats_ptr;
            stats.rx_packets = stats.rx_packets.wrapping_add(1);
            stats.rx_bytes = stats.rx_bytes.wrapping_add(rx_bytes);

            if dropped {
                stats.dropped_packets = stats.dropped_packets.wrapping_add(1);
                stats.dropped_bytes = stats.dropped_bytes.wrapping_add(dropped_bytes);
            } else {
                stats.accepted_packets = stats.accepted_packets.wrapping_add(1);
                stats.accepted_bytes = stats.accepted_bytes.wrapping_add(rx_bytes);
            }

            if ringbuf_emitted {
                stats.ringbuf_events = stats.ringbuf_events.wrapping_add(1);
            }
        }
    }
}

/// ---------------------------------------------------------------------------
/// MAIN XDP INGRESS FIREWALL HOOK
/// ---------------------------------------------------------------------------

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => {
            // Malformed packet or truncated header: safely let kernel handle it
            xdp_action::XDP_PASS
        }
    }
}

#[inline(always)]
fn try_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let packet_len = (ctx.data_end() - ctx.data()) as u32;

    // 1. Parse Ethernet Header
    let eth_ptr = ptr_at::<EthernetHeader>(ctx, 0)?;
    let eth_hdr = unsafe { core::ptr::read_unaligned(eth_ptr) };
    let mut ether_type = u16::from_be(eth_hdr.ether_type);
    let mut offset = ETH_HDR_LEN;

    // Handle 802.1Q / 802.1ad VLAN tags (skip 4 bytes per tag)
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vlan_ptr = ptr_at::<[u8; 4]>(ctx, offset)?;
        let vlan_bytes = unsafe { *vlan_ptr };
        ether_type = u16::from_be_bytes([vlan_bytes[2], vlan_bytes[3]]);
        offset += 4;
    }

    // 2. Dispatch by Network Layer Protocol
    match ether_type {
        ETH_P_IP => process_ipv4(ctx, offset, packet_len),
        ETH_P_IPV6 => process_ipv6(ctx, offset, packet_len),
        _ => {
            // Non-IP packets (e.g. ARP, LLDP) are accepted directly
            update_stats(packet_len as u64, false, 0, false);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// ---------------------------------------------------------------------------
/// IPv4 PROCESSING PIPELINE
/// ---------------------------------------------------------------------------

/// Check if an IPv4 address belongs to GitHub infrastructure (AS36459)
#[inline(always)]
fn is_github_ipv4(ip: &[u8; 4]) -> bool {
    // 140.82.112.0/20 (140.82.112.0 - 140.82.127.255, including github.com 140.82.121.3 / 140.82.121.4)
    if ip[0] == 140 && ip[1] == 82 && (ip[2] & 0xF0) == 112 {
        return true;
    }
    // 192.30.252.0/22 (192.30.252.0 - 192.30.255.255)
    if ip[0] == 192 && ip[1] == 30 && (ip[2] & 0xFC) == 252 {
        return true;
    }
    // 185.199.108.0/22 (185.199.108.0 - 185.199.111.255)
    if ip[0] == 185 && ip[1] == 199 && (ip[2] & 0xFC) == 108 {
        return true;
    }
    // 143.55.64.0/20 (143.55.64.0 - 143.55.79.255)
    if ip[0] == 143 && ip[1] == 55 && (ip[2] & 0xF0) == 64 {
        return true;
    }
    // Azure GitHub frontends (20.201.28.151, 20.205.243.166, 4.237.22.0/23)
    if (ip[0] == 20 && ip[1] == 201 && ip[2] == 28 && ip[3] == 151)
        || (ip[0] == 20 && ip[1] == 205 && ip[2] == 243 && ip[3] == 166)
        || (ip[0] == 4 && ip[1] == 237 && (ip[2] == 22 || ip[2] == 23))
    {
        return true;
    }
    false
}

#[inline(always)]
fn process_ipv4(ctx: &XdpContext, offset: usize, packet_len: u32) -> Result<u32, ()> {
    let ip_ptr = ptr_at::<Ipv4Header>(ctx, offset)?;
    let ip_hdr = unsafe { core::ptr::read_unaligned(ip_ptr) };

    // IPv4 header length is stored in 32-bit words in the lower 4 bits of vhl
    let ihl = ((ip_hdr.vhl & 0x0F) as usize) * 4;
    if ihl < 20 {
        return Err(());
    }

    // Ensure entire IPv4 options/header is present in bounds
    let l4_offset = offset + ihl;
    if ctx.data() + l4_offset > ctx.data_end() {
        return Err(());
    }

    let src_ip = ip_hdr.src_addr;
    let dst_ip = ip_hdr.dst_addr;
    let protocol = ip_hdr.protocol;

    // Parse L4 transport ports if TCP or UDP
    let (src_port, dst_port) = extract_ports(ctx, l4_offset, protocol);

    // Management & infrastructure bypasses:
    // 1. DNS responses (port 53) so domain resolution never fails
    if (protocol == PROTO_UDP || protocol == PROTO_TCP) && src_port == 53 {
        update_stats(packet_len as u64, false, 0, false);
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. Upstream Git/HTTPS responses (port 443) from GitHub infrastructure
    if protocol == PROTO_TCP && src_port == 443 && is_github_ipv4(&src_ip) {
        update_stats(packet_len as u64, false, 0, false);
        return Ok(xdp_action::XDP_PASS);
    }

    // -----------------------------------------------------------------------
    // IP REPUTATION LOOKUP HIERARCHY
    // -----------------------------------------------------------------------

    let mut matched_rule: Option<RuleValue> = None;
    let mut match_type = MATCH_NONE;

    // LEVEL 1: Exact IP lookup in BPF HashMap (O(1) average time complexity)
    if let Some(rule) = unsafe { IPV4_EXACT_MAP.get(&src_ip) } {
        matched_rule = Some(*rule);
        match_type = MATCH_EXACT_HASH;
    }

    // LEVEL 2: CIDR Range lookup in BPF LPM Trie (Trie lookup)
    // If not matched in exact map, query LPM Trie with prefixlen = 32
    if matched_rule.is_none() {
        let lpm_key = Key::new(32, src_ip);
        if let Some(rule) = IPV4_LPM_MAP.get(&lpm_key) {
            matched_rule = Some(*rule);
            match_type = MATCH_LPM_TRIE;
        }
    }

    // -----------------------------------------------------------------------
    // ACTION ENFORCEMENT & RING BUFFER TELEMETRY
    // -----------------------------------------------------------------------

    if let Some(rule) = matched_rule {
        if rule.action == ACTION_DROP {
            // Emitting telemetry event to User Space via Ring Buffer
            let event = PacketLogEvent {
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                src_ip: [
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                dst_ip: [
                    dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                rule_id: rule.rule_id,
                packet_len,
                ifindex: ctx.ingress_ifindex() as u32,
                src_port,
                dst_port,
                protocol,
                ip_version: 4,
                action: ACTION_DROP,
                match_type,
                _pad: [0; 4],
            };

            // Submit event to RingBuf with zero allocations
            let ringbuf_success = EVENTS.output::<PacketLogEvent>(&event, 0).is_ok();

            // Update drop statistics
            update_stats(packet_len as u64, true, packet_len as u64, ringbuf_success);

            // DROP packet immediately at XDP driver level!
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Packet allowed
    update_stats(packet_len as u64, false, 0, false);
    Ok(xdp_action::XDP_PASS)
}

/// ---------------------------------------------------------------------------
/// IPv6 PROCESSING PIPELINE
/// ---------------------------------------------------------------------------

#[inline(always)]
fn process_ipv6(ctx: &XdpContext, offset: usize, packet_len: u32) -> Result<u32, ()> {
    let ip_ptr = ptr_at::<Ipv6Header>(ctx, offset)?;
    let ip_hdr = unsafe { core::ptr::read_unaligned(ip_ptr) };

    let l4_offset = offset + mem::size_of::<Ipv6Header>();
    if ctx.data() + l4_offset > ctx.data_end() {
        return Err(());
    }

    let src_ip = ip_hdr.src_addr;
    let dst_ip = ip_hdr.dst_addr;
    let protocol = ip_hdr.next_header;

    let (src_port, dst_port) = extract_ports(ctx, l4_offset, protocol);

    // -----------------------------------------------------------------------
    // IPv6 REPUTATION LOOKUP HIERARCHY
    // -----------------------------------------------------------------------

    let mut matched_rule: Option<RuleValue> = None;
    let mut match_type = MATCH_NONE;

    // LEVEL 1: Exact IPv6 match in HashMap
    if let Some(rule) = unsafe { IPV6_EXACT_MAP.get(&src_ip) } {
        matched_rule = Some(*rule);
        match_type = MATCH_EXACT_HASH;
    }

    // LEVEL 2: CIDR match in LPM Trie (prefixlen = 128)
    if matched_rule.is_none() {
        let lpm_key = Key::new(128, src_ip);
        if let Some(rule) = IPV6_LPM_MAP.get(&lpm_key) {
            matched_rule = Some(*rule);
            match_type = MATCH_LPM_TRIE;
        }
    }

    // -----------------------------------------------------------------------
    // ACTION ENFORCEMENT & RING BUFFER TELEMETRY
    // -----------------------------------------------------------------------

    if let Some(rule) = matched_rule {
        if rule.action == ACTION_DROP {
            let event = PacketLogEvent {
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                src_ip,
                dst_ip,
                rule_id: rule.rule_id,
                packet_len,
                ifindex: ctx.ingress_ifindex() as u32,
                src_port,
                dst_port,
                protocol,
                ip_version: 6,
                action: ACTION_DROP,
                match_type,
                _pad: [0; 4],
            };

            let ringbuf_success = EVENTS.output::<PacketLogEvent>(&event, 0).is_ok();
            update_stats(packet_len as u64, true, packet_len as u64, ringbuf_success);

            return Ok(xdp_action::XDP_DROP);
        }
    }

    update_stats(packet_len as u64, false, 0, false);
    Ok(xdp_action::XDP_PASS)
}

/// Extract Layer 4 source and destination ports for TCP and UDP packets.
#[inline(always)]
fn extract_ports(ctx: &XdpContext, l4_offset: usize, protocol: u8) -> (u16, u16) {
    if protocol == PROTO_TCP || protocol == PROTO_UDP {
        if let Ok(ports_ptr) = ptr_at::<TransportPorts>(ctx, l4_offset) {
            let ports = unsafe { core::ptr::read_unaligned(ports_ptr) };
            return (u16::from_be(ports.src_port), u16::from_be(ports.dst_port));
        }
    }
    (0, 0)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_github_ipv4_140_82_112_slash20() {
        assert!(is_github_ipv4(&[140, 82, 112, 0]));
        assert!(is_github_ipv4(&[140, 82, 121, 3]));
        assert!(is_github_ipv4(&[140, 82, 121, 4]));
        assert!(is_github_ipv4(&[140, 82, 127, 255]));
        assert!(!is_github_ipv4(&[140, 82, 111, 255]));
        assert!(!is_github_ipv4(&[140, 82, 128, 0]));
        assert!(!is_github_ipv4(&[140, 81, 112, 0]));
    }

    #[test]
    fn test_is_github_ipv4_192_30_252_slash22() {
        assert!(is_github_ipv4(&[192, 30, 252, 0]));
        assert!(is_github_ipv4(&[192, 30, 252, 10]));
        assert!(is_github_ipv4(&[192, 30, 255, 255]));
        assert!(!is_github_ipv4(&[192, 30, 251, 255]));
        assert!(!is_github_ipv4(&[192, 31, 252, 0]));
    }

    #[test]
    fn test_is_github_ipv4_185_199_108_slash22() {
        assert!(is_github_ipv4(&[185, 199, 108, 0]));
        assert!(is_github_ipv4(&[185, 199, 108, 153]));
        assert!(is_github_ipv4(&[185, 199, 111, 255]));
        assert!(!is_github_ipv4(&[185, 199, 107, 255]));
        assert!(!is_github_ipv4(&[185, 199, 112, 0]));
    }

    #[test]
    fn test_is_github_ipv4_143_55_64_slash20() {
        assert!(is_github_ipv4(&[143, 55, 64, 0]));
        assert!(is_github_ipv4(&[143, 55, 79, 255]));
        assert!(!is_github_ipv4(&[143, 55, 63, 255]));
        assert!(!is_github_ipv4(&[143, 55, 80, 0]));
        assert!(!is_github_ipv4(&[143, 56, 64, 0]));
    }

    #[test]
    fn test_is_github_ipv4_azure_frontends() {
        assert!(is_github_ipv4(&[20, 201, 28, 151]));
        assert!(is_github_ipv4(&[20, 205, 243, 166]));
        assert!(is_github_ipv4(&[4, 237, 22, 1]));
        assert!(is_github_ipv4(&[4, 237, 23, 255]));
        // 4.237.24.0/23 boundary: 24 is outside [22, 23].
        assert!(!is_github_ipv4(&[4, 237, 24, 0]));
        assert!(!is_github_ipv4(&[20, 201, 28, 152]));
        assert!(!is_github_ipv4(&[20, 205, 243, 167]));
    }

    #[test]
    fn test_is_github_ipv4_unrelated_addresses() {
        assert!(!is_github_ipv4(&[8, 8, 8, 8]));
        assert!(!is_github_ipv4(&[0, 0, 0, 0]));
        assert!(!is_github_ipv4(&[255, 255, 255, 255]));
        assert!(!is_github_ipv4(&[127, 0, 0, 1]));
    }

    /// Represents an XDP packet buffer mapped into the low 4 GiB of the address
    /// space, where the u32 `data`/`data_end` fields of `xdp_md` can encode the
    /// absolute buffer addresses without truncation.
    struct MockPacket {
        ptr: *mut std::ffi::c_void,
        len: usize,
        /// Page-aligned number of bytes mapped (used for munmap).
        mapped: usize,
    }

    impl MockPacket {
        fn new(len: usize) -> Self {
            unsafe {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                let mapped = (len + page - 1) & !(page - 1);
                let mut addr = 0x1000_0000usize;
                let mut ptr = std::ptr::null_mut();
                while addr < 0x8000_0000 {
                    let res = libc::mmap(
                        addr as *mut std::ffi::c_void,
                        mapped,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    );
                    if res != libc::MAP_FAILED {
                        ptr = res;
                        break;
                    }
                    addr += page;
                }
                assert!(!ptr.is_null(), "could not mmap low memory for XDP test ctx");
                MockPacket {
                    ptr,
                    len,
                    mapped,
                }
            }
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.ptr.cast::<u8>(), self.len) }
        }

        fn ctx(&self) -> XdpContext {
            let mut md: ::aya_ebpf::bindings::xdp_md = unsafe { std::mem::zeroed() };
            md.data = self.ptr as usize as u32;
            md.data_end = (self.ptr as usize + self.len) as u32;
            md.ingress_ifindex = 2;
            md.rx_queue_index = 0;
            XdpContext::new(&mut md)
        }
    }

    impl Drop for MockPacket {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.ptr, self.mapped);
            }
        }
    }

    #[test]
    fn test_extract_ports_reads_unaligned_tcp_udp_ports() {
        let len = 64;
        let mut pkt = MockPacket::new(len);
        let bytes = pkt.bytes_mut();
        bytes.fill(0);
        // src_port 443 (0x01bb), dst_port 53 (0x0035) at 2-byte unaligned offset.
        bytes[14 + 4 + 0] = 0x01;
        bytes[14 + 4 + 1] = 0xbb;
        bytes[14 + 4 + 2] = 0x00;
        bytes[14 + 4 + 3] = 0x35;

        let ctx = pkt.ctx();
        assert_eq!(
            extract_ports(&ctx, 14 + 4, PROTO_TCP),
            (443, 53)
        );
        assert_eq!(
            extract_ports(&ctx, 14 + 4, PROTO_UDP),
            (443, 53)
        );

        // Non-TCP/UDP protocols short-circuit to (0, 0).
        assert_eq!(
            extract_ports(&ctx, 14 + 4, 1), // ICMP
            (0, 0)
        );

        // L4 offset beyond the packet boundary falls back to (0, 0).
        assert_eq!(
            extract_ports(&ctx, len, PROTO_TCP),
            (0, 0)
        );
        assert_eq!(
            extract_ports(&ctx, len - 2, PROTO_TCP),
            (0, 0)
        );
    }

    #[test]
    fn test_ptr_at_bounds_checks_against_packet_end() {
        let mut pkt = MockPacket::new(64);
        pkt.bytes_mut().fill(0xAA);
        let ctx = pkt.ctx();

        // Complete Ethernet + IPv4 headers fit within the 64-byte buffer.
        assert!(ptr_at::<EthernetHeader>(&ctx, 0).is_ok());
        assert!(ptr_at::<Ipv4Header>(&ctx, ETH_HDR_LEN).is_ok());

        // sizeof(EthernetHeader) == 14: exactly [50, 64) fits in 64 bytes.
        assert!(ptr_at::<EthernetHeader>(&ctx, 64 - 14).is_ok());

        // The full 14-byte Ethernet header no longer fits starting at 51.
        assert!(ptr_at::<EthernetHeader>(&ctx, 64 - 14 + 1).is_err());
        // Ipv4Header (20 bytes) fits exactly [44, 64) but overflows from 45.
        assert!(ptr_at::<Ipv4Header>(&ctx, 64 - 20).is_ok());
        assert!(ptr_at::<Ipv4Header>(&ctx, 64 - 20 + 1).is_err());
        // Entirely out-of-range access.
        assert!(ptr_at::<Ipv4Header>(&ctx, 64).is_err());
    }
}
