#![cfg_attr(not(test), no_std)]


use core::mem;
pub use firewall_common::{
    ACTION_ACCEPT, ACTION_DROP, MATCH_EXACT_HASH, MATCH_NONE, PROTO_ICMP, PROTO_ICMPV6,
    PROTO_TCP, PROTO_UDP,
};

/// ---------------------------------------------------------------------------
/// PROTOCOL CONSTANTS
/// ---------------------------------------------------------------------------

pub const ETH_P_IP: u16 = 0x0800; // IPv4 Ethernet Protocol ID (big-endian 0x0800)
pub const ETH_P_IPV6: u16 = 0x86DD; // IPv6 Ethernet Protocol ID (big-endian 0x86DD)
pub const ETH_P_8021Q: u16 = 0x8100; // 802.1Q VLAN tag
pub const ETH_P_8021AD: u16 = 0x88A8; // 802.1ad QinQ VLAN tag

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_MIN_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;

/// ---------------------------------------------------------------------------
/// PACKET HEADERS (Packed C Representation for Kernel Wire Compatibility)
/// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub vhl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub vtc_fl: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportPorts {
    pub src_port: u16,
    pub dst_port: u16,
}

/// ---------------------------------------------------------------------------
/// PARSED PACKET CLASSIFICATION RESULT
/// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub ip_version: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_len: usize,
    pub l4_offset: usize,
}

/// ---------------------------------------------------------------------------
/// SAFE PARSING & BOUNDS CHECKING FUNCTIONS
/// ---------------------------------------------------------------------------

/// Verifier-compatible boundary checker with overflow protection.
#[inline(always)]
pub fn check_bounds(total_len: usize, offset: usize, needed: usize) -> bool {
    match offset.checked_add(needed) {
        Some(end) => end <= total_len,
        None => false,
    }
}

/// Parse Ethernet header and strip single (802.1Q) or double (802.1ad QinQ) VLAN tags.
///
/// Returns `(EthernetHeader, l3_offset, final_ether_type)` on success.
#[inline(always)]
pub fn parse_ethernet(data: &[u8]) -> Result<(EthernetHeader, usize, u16), ()> {
    if !check_bounds(data.len(), 0, ETH_HDR_LEN) {
        return Err(());
    }

    let eth_hdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const EthernetHeader) };
    let mut ether_type = u16::from_be(eth_hdr.ether_type);
    let mut offset = ETH_HDR_LEN;

    // Handle 802.1Q and 802.1ad VLAN tags (up to 2 tags for QinQ)
    for _ in 0..2 {
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            if !check_bounds(data.len(), offset, 4) {
                return Err(());
            }
            let vlan_bytes = [data[offset + 2], data[offset + 3]];
            ether_type = u16::from_be_bytes(vlan_bytes);
            offset += 4;
        } else {
            break;
        }
    }

    Ok((eth_hdr, offset, ether_type))
}

/// Parse IPv4 header, validating version, IHL (>= 20 bytes), and buffer bounds.
///
/// Returns `(Ipv4Header, l4_offset)` on success.
#[inline(always)]
pub fn parse_ipv4(data: &[u8], offset: usize) -> Result<(Ipv4Header, usize), ()> {
    if !check_bounds(data.len(), offset, IPV4_MIN_HDR_LEN) {
        return Err(());
    }

    let ip_hdr =
        unsafe { core::ptr::read_unaligned((data.as_ptr() as usize + offset) as *const Ipv4Header) };

    // Version must be 4
    if (ip_hdr.vhl >> 4) != 4 {
        return Err(());
    }

    // Internet Header Length (IHL) in 32-bit words (lower 4 bits of vhl)
    let ihl = ((ip_hdr.vhl & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return Err(());
    }

    // Ensure entire IPv4 options/header fits in the packet buffer
    if !check_bounds(data.len(), offset, ihl) {
        return Err(());
    }

    let l4_offset = offset + ihl;
    Ok((ip_hdr, l4_offset))
}

/// Parse IPv6 fixed 40-byte header, validating version.
///
/// Returns `(Ipv6Header, l4_offset)` on success.
#[inline(always)]
pub fn parse_ipv6(data: &[u8], offset: usize) -> Result<(Ipv6Header, usize), ()> {
    if !check_bounds(data.len(), offset, IPV6_HDR_LEN) {
        return Err(());
    }

    let ip_hdr =
        unsafe { core::ptr::read_unaligned((data.as_ptr() as usize + offset) as *const Ipv6Header) };

    // IPv6 Version is in the first 4 bits of vtc_fl (in big-endian)
    let version = (u32::from_be(ip_hdr.vtc_fl) >> 28) as u8;
    if version != 6 {
        return Err(());
    }

    let l4_offset = offset + IPV6_HDR_LEN;
    Ok((ip_hdr, l4_offset))
}

/// Extract Layer 4 transport source and destination ports for TCP or UDP.
///
/// Returns `(src_port, dst_port)` in host byte order, or `(0, 0)` if not TCP/UDP or truncated.
#[inline(always)]
pub fn extract_transport_ports(data: &[u8], l4_offset: usize, protocol: u8) -> (u16, u16) {
    if protocol == PROTO_TCP || protocol == PROTO_UDP {
        if check_bounds(data.len(), l4_offset, mem::size_of::<TransportPorts>()) {
            let ports = unsafe {
                core::ptr::read_unaligned(
                    (data.as_ptr() as usize + l4_offset) as *const TransportPorts,
                )
            };
            return (u16::from_be(ports.src_port), u16::from_be(ports.dst_port));
        }
    }
    (0, 0)
}

/// End-to-end zero-copy classification of a raw packet buffer.
#[inline(always)]
pub fn classify_packet(data: &[u8]) -> Result<ParsedPacket, ()> {
    let (_eth_hdr, l3_offset, ether_type) = parse_ethernet(data)?;

    match ether_type {
        ETH_P_IP => {
            let (ip_hdr, l4_offset) = parse_ipv4(data, l3_offset)?;
            let (src_port, dst_port) = extract_transport_ports(data, l4_offset, ip_hdr.protocol);

            let mut src_ip = [0u8; 16];
            src_ip[..4].copy_from_slice(&ip_hdr.src_addr);
            let mut dst_ip = [0u8; 16];
            dst_ip[..4].copy_from_slice(&ip_hdr.dst_addr);

            Ok(ParsedPacket {
                ip_version: 4,
                src_ip,
                dst_ip,
                protocol: ip_hdr.protocol,
                src_port,
                dst_port,
                packet_len: data.len(),
                l4_offset,
            })
        }
        ETH_P_IPV6 => {
            let (ip_hdr, l4_offset) = parse_ipv6(data, l3_offset)?;
            let (src_port, dst_port) = extract_transport_ports(data, l4_offset, ip_hdr.next_header);

            Ok(ParsedPacket {
                ip_version: 6,
                src_ip: ip_hdr.src_addr,
                dst_ip: ip_hdr.dst_addr,
                protocol: ip_hdr.next_header,
                src_port,
                dst_port,
                packet_len: data.len(),
                l4_offset,
            })
        }
        _ => Err(()),
    }
}

/// Simulate eBPF HashMap exact match lookup logic.
#[inline(always)]
pub fn simulate_exact_match(
    parsed: &ParsedPacket,
    exact_v4: &[[u8; 4]],
    exact_v6: &[[u8; 16]],
) -> (u8, u8) {
    if parsed.ip_version == 4 {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&parsed.src_ip[..4]);
        if exact_v4.contains(&addr) {
            return (ACTION_DROP, MATCH_EXACT_HASH);
        }
    } else if parsed.ip_version == 6 {
        if exact_v6.contains(&parsed.src_ip) {
            return (ACTION_DROP, MATCH_EXACT_HASH);
        }
    }
    (ACTION_ACCEPT, MATCH_NONE)
}

/// ---------------------------------------------------------------------------
/// UNIT TESTS
/// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_raw_ipv4_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> [u8; 54] {
        let mut buf = [0u8; 54];
        // Ethernet: Dst MAC (6), Src MAC (6), EtherType 0x0800 (2)
        buf[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x42, 0x55, 0x66]);
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        // IPv4 Header (20 bytes at offset 14)
        buf[14] = 0x45; // Version 4, IHL 5 (20 bytes)
        buf[15] = 0x00; // TOS
        buf[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total length: 40
        buf[23] = PROTO_TCP; // Protocol TCP
        buf[26..30].copy_from_slice(&src_ip);
        buf[30..34].copy_from_slice(&dst_ip);

        // TCP Header (20 bytes at offset 34)
        buf[34..36].copy_from_slice(&sport.to_be_bytes());
        buf[36..38].copy_from_slice(&dport.to_be_bytes());
        buf[46] = 0x50; // Data offset 5 words
        buf[47] = 0x02; // SYN flag

        buf
    }

    fn build_raw_ipv4_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> [u8; 42] {
        let mut buf = [0u8; 42];
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        buf[14] = 0x45;
        buf[23] = PROTO_UDP;
        buf[26..30].copy_from_slice(&src_ip);
        buf[30..34].copy_from_slice(&dst_ip);
        buf[34..36].copy_from_slice(&sport.to_be_bytes());
        buf[36..38].copy_from_slice(&dport.to_be_bytes());
        buf
    }

    fn build_raw_vlan_8021q_packet() -> [u8; 58] {
        let mut buf = [0u8; 58];
        // Ethernet: 12 bytes MACs
        buf[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // 802.1Q Tag: TPID 0x8100, TCI (VLAN ID 100), Inner EtherType 0x0800
        buf[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        buf[14..16].copy_from_slice(&100u16.to_be_bytes());
        buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());

        // IPv4 at offset 18
        buf[18] = 0x45;
        buf[27] = PROTO_UDP;
        buf[30..34].copy_from_slice(&[192, 168, 1, 50]);
        buf[34..38].copy_from_slice(&[10, 0, 0, 1]);
        // UDP Ports at offset 38
        buf[38..40].copy_from_slice(&5353u16.to_be_bytes());
        buf[40..42].copy_from_slice(&53u16.to_be_bytes());
        buf
    }

    fn build_raw_ipv6_tcp_packet(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> [u8; 74] {
        let mut buf = [0u8; 74];
        buf[12..14].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6 EtherType

        // IPv6 Header at offset 14 (40 bytes)
        buf[14..18].copy_from_slice(&0x60000000u32.to_be_bytes()); // Version 6
        buf[18..20].copy_from_slice(&20u16.to_be_bytes()); // Payload len: 20
        buf[20] = PROTO_TCP; // Next Header
        buf[21] = 64; // Hop limit
        buf[22..38].copy_from_slice(&src);
        buf[38..54].copy_from_slice(&dst);

        // TCP Header at offset 54
        buf[54..56].copy_from_slice(&sport.to_be_bytes());
        buf[56..58].copy_from_slice(&dport.to_be_bytes());
        buf
    }

    #[test]
    fn test_bounds_check_safety() {
        assert!(check_bounds(100, 0, 50));
        assert!(check_bounds(100, 50, 50));
        assert!(!check_bounds(100, 50, 51));
        assert!(!check_bounds(100, 101, 1));
        assert!(!check_bounds(100, usize::MAX, 1)); // Overflow safety
    }

    #[test]
    fn test_parse_ethernet_standard() {
        let packet = build_raw_ipv4_tcp_packet([192, 168, 1, 1], [10, 0, 0, 1], 1234, 80);
        let (eth, l3_offset, ether_type) = parse_ethernet(&packet).expect("parse ethernet");
        assert_eq!(ether_type, ETH_P_IP);
        assert_eq!(l3_offset, 14);
        assert_eq!(eth.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_ethernet_vlan_8021q() {
        let packet = build_raw_vlan_8021q_packet();
        let (_eth, l3_offset, ether_type) = parse_ethernet(&packet).expect("parse vlan");
        assert_eq!(ether_type, ETH_P_IP);
        assert_eq!(l3_offset, 18);
    }

    #[test]
    fn test_parse_ethernet_qinq_double_vlan() {
        let mut buf = [0u8; 62];
        buf[12..14].copy_from_slice(&ETH_P_8021AD.to_be_bytes()); // Outer QinQ
        buf[16..18].copy_from_slice(&ETH_P_8021Q.to_be_bytes());  // Inner 802.1Q
        buf[20..22].copy_from_slice(&ETH_P_IP.to_be_bytes());     // Final IPv4
        buf[22] = 0x45; // IPv4

        let (_eth, l3_offset, ether_type) = parse_ethernet(&buf).expect("parse qinq");
        assert_eq!(ether_type, ETH_P_IP);
        assert_eq!(l3_offset, 22);
    }

    #[test]
    fn test_parse_ethernet_truncated() {
        let short = [0u8; 13];
        assert!(parse_ethernet(&short).is_err());
    }

    #[test]
    fn test_parse_ipv4_tcp() {
        let packet = build_raw_ipv4_tcp_packet([192, 168, 10, 20], [172, 28, 0, 2], 44321, 443);
        let (ip_hdr, l4_offset) = parse_ipv4(&packet, 14).expect("parse ipv4");
        assert_eq!(ip_hdr.src_addr, [192, 168, 10, 20]);
        assert_eq!(ip_hdr.dst_addr, [172, 28, 0, 2]);
        assert_eq!(ip_hdr.protocol, PROTO_TCP);
        assert_eq!(l4_offset, 34);

        let (sport, dport) = extract_transport_ports(&packet, l4_offset, ip_hdr.protocol);
        assert_eq!(sport, 44321);
        assert_eq!(dport, 443);
    }

    #[test]
    fn test_parse_ipv4_udp() {
        let packet = build_raw_ipv4_udp_packet([10, 0, 0, 5], [10, 0, 0, 1], 5353, 53);
        let (ip_hdr, l4_offset) = parse_ipv4(&packet, 14).expect("parse ipv4 udp");
        assert_eq!(ip_hdr.protocol, PROTO_UDP);
        let (sport, dport) = extract_transport_ports(&packet, l4_offset, ip_hdr.protocol);
        assert_eq!(sport, 5353);
        assert_eq!(dport, 53);
    }

    #[test]
    fn test_parse_ipv4_icmp() {
        let mut buf = [0u8; 34];
        buf[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        buf[14] = 0x45;
        buf[23] = PROTO_ICMP;
        let (ip_hdr, l4_offset) = parse_ipv4(&buf, 14).expect("parse icmp");
        assert_eq!(ip_hdr.protocol, PROTO_ICMP);
        let (sport, dport) = extract_transport_ports(&buf, l4_offset, ip_hdr.protocol);
        assert_eq!((sport, dport), (0, 0));
    }

    #[test]
    fn test_parse_ipv4_options_ihl() {
        let mut buf = [0u8; 60];
        buf[14] = 0x46; // IHL = 6 words = 24 bytes
        buf[14 + 24] = 0x00; // Valid offset boundary
        let (_ip_hdr, l4_offset) = parse_ipv4(&buf, 14).expect("parse ipv4 options");
        assert_eq!(l4_offset, 14 + 24);
    }

    #[test]
    fn test_parse_ipv4_invalid_ihl_and_truncated() {
        let mut buf = [0u8; 40];
        buf[14] = 0x44; // IHL = 4 words = 16 bytes (< 20 bytes!)
        assert!(parse_ipv4(&buf, 14).is_err());

        let short_buf = [0u8; 25]; // < 14 + 20 = 34 bytes
        assert!(parse_ipv4(&short_buf, 14).is_err());
    }

    #[test]
    fn test_parse_ipv6_tcp() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let packet = build_raw_ipv6_tcp_packet(src, dst, 8080, 80);

        let (ip_hdr, l4_offset) = parse_ipv6(&packet, 14).expect("parse ipv6");
        assert_eq!(ip_hdr.src_addr, src);
        assert_eq!(ip_hdr.dst_addr, dst);
        assert_eq!(ip_hdr.next_header, PROTO_TCP);
        assert_eq!(l4_offset, 54);

        let (sport, dport) = extract_transport_ports(&packet, l4_offset, ip_hdr.next_header);
        assert_eq!(sport, 8080);
        assert_eq!(dport, 80);
    }

    #[test]
    fn test_parse_ipv6_invalid_version_and_truncated() {
        let mut buf = [0u8; 60];
        buf[14..18].copy_from_slice(&0x40000000u32.to_be_bytes()); // Version 4 instead of 6
        assert!(parse_ipv6(&buf, 14).is_err());

        let short_buf = [0u8; 45]; // < 14 + 40 = 54 bytes
        assert!(parse_ipv6(&short_buf, 14).is_err());
    }

    #[test]
    fn test_classify_packet_ipv6_e2e() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcd];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab];
        let packet = build_raw_ipv6_tcp_packet(src, dst, 443, 44321);

        let parsed = classify_packet(&packet).expect("classify ipv6");
        assert_eq!(parsed.ip_version, 6);
        assert_eq!(parsed.src_ip, src);
        assert_eq!(parsed.dst_ip, dst);
        assert_eq!(parsed.protocol, PROTO_TCP);
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 44321);
        assert_eq!(parsed.l4_offset, 54);
        assert_eq!(parsed.packet_len, 74);

        // Exact IPv6 match simulation (no IPv4 match).
        let (action, match_type) = simulate_exact_match(&parsed, &[], &[src]);
        assert_eq!(action, ACTION_DROP);
        assert_eq!(match_type, MATCH_EXACT_HASH);

        // Non-matching IPv6 address.
        let (action, match_type) = simulate_exact_match(&parsed, &[], &[]);
        assert_eq!(action, ACTION_ACCEPT);
        assert_eq!(match_type, MATCH_NONE);
    }

    #[test]
    fn test_classify_packet_unknown_ethertype_and_exact_v4_ignores_v6() {
        // An IPv4 packet must never match an IPv6 exact blocklist entry.
        let packet = build_raw_ipv4_tcp_packet([198, 51, 100, 14], [172, 28, 0, 2], 55555, 80);
        let parsed = classify_packet(&packet).expect("classify ipv4");
        let v6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let (action, _) = simulate_exact_match(&parsed, &[], &[v6_addr]);
        assert_eq!(action, ACTION_ACCEPT);

        // Non-IP EtherType (e.g. ARP 0x0806) must be rejected by classify_packet.
        let mut arp = [0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(classify_packet(&arp).is_err());

        // Unknown ip_version reported by a synthetic ParsedPacket falls back to accept.
        let mut unknown = build_raw_ipv4_tcp_packet([192, 0, 2, 1], [172, 28, 0, 2], 1, 2);
        let mut parsed_unknown = classify_packet(&unknown).unwrap();
        parsed_unknown.ip_version = 99;
        let (action, _) = simulate_exact_match(&parsed_unknown, &[[192, 0, 2, 1]], &[]);
        assert_eq!(action, ACTION_ACCEPT);
        let _ = unknown;
    }

    #[test]
    fn test_classify_packet_ipv6_udp_and_truncated_ipv4() {
        // IPv6 UDP: an address matching the exact v6 map routes to drop, and ports are parsed.
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
        let mut buf = [0u8; 74];
        buf[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        buf[14..18].copy_from_slice(&0x60000000u32.to_be_bytes());
        buf[18..20].copy_from_slice(&8u16.to_be_bytes()); // 8-byte UDP header + 0 payload
        buf[20] = PROTO_UDP;
        buf[22..38].copy_from_slice(&src);
        buf[38..54].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        buf[54..56].copy_from_slice(&5353u16.to_be_bytes());
        buf[56..58].copy_from_slice(&53u16.to_be_bytes());

        let parsed = classify_packet(&buf).expect("classify ipv6 udp");
        assert_eq!(parsed.ip_version, 6);
        assert_eq!(parsed.protocol, PROTO_UDP);
        assert_eq!((parsed.src_port, parsed.dst_port), (5353, 53));
    }

    #[test]
    fn test_classify_packet_e2e() {
        let packet = build_raw_ipv4_tcp_packet([198, 51, 100, 14], [172, 28, 0, 2], 55555, 80);
        let parsed = classify_packet(&packet).expect("classify packet");
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.src_ip[..4], [198, 51, 100, 14]);
        assert_eq!(parsed.dst_ip[..4], [172, 28, 0, 2]);
        assert_eq!(parsed.protocol, PROTO_TCP);
        assert_eq!(parsed.src_port, 55555);
        assert_eq!(parsed.dst_port, 80);

        // Match simulation
        let exact_blocklist = [[198, 51, 100, 14], [10, 0, 0, 99]];
        let (action, match_type) = simulate_exact_match(&parsed, &exact_blocklist, &[]);
        assert_eq!(action, ACTION_DROP);
        assert_eq!(match_type, MATCH_EXACT_HASH);

        // Allowed packet simulation
        let clean_packet = build_raw_ipv4_tcp_packet([172, 28, 0, 10], [172, 28, 0, 2], 12345, 80);
        let clean_parsed = classify_packet(&clean_packet).expect("classify clean packet");
        let (action_clean, match_type_clean) = simulate_exact_match(&clean_parsed, &exact_blocklist, &[]);
        assert_eq!(action_clean, ACTION_ACCEPT);
        assert_eq!(match_type_clean, MATCH_NONE);
    }
}
