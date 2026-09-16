//! Zero-copy packet crafting and RFC 1071 checksum calculation for IPv4, TCP, UDP, ICMP.

use std::net::Ipv4Addr;

/// IP Protocol numbers
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_TEST_OTHER: u8 = 253; // RFC 3692 experimental / test protocol

pub const IPV4_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
pub const ICMP_HEADER_LEN: usize = 8;

/// Reusable pre-allocated packet buffer avoiding heap allocations in high-speed benchmarks.
pub struct PacketBuffer {
    data: [u8; 1500],
    len: usize,
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuffer {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            data: [0u8; 1500],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.data.len());
        self.len = len;
    }
}

/// Calculate RFC 1071 Internet Checksum over a byte slice.
#[inline]
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let word = u16::from_be_bytes([remainder[0], 0]) as u32;
        sum += word;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Computes TCP or UDP pseudo-header sum.
#[inline]
fn pseudo_header_sum(src: [u8; 4], dst: [u8; 4], proto: u8, l4_len: u16) -> u32 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += l4_len as u32;
    sum
}

/// Calculates Layer 4 checksum incorporating the pseudo-header.
#[inline]
pub fn l4_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, l4_data: &[u8]) -> u16 {
    let mut sum = pseudo_header_sum(src, dst, proto, l4_data.len() as u16);
    let mut chunks = l4_data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let word = u16::from_be_bytes([remainder[0], 0]) as u32;
        sum += word;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let res = !(sum as u16);
    if res == 0 && proto == IPPROTO_UDP {
        0xffff
    } else {
        res
    }
}

/// Crafts an IPv4 header at `buf[0..20]` in-place.
#[inline]
pub fn write_ipv4_header(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: u8,
    identification: u16,
    payload_len: usize,
) -> usize {
    let total_len = (IPV4_HEADER_LEN + payload_len) as u16;

    buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    buf[1] = 0x00; // DSCP / ECN
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&identification.to_be_bytes());
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF (Don't Fragment) flag
    buf[8] = 64; // TTL
    buf[9] = proto;
    buf[10..12].copy_from_slice(&[0, 0]); // Checksum zeroed for computation
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let csum = internet_checksum(&buf[0..IPV4_HEADER_LEN]);
    buf[10..12].copy_from_slice(&csum.to_be_bytes());

    IPV4_HEADER_LEN
}

/// Builds a complete IPv4 + TCP SYN packet in `buf`.
pub fn build_ipv4_tcp_syn(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    id: u16,
    payload: &[u8],
) -> usize {
    let l4_len = TCP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + l4_len;
    assert!(buf.len() >= total_len, "Buffer too small for TCP packet");

    // Write TCP header
    let tcp_start = IPV4_HEADER_LEN;
    buf[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_start + 8..tcp_start + 12].copy_from_slice(&0u32.to_be_bytes()); // Ack number
    buf[tcp_start + 12] = 0x50; // Data offset: 5 (20 bytes), reserved 0
    buf[tcp_start + 13] = 0x02; // Flags: SYN
    buf[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes()); // Window size
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[tcp_start + 18..tcp_start + 20].copy_from_slice(&[0, 0]); // Urgent pointer

    if !payload.is_empty() {
        buf[tcp_start + 20..total_len].copy_from_slice(payload);
    }

    // Compute TCP checksum
    let csum = l4_checksum(
        src_ip.octets(),
        dst_ip.octets(),
        IPPROTO_TCP,
        &buf[tcp_start..total_len],
    );
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&csum.to_be_bytes());

    // Write IPv4 header
    write_ipv4_header(buf, src_ip, dst_ip, IPPROTO_TCP, id, l4_len);

    total_len
}

/// Builds a complete IPv4 + UDP packet in `buf`.
pub fn build_ipv4_udp(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    id: u16,
    payload: &[u8],
) -> usize {
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let total_len = IPV4_HEADER_LEN + (udp_len as usize);
    assert!(buf.len() >= total_len, "Buffer too small for UDP packet");

    let udp_start = IPV4_HEADER_LEN;
    buf[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&[0, 0]); // Checksum placeholder

    if !payload.is_empty() {
        buf[udp_start + 8..total_len].copy_from_slice(payload);
    }

    let csum = l4_checksum(
        src_ip.octets(),
        dst_ip.octets(),
        IPPROTO_UDP,
        &buf[udp_start..total_len],
    );
    buf[udp_start + 6..udp_start + 8].copy_from_slice(&csum.to_be_bytes());

    write_ipv4_header(buf, src_ip, dst_ip, IPPROTO_UDP, id, udp_len as usize);

    total_len
}

/// Builds a complete IPv4 + ICMP Echo Request packet in `buf`.
pub fn build_ipv4_icmp_echo(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    seq: u16,
    id: u16,
    payload: &[u8],
) -> usize {
    let icmp_len = ICMP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + icmp_len;
    assert!(buf.len() >= total_len, "Buffer too small for ICMP packet");

    let icmp_start = IPV4_HEADER_LEN;
    buf[icmp_start] = 8; // Type: Echo Request
    buf[icmp_start + 1] = 0; // Code: 0
    buf[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[icmp_start + 4..icmp_start + 6].copy_from_slice(&ident.to_be_bytes());
    buf[icmp_start + 6..icmp_start + 8].copy_from_slice(&seq.to_be_bytes());

    if !payload.is_empty() {
        buf[icmp_start + 8..total_len].copy_from_slice(payload);
    }

    let csum = internet_checksum(&buf[icmp_start..total_len]);
    buf[icmp_start + 2..icmp_start + 4].copy_from_slice(&csum.to_be_bytes());

    write_ipv4_header(buf, src_ip, dst_ip, IPPROTO_ICMP, id, icmp_len);

    total_len
}

/// Builds a complete IPv4 packet with an experimental/other protocol (e.g. 253).
pub fn build_ipv4_other(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: u8,
    id: u16,
    payload: &[u8],
) -> usize {
    let total_len = IPV4_HEADER_LEN + payload.len();
    assert!(buf.len() >= total_len, "Buffer too small for Other packet");

    if !payload.is_empty() {
        buf[IPV4_HEADER_LEN..total_len].copy_from_slice(payload);
    }

    write_ipv4_header(buf, src_ip, dst_ip, proto, id, payload.len());

    total_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc1071_checksum_simple() {
        let data = [0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06];
        let csum = internet_checksum(&data);
        assert_ne!(csum, 0);

        // Appending the checksum to the data should produce 0 (or 0xffff inverted)
        let mut full = data.to_vec();
        full.extend_from_slice(&csum.to_be_bytes());
        assert_eq!(internet_checksum(&full), 0);
    }

    #[test]
    fn test_build_ipv4_tcp_syn() {
        let mut buf = [0u8; 128];
        let src = Ipv4Addr::new(198, 51, 100, 14);
        let dst = Ipv4Addr::new(172, 28, 0, 2);
        let len = build_ipv4_tcp_syn(&mut buf, src, dst, 49152, 80, 12345, 1, b"DATA");

        assert_eq!(len, 44);
        assert_eq!(buf[0], 0x45);
        assert_eq!(buf[9], IPPROTO_TCP);
        assert_eq!(&buf[12..16], &[198, 51, 100, 14]);
        assert_eq!(&buf[16..20], &[172, 28, 0, 2]);
        assert_eq!(buf[20..22], 49152u16.to_be_bytes());
        assert_eq!(buf[22..24], 80u16.to_be_bytes());
        assert_eq!(buf[33], 0x02); // SYN flag
    }

    #[test]
    fn test_build_ipv4_udp() {
        let mut buf = [0u8; 128];
        let src = Ipv4Addr::new(10, 0, 0, 50);
        let dst = Ipv4Addr::new(172, 28, 0, 2);
        let len = build_ipv4_udp(&mut buf, src, dst, 5353, 53, 2, b"QUERY");

        assert_eq!(len, 20 + 8 + 5);
        assert_eq!(buf[9], IPPROTO_UDP);
        assert_eq!(&buf[12..16], &[10, 0, 0, 50]);
        assert_eq!(&buf[16..20], &[172, 28, 0, 2]);
    }

    #[test]
    fn test_build_ipv4_icmp_echo() {
        let mut buf = [0u8; 128];
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(172, 28, 0, 2);
        let len = build_ipv4_icmp_echo(&mut buf, src, dst, 100, 1, 3, b"PING");

        assert_eq!(len, 20 + 8 + 4);
        assert_eq!(buf[9], IPPROTO_ICMP);
        assert_eq!(buf[20], 8); // Echo Request
    }

    #[test]
    fn test_build_ipv4_other() {
        let mut buf = [0u8; 128];
        let src = Ipv4Addr::new(198, 51, 100, 14);
        let dst = Ipv4Addr::new(172, 28, 0, 2);
        let len = build_ipv4_other(&mut buf, src, dst, IPPROTO_TEST_OTHER, 4, b"CUSTOM_PAYLOAD");

        assert_eq!(len, 20 + 14);
        assert_eq!(buf[9], IPPROTO_TEST_OTHER);
    }

    #[test]
    fn test_packet_buffer_methods() {
        let mut pb = PacketBuffer::default();
        assert!(pb.is_empty());
        assert_eq!(pb.len(), 0);
        assert_eq!(pb.as_slice().len(), 0);

        pb.buffer_mut()[0] = 0xAA;
        pb.set_len(1);
        assert!(!pb.is_empty());
        assert_eq!(pb.len(), 1);
        assert_eq!(pb.as_slice(), &[0xAA]);
    }

    #[test]
    fn test_l4_checksum_odd_length_and_udp() {
        let src = [192, 168, 1, 1];
        let dst = [192, 168, 1, 2];
        let data = [1, 2, 3];
        let csum = l4_checksum(src, dst, IPPROTO_UDP, &data);
        assert_ne!(csum, 0);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        // Odd-length input exercises the zero-padded remainder word of RFC 1071.
        assert_eq!(internet_checksum(&[0x12, 0x34, 0x56]), 0x97cb);
        assert_eq!(internet_checksum(&[0xfe]), 0x01ff);
    }

    #[test]
    fn test_l4_checksum_udp_zero_translated_to_ffff() {
        // Zero pseudo-header + single 0xffec word folds to 0xffff, which per RFC 768
        // is emitted as 0xffff for UDP so it is never confused with "no checksum".
        assert_eq!(
            l4_checksum([0; 4], [0; 4], IPPROTO_UDP, &[0xff, 0xec]),
            0xffff
        );
        // TCP keeps the true one's-complement result without substitution:
        // 0xffec + proto 6 + l4 length 2 = 0xfff4 -> ~0xfff4 = 0x000b.
        assert_eq!(
            l4_checksum([0; 4], [0; 4], IPPROTO_TCP, &[0xff, 0xec]),
            0x000b
        );
    }
}
