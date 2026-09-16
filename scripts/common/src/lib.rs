//! Common library for eBPF firewall traffic generation and performance benchmarking.

pub mod console;
pub mod generator;
pub mod packet;
pub mod socket;
pub mod stats;

pub use console::*;
pub use generator::{
    FastPrng, IpPool, PacketProtocol, ProtocolChoice, DEFAULT_FIREWALL_IPV4, EXACT_BLOCKED_IPV4,
    LEGITIMATE_CONTAINER_IPV4,
};
pub use packet::{
    build_ipv4_icmp_echo, build_ipv4_other, build_ipv4_tcp_syn, build_ipv4_udp, internet_checksum,
    l4_checksum, write_ipv4_header, PacketBuffer, ICMP_HEADER_LEN, IPPROTO_ICMP, IPPROTO_TCP,
    IPPROTO_TEST_OTHER, IPPROTO_UDP, IPV4_HEADER_LEN, TCP_HEADER_LEN, UDP_HEADER_LEN,
};
pub use socket::{
    add_ip_alias, del_ip_alias, probe_tcp_connect, run_ping_check, send_udp_datagram,
    RawSocketSender,
};
pub use stats::{
    format_float_with_spaces, format_int_with_spaces, get_cpu_times, BenchmarkSummary, ThreadStats,
};
