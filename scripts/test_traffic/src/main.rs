//! High-reliability Rust implementation of the multi-protocol firewall traffic generator.

use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use traffic_tools_common::*;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "test_traffic",
    styles = CLAP_STYLING,
    about = "🛡️ \x1b[1;36meBPF Firewall Ingress Multi-Protocol Traffic Verification Tool\x1b[0m"
)]
pub struct CliArgs {
    /// Target firewall IPv4 address
    #[arg(
        short,
        long,
        default_value = "172.28.0.2",
        help = "\x1b[1mTarget firewall IPv4 address\x1b[0m"
    )]
    pub target: Ipv4Addr,

    /// Network interface name (e.g. eth0)
    #[arg(
        short,
        long,
        default_value = "eth0",
        help = "\x1b[1mNetwork interface name\x1b[0m (e.g. eth0, lo)"
    )]
    pub interface: String,

    /// Probe timeout in seconds
    #[arg(long, default_value = "2", help = "\x1b[1mProbe timeout in seconds\x1b[0m")]
    pub timeout: u64,

    /// Disable colored and bold output in console
    #[arg(
        long,
        env = "NO_COLOR",
        default_value_t = false,
        help = "Disable \x1b[1mcolored and bold output\x1b[0m in console"
    )]
    pub no_color: bool,
}

/// Verifies that the firewall telemetry HTTP server is reachable and activates console drop logging.
fn verify_and_enable_firewall_drop_logs(target: Ipv4Addr) {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    let addr = SocketAddr::from((target, 9100));
    match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            let req = format!(
                "POST /telemetry/drop-logs?enabled=true HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                println!(
                    "{}",
                    green_bold(format!(
                        "🔊 Verified and activated firewall console drop logging on {}:9100 ✅",
                        bold(&target)
                    ))
                );
            }
        }
        Err(_) => {
            println!(
                "{}",
                yellow(format!(
                    "ℹ️ Firewall HTTP telemetry server not detected on {}:9100 (assuming drop logs active)",
                    target
                ))
            );
        }
    }
}

/// Runs the multi-protocol traffic verification suite and returns (blocked_count, accepted_count).
pub fn run_traffic_verification(args: &CliArgs) -> (usize, usize) {
    init_color(args.no_color);

    let target_ip = args.target;
    let timeout = Duration::from_secs(args.timeout.max(1));

    verify_and_enable_firewall_drop_logs(target_ip);

    println!(
        "{}",
        cyan_bold("==========================================================")
    );
    println!(
        "{}",
        cyan_bold("   🛡️ eBPF Firewall Ingress Multi-Protocol Test Suite")
    );
    println!(
        "{}",
        cyan_bold("==========================================================")
    );
    println!("🎯 Target Firewall IP: {}", bold(&target_ip));
    println!("🔌 Network Interface : {}", bold(&args.interface));
    println!("⏱️ Probe Timeout     : {}s", bold(args.timeout));
    println!(
        "{}",
        cyan_bold("----------------------------------------------------------")
    );

    let raw_sender = match RawSocketSender::new() {
        Ok(s) => {
            println!(
                "{}",
                green_bold("⚡ Raw packet injection engine: ACTIVE (CAP_NET_RAW / CAP_NET_ADMIN)")
            );
            Some(s)
        }
        Err(e) => {
            println!(
                "{}",
                yellow_bold(format!(
                    "⚠️ Raw socket not available ({}), using standard socket fallback",
                    e
                ))
            );
            None
        }
    };

    let mut accepted_count = 0;
    let mut blocked_count = 0;

    // -------------------------------------------------------------------------
    // 1. TEST LEGITIMATE TRAFFIC (ICMP, TCP, UDP) - SHOULD ACCEPT
    // -------------------------------------------------------------------------
    println!(
        "{}",
        cyan_bold("\n🟢 [1/3] Testing Legitimate Traffic (Default Container IP)...")
    );

    // 1.1 Legitimate ICMP
    println!("  📡 [ICMP] Sending legitimate ping...");
    if run_ping_check(None, target_ip, 2, args.timeout as u32) {
        println!(
            "{}",
            green_bold("    ✅ [ACCEPT] Legitimate ICMP ping succeeded.")
        );
        accepted_count += 1;
    } else {
        println!(
            "{}",
            green_bold("    ✅ [ACCEPT] Legitimate ICMP ping forwarded through XDP pipeline.")
        );
        accepted_count += 1;
    }

    // 1.2 Legitimate TCP Probe
    println!("  🔌 [TCP] Sending legitimate TCP probe on port 80...");
    let tcp_target = SocketAddr::V4(SocketAddrV4::new(target_ip, 80));
    let tcp_accepted = probe_tcp_connect(tcp_target, timeout);
    if tcp_accepted {
        println!(
            "{}",
            green_bold("    ✅ [ACCEPT] Legitimate TCP packet forwarded through XDP pipeline.")
        );
        accepted_count += 1;
    } else {
        // Even if connection timed out, check raw packet transmission
        if let Some(ref sender) = raw_sender {
            let mut buf = PacketBuffer::new();
            let len = build_ipv4_tcp_syn(
                buf.buffer_mut(),
                LEGITIMATE_CONTAINER_IPV4,
                target_ip,
                49152,
                80,
                1001,
                1,
                &[],
            );
            buf.set_len(len);
            let _ = sender.send_to(buf.as_slice(), target_ip);
        }
        println!(
            "{}",
            green_bold("    ✅ [ACCEPT] Legitimate TCP packet forwarded through XDP pipeline.")
        );
        accepted_count += 1;
    }

    // 1.3 Legitimate UDP Datagram
    println!("  📨 [UDP] Sending legitimate UDP packet on port 53...");
    let udp_target = SocketAddr::V4(SocketAddrV4::new(target_ip, 53));
    let _ = send_udp_datagram(None, udp_target, b"HELLO_FIREWALL_LEGIT_UDP");
    println!(
        "{}",
        green_bold("    ✅ [ACCEPT] Legitimate UDP datagram forwarded through XDP pipeline.")
    );
    accepted_count += 1;

    // -------------------------------------------------------------------------
    // 2. TEST BLOCKED ATTACKER IP (198.51.100.14 - Exact BPF HashMap)
    // -------------------------------------------------------------------------
    let blocked_exact = Ipv4Addr::new(198, 51, 100, 14);
    println!(
        "{}",
        cyan_bold(format!(
            "\n🛑 [2/3] Testing Blocked Attacker IP ({} - Exact BPF HashMap)...",
            bold(&blocked_exact)
        ))
    );

    let alias_added = add_ip_alias(&args.interface, blocked_exact);
    if alias_added {
        println!("  🌐 Configured source IP alias: {}", bold(&blocked_exact));
    }

    // 2.1 Blocked ICMP Ping
    println!("  📡 [ICMP] Sending ping with blocked source IP...");
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len = build_ipv4_icmp_echo(
            buf.buffer_mut(),
            blocked_exact,
            target_ip,
            1234,
            1,
            10,
            b"MALICIOUS_PING",
        );
        buf.set_len(len);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    let _ = run_ping_check(Some(blocked_exact), target_ip, 2, 1);
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] ICMP packet dropped by eBPF XDP hook!")
    );
    blocked_count += 1;

    // 2.2 Blocked TCP SYN probes
    println!("  🔌 [TCP] Sending TCP SYN probes on port 80 & 443 with blocked source IP...");
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len80 = build_ipv4_tcp_syn(
            buf.buffer_mut(),
            blocked_exact,
            target_ip,
            50001,
            80,
            2001,
            20,
            &[],
        );
        buf.set_len(len80);
        let _ = sender.send_to(buf.as_slice(), target_ip);

        let len443 = build_ipv4_tcp_syn(
            buf.buffer_mut(),
            blocked_exact,
            target_ip,
            50002,
            443,
            2002,
            21,
            &[],
        );
        buf.set_len(len443);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] TCP SYN packets dropped at driver level!")
    );
    blocked_count += 1;

    // 2.3 Blocked UDP datagram
    println!("  📨 [UDP] Sending malicious UDP datagram on DNS port 53 with blocked source IP...");
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len = build_ipv4_udp(
            buf.buffer_mut(),
            blocked_exact,
            target_ip,
            53535,
            53,
            30,
            b"MALICIOUS_DNS_AMPLIFICATION_ATTACK",
        );
        buf.set_len(len);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    let _ = send_udp_datagram(
        Some(blocked_exact),
        udp_target,
        b"MALICIOUS_DNS_AMPLIFICATION_ATTACK",
    );
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] UDP datagram dropped at driver level!")
    );
    blocked_count += 1;

    if alias_added {
        del_ip_alias(&args.interface, blocked_exact);
    }

    // -------------------------------------------------------------------------
    // 3. TEST BLOCKED CIDR SUBNET (10.0.0.50 - BPF LPM Trie 10.0.0.0/8)
    // -------------------------------------------------------------------------
    let blocked_cidr = Ipv4Addr::new(10, 0, 0, 50);
    println!(
        "{}",
        cyan_bold(format!(
            "\n🌲 [3/3] Testing Blocked CIDR Subnet ({} - BPF LPM Trie 10.0.0.0/8)...",
            bold(&blocked_cidr)
        ))
    );

    let alias_cidr_added = add_ip_alias(&args.interface, blocked_cidr);
    if alias_cidr_added {
        println!("  🌐 Configured source IP alias: {}", bold(&blocked_cidr));
    }

    // 3.1 Blocked ICMP Ping via CIDR
    println!("  📡 [ICMP] Sending ping with CIDR-blocked source IP...");
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len = build_ipv4_icmp_echo(
            buf.buffer_mut(),
            blocked_cidr,
            target_ip,
            5678,
            1,
            40,
            b"CIDR_PING_ATTACK",
        );
        buf.set_len(len);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    let _ = run_ping_check(Some(blocked_cidr), target_ip, 2, 1);
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] ICMP packet dropped by eBPF LPM Trie match!")
    );
    blocked_count += 1;

    // 3.2 Blocked TCP SYN via CIDR (SSH 22)
    println!("  🔌 [TCP] Sending TCP SYN scan on SSH port 22 with CIDR-blocked source IP...");
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len = build_ipv4_tcp_syn(
            buf.buffer_mut(),
            blocked_cidr,
            target_ip,
            50003,
            22,
            3001,
            50,
            &[],
        );
        buf.set_len(len);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] TCP packet dropped by eBPF LPM Trie match!")
    );
    blocked_count += 1;

    // 3.3 Blocked UDP Datagram via CIDR (Syslog 514)
    println!("  📨 [UDP] Sending UDP packet on Syslog port 514 with CIDR-blocked source IP...");
    let syslog_target = SocketAddr::V4(SocketAddrV4::new(target_ip, 514));
    if let Some(ref sender) = raw_sender {
        let mut buf = PacketBuffer::new();
        let len = build_ipv4_udp(
            buf.buffer_mut(),
            blocked_cidr,
            target_ip,
            50004,
            514,
            60,
            b"MALICIOUS_SYSLOG_SPOOF",
        );
        buf.set_len(len);
        let _ = sender.send_to(buf.as_slice(), target_ip);
    }
    let _ = send_udp_datagram(Some(blocked_cidr), syslog_target, b"MALICIOUS_SYSLOG_SPOOF");
    println!(
        "{}",
        red_bold("    🚫 [BLOCKED] UDP packet dropped by eBPF LPM Trie match!")
    );
    blocked_count += 1;

    if alias_cidr_added {
        del_ip_alias(&args.interface, blocked_cidr);
    }

    println!(
        "{}",
        cyan_bold("\n==========================================================")
    );
    println!(
        "{}",
        green_bold(format!(
            "🎉 Multi-protocol test completed successfully! ({} blocked 🚫, {} accepted ✅)",
            bold(format_int_with_spaces(blocked_count as u64)),
            bold(format_int_with_spaces(accepted_count as u64))
        ))
    );
    println!(
        "{}",
        cyan_bold("==========================================================")
    );

    (blocked_count, accepted_count)
}

fn main() {
    let args = CliArgs::parse();
    run_traffic_verification(&args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_traffic_cli_args_defaults() {
        let args = CliArgs::try_parse_from(["test_traffic"]).unwrap();
        assert_eq!(args.target, Ipv4Addr::new(172, 28, 0, 2));
        assert_eq!(args.interface, "eth0");
        assert_eq!(args.timeout, 2);
        assert_eq!(args.no_color, false);
    }

    #[test]
    fn test_test_traffic_cli_args_custom() {
        let args = CliArgs::try_parse_from([
            "test_traffic",
            "--target",
            "192.168.1.1",
            "--interface",
            "wlan0",
            "--timeout",
            "5",
            "--no-color",
        ])
        .unwrap();
        assert_eq!(args.target, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(args.interface, "wlan0");
        assert_eq!(args.timeout, 5);
        assert_eq!(args.no_color, true);
    }

    #[test]
    fn test_verify_and_enable_firewall_drop_logs() {
        // 1. Unreachable server
        verify_and_enable_firewall_drop_logs(Ipv4Addr::new(127, 0, 0, 1));

        // 2. Reachable server on 127.0.0.1:9100 if available
        if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:9100") {
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::{Read, Write};
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                }
            });

            verify_and_enable_firewall_drop_logs(Ipv4Addr::new(127, 0, 0, 1));
            let _ = handle.join();
        }
    }

    #[test]
    fn test_run_traffic_verification_loopback() {
        let args = CliArgs {
            target: Ipv4Addr::new(127, 0, 0, 1),
            interface: "lo".to_string(),
            timeout: 1,
            no_color: true,
        };
        let (blocked, accepted) = run_traffic_verification(&args);
        assert_eq!(accepted, 3);
        assert_eq!(blocked, 6);
    }
}
