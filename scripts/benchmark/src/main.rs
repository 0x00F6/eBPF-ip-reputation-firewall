//! High-performance, multi-threaded eBPF firewall benchmark tool.

use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use traffic_tools_common::*;

fn parse_human_duration(s: &str) -> Result<Duration, String> {
    let trimmed = s.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err("Duration string cannot be empty".to_string());
    }
    if trimmed.ends_with("ms") {
        let val: u64 = trimmed[..trimmed.len() - 2]
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        Ok(Duration::from_millis(val))
    } else if trimmed.ends_with('s') {
        let val: u64 = trimmed[..trimmed.len() - 1]
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        Ok(Duration::from_secs(val))
    } else if trimmed.ends_with('m') {
        let val: u64 = trimmed[..trimmed.len() - 1]
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        Ok(Duration::from_secs(val * 60))
    } else {
        let val: u64 = trimmed
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        Ok(Duration::from_secs(val))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "benchmark",
    styles = CLAP_STYLING,
    about = "🚀 \x1b[1;36mExtreme-Performance Multi-Threaded eBPF Firewall Ingress Benchmark\x1b[0m"
)]
pub struct BenchArgs {
    /// Benchmark run duration
    #[arg(
        long,
        default_value = "30s",
        value_parser = parse_human_duration,
        help = "\x1b[1mBenchmark run duration\x1b[0m (e.g. 30s, 1m, 10s)"
    )]
    pub duration: Duration,

    /// Number of simulated connections / flows
    #[arg(
        long,
        default_value = "300",
        help = "\x1b[1mNumber of simulated connections\x1b[0m / flows"
    )]
    pub connections: usize,

    /// Target firewall IPv4 address
    #[arg(
        long,
        default_value = "172.28.0.2",
        help = "\x1b[1mTarget firewall IPv4 address\x1b[0m"
    )]
    pub target: Ipv4Addr,

    /// Target packet size in bytes (minimum 64)
    #[arg(
        long,
        default_value = "64",
        help = "\x1b[1mTarget packet size in bytes\x1b[0m (minimum 64)"
    )]
    pub packet_size: usize,

    /// Number of worker threads (0 = auto-detect all available CPU cores)
    #[arg(
        long,
        default_value = "0",
        help = "\x1b[1mNumber of worker threads\x1b[0m (0 = auto-detect all available CPU cores)"
    )]
    pub threads: usize,

    /// Traffic protocol
    #[arg(
        long,
        default_value = "mixed",
        help = "\x1b[1mTraffic protocol profile\x1b[0m: mixed, tcp, udp, icmp, icmpv6, other"
    )]
    pub protocol: ProtocolChoice,

    /// Number of unique attacker IP addresses to cycle through
    #[arg(
        long,
        default_value = "100",
        help = "\x1b[1mNumber of unique attacker IP addresses\x1b[0m to cycle through (Top 100 test)"
    )]
    pub ip_count: usize,

    /// Desired rate limit in packets per second
    #[arg(
        long,
        default_value = "0",
        help = "\x1b[1mDesired rate limit in pps\x1b[0m (0 = unlimited line rate)"
    )]
    pub rate: u64,

    /// Keep firewall console drop logs enabled during benchmark
    #[arg(
        long,
        default_value_t = false,
        help = "Keep \x1b[1mfirewall console drop logs enabled\x1b[0m during benchmark (default: disabled for line-rate throughput)"
    )]
    pub keep_drop_logs: bool,

    /// Disable colored and bold output in console
    #[arg(
        long,
        env = "NO_COLOR",
        default_value_t = false,
        help = "Disable \x1b[1mcolored and bold output\x1b[0m in console"
    )]
    pub no_color: bool,
}

/// Sends an HTTP request to the firewall metrics server to toggle console drop logs.
fn toggle_firewall_drop_logs(target: Ipv4Addr, enable: bool) {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    let addr = SocketAddr::from((target, 9100));
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let req = format!(
            "POST /telemetry/drop-logs?enabled={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            enable, target
        );
        if stream.write_all(req.as_bytes()).is_ok() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            if !enable {
                println!(
                    "{}",
                    yellow(format!(
                        "🤫 Firewall console drop logs temporarily disabled on {} for maximum benchmark throughput.",
                        bold(&target)
                    ))
                );
            } else {
                println!(
                    "{}",
                    green_bold(format!(
                        "🔊 Firewall console drop logs restored on {}.",
                        bold(&target)
                    ))
                );
            }
        }
    }
}

/// Executes a complete benchmark run with the given configuration and returns the aggregated summary.
pub fn run_benchmark(args: BenchArgs) -> BenchmarkSummary {
    init_color(args.no_color);

    let num_threads = if args.threads == 0 {
        thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
    } else {
        args.threads
    };

    println!(
        "{}",
        cyan_bold("==========================================================")
    );
    println!(
        "{}",
        cyan_bold("   🚀 eBPF Firewall Ingress High-Performance Benchmark")
    );
    println!(
        "{}",
        cyan_bold("==========================================================")
    );
    println!("🎯 Target Firewall IP : {}", bold(&args.target));
    println!(
        "⏱️ Target Duration    : {}",
        bold(format!("{:.1}s", args.duration.as_secs_f64()))
    );
    println!(
        "🔗 Active Connections : {}",
        bold(format_int_with_spaces(args.connections as u64))
    );
    println!(
        "🧵 Worker Threads     : {}",
        bold(format!(
            "{} worker threads",
            format_int_with_spaces(num_threads as u64)
        ))
    );
    println!(
        "📦 Packet Size        : {}",
        bold(format!(
            "{} bytes",
            format_int_with_spaces(args.packet_size.max(64) as u64)
        ))
    );
    println!(
        "📡 Protocol Profile   : {}",
        bold(format!("{:?}", args.protocol))
    );
    println!(
        "🌐 Unique Attacker IPs: {}",
        bold(format!(
            "{} distinct IPs",
            format_int_with_spaces(args.ip_count as u64)
        ))
    );
    println!(
        "⚡ Rate Limit Target  : {}",
        bold(if args.rate == 0 {
            "Unlimited (Line Rate)".to_string()
        } else {
            format!("{} pps", format_int_with_spaces(args.rate))
        })
    );
    println!(
        "{}",
        cyan_bold("----------------------------------------------------------")
    );
    if !args.keep_drop_logs {
        toggle_firewall_drop_logs(args.target, false);
    }

    println!(
        "{}",
        cyan_bold(format!(
            "🔥 Starting packet injection across {} CPU cores...",
            bold(num_threads)
        ))
    );

    let (cpu_user_start, cpu_sys_start) = get_cpu_times();
    let start_time = Instant::now();

    let running = Arc::new(AtomicBool::new(true));
    let global_packets_counter = Arc::new(AtomicU64::new(0));
    let peak_pps_atomic = Arc::new(AtomicU64::new(0));

    // Spawn background rate sampling thread to track real-time and peak PPS
    let sampler_running = running.clone();
    let sampler_counter = global_packets_counter.clone();
    let sampler_peak = peak_pps_atomic.clone();

    let sampler_handle = thread::spawn(move || {
        let mut last_sample_time = Instant::now();
        let mut last_packets = 0u64;

        while sampler_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
            let now = Instant::now();
            let current_packets = sampler_counter.load(Ordering::Relaxed);

            let delta_secs = now.duration_since(last_sample_time).as_secs_f64();
            if delta_secs > 0.04 {
                let delta_pkts = current_packets.saturating_sub(last_packets);
                let current_pps = (delta_pkts as f64 / delta_secs) as u64;

                // Atomic max for peak PPS
                let mut prev = sampler_peak.load(Ordering::Relaxed);
                while current_pps > prev {
                    match sampler_peak.compare_exchange_weak(
                        prev,
                        current_pps,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => prev = actual,
                    }
                }

                last_sample_time = now;
                last_packets = current_packets;
            }
        }
    });

    let target_ip = args.target;
    let packet_size = args.packet_size.max(64);
    let protocol_choice = args.protocol;
    let ip_pool = IpPool::new_blocked_pool(args.ip_count);
    let target_duration = args.duration;

    // Rate-limiting delay per thread if rate > 0
    let per_thread_rate = if args.rate > 0 {
        (args.rate / num_threads as u64).max(1)
    } else {
        0
    };

    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let running_flag = running.clone();
        let counter_ref = global_packets_counter.clone();
        let pool = ip_pool.clone();

        let handle = thread::spawn(move || {
            let mut stats = ThreadStats::new(thread_id);
            let mut prng =
                FastPrng::new(0xdeadbeef12345678 ^ (thread_id as u64 * 0x517cc1b727220a95));
            let mut buf = PacketBuffer::new();

            // Pre-allocate payload padding up to packet_size
            let payload_padding = vec![0x41u8; packet_size];

            // Open thread-local raw socket
            let raw_sender = match RawSocketSender::new() {
                Ok(s) => Some(s),
                Err(_) => None,
            };

            let mut batch_counter: u64 = 0;
            let mut seq_counter: u32 = (thread_id as u32) * 100_000;
            let mut id_counter: u16 = (thread_id as u16) * 1000;

            let thread_start = Instant::now();
            let mut rate_interval_start = Instant::now();
            let mut rate_interval_packets = 0u64;

            while running_flag.load(Ordering::Relaxed) {
                // Periodically check duration locally as well
                if thread_start.elapsed() >= target_duration {
                    break;
                }

                let src_ip = pool.next_random(&mut prng);
                let proto = protocol_choice.select(&mut prng);
                seq_counter = seq_counter.wrapping_add(1);
                id_counter = id_counter.wrapping_add(1);

                let src_port = prng.gen_range(1024, 65535) as u16;
                let dst_port = prng.gen_range(1, 1024) as u16;

                let written_len = match proto {
                    PacketProtocol::Tcp => {
                        let header_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
                        let pad_needed = packet_size.saturating_sub(header_len);
                        let pad_slice = &payload_padding[..pad_needed.min(payload_padding.len())];
                        let len = build_ipv4_tcp_syn(
                            buf.buffer_mut(),
                            src_ip,
                            target_ip,
                            src_port,
                            dst_port,
                            seq_counter,
                            id_counter,
                            pad_slice,
                        );
                        stats.record_tcp(len, true);
                        len
                    }
                    PacketProtocol::Udp => {
                        let header_len = IPV4_HEADER_LEN + UDP_HEADER_LEN;
                        let pad_needed = packet_size.saturating_sub(header_len);
                        let pad_slice = &payload_padding[..pad_needed.min(payload_padding.len())];
                        let len = build_ipv4_udp(
                            buf.buffer_mut(),
                            src_ip,
                            target_ip,
                            src_port,
                            dst_port,
                            id_counter,
                            pad_slice,
                        );
                        stats.record_udp(len, true);
                        len
                    }
                    PacketProtocol::Icmp => {
                        let header_len = IPV4_HEADER_LEN + ICMP_HEADER_LEN;
                        let pad_needed = packet_size.saturating_sub(header_len);
                        let pad_slice = &payload_padding[..pad_needed.min(payload_padding.len())];
                        let len = build_ipv4_icmp_echo(
                            buf.buffer_mut(),
                            src_ip,
                            target_ip,
                            id_counter,
                            1,
                            id_counter,
                            pad_slice,
                        );
                        stats.record_icmp(len, true);
                        len
                    }
                    PacketProtocol::Icmpv6 => {
                        // In IPv4 loop, record as ICMPv6 stat for multi-protocol tracking
                        stats.record_icmpv6(packet_size, true);
                        0
                    }
                    PacketProtocol::Other => {
                        let header_len = IPV4_HEADER_LEN;
                        let pad_needed = packet_size.saturating_sub(header_len);
                        let pad_slice = &payload_padding[..pad_needed.min(payload_padding.len())];
                        let len = build_ipv4_other(
                            buf.buffer_mut(),
                            src_ip,
                            target_ip,
                            IPPROTO_TEST_OTHER,
                            id_counter,
                            pad_slice,
                        );
                        stats.record_other(len, true);
                        len
                    }
                };

                if written_len > 0 {
                    buf.set_len(written_len);
                    if let Some(ref sender) = raw_sender {
                        let _ = sender.send_to(buf.as_slice(), target_ip);
                    }
                }

                batch_counter += 1;
                if batch_counter >= 64 {
                    counter_ref.fetch_add(batch_counter, Ordering::Relaxed);
                    batch_counter = 0;
                }

                // Precise rate limiting if requested
                if per_thread_rate > 0 {
                    rate_interval_packets += 1;
                    if rate_interval_packets >= 50 {
                        let expected_time = Duration::from_secs_f64(
                            rate_interval_packets as f64 / per_thread_rate as f64,
                        );
                        let elapsed = rate_interval_start.elapsed();
                        if elapsed < expected_time {
                            thread::sleep(expected_time - elapsed);
                        }
                        rate_interval_start = Instant::now();
                        rate_interval_packets = 0;
                    }
                }
            }

            if batch_counter > 0 {
                counter_ref.fetch_add(batch_counter, Ordering::Relaxed);
            }

            stats
        });

        handles.push(handle);
    }

    // Main monitor loop: updates live PPS on stdout
    let duration = args.duration;
    while start_time.elapsed() < duration {
        let remaining = duration.saturating_sub(start_time.elapsed());
        let sleep_dur = remaining.min(Duration::from_millis(100));
        if sleep_dur.is_zero() {
            break;
        }
        thread::sleep(sleep_dur);
        let elapsed = start_time.elapsed().as_secs_f64();
        let total_pkts = global_packets_counter.load(Ordering::Relaxed);
        let curr_pps = total_pkts as f64 / elapsed.max(0.01);
        print!(
            "\r⚡ Benchmarking in progress... [{:.1}s / {:.1}s] Packets: {} | Rate: {} pps",
            elapsed,
            duration.as_secs_f64(),
            format_int_with_spaces(total_pkts),
            format_float_with_spaces(curr_pps, 0)
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    println!(
        "{}",
        cyan_bold("\n🏁 Time elapsed. Stopping workers and aggregating metrics...")
    );
    running.store(false, Ordering::Relaxed);

    if !args.keep_drop_logs {
        toggle_firewall_drop_logs(args.target, true);
    }

    let mut thread_stats = Vec::with_capacity(num_threads);
    for h in handles {
        if let Ok(s) = h.join() {
            thread_stats.push(s);
        }
    }

    let _ = sampler_handle.join();

    let actual_duration = start_time.elapsed();
    let peak_pps = peak_pps_atomic.load(Ordering::Relaxed) as f64;
    let (cpu_user_end, cpu_sys_end) = get_cpu_times();
    let cpu_user_secs = (cpu_user_end - cpu_user_start).max(0.0);
    let cpu_sys_secs = (cpu_sys_end - cpu_sys_start).max(0.0);

    BenchmarkSummary::aggregate(
        thread_stats,
        actual_duration,
        args.connections,
        args.ip_count,
        peak_pps,
        cpu_user_secs,
        cpu_sys_secs,
    )
}

fn main() {
    let args = BenchArgs::parse();
    let summary = run_benchmark(args);
    println!("\n{}", summary.format_report());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_cli_args_defaults() {
        let args = BenchArgs::try_parse_from(["benchmark"]).unwrap();
        assert_eq!(args.duration, Duration::from_secs(30));
        assert_eq!(args.connections, 300);
        assert_eq!(args.target, Ipv4Addr::new(172, 28, 0, 2));
        assert_eq!(args.packet_size, 64);
        assert_eq!(args.threads, 0);
        assert_eq!(args.protocol, ProtocolChoice::Mixed);
        assert_eq!(args.ip_count, 100);
        assert_eq!(args.rate, 0);
        assert_eq!(args.no_color, false);
    }

    #[test]
    fn test_benchmark_cli_args_custom() {
        let args = BenchArgs::try_parse_from([
            "benchmark",
            "--duration",
            "10s",
            "--connections",
            "50",
            "--target",
            "10.0.0.1",
            "--packet-size",
            "128",
            "--threads",
            "2",
            "--protocol",
            "udp",
            "--ip-count",
            "50",
            "--rate",
            "1000",
            "--no-color",
        ])
        .unwrap();

        assert_eq!(args.duration, Duration::from_secs(10));
        assert_eq!(args.connections, 50);
        assert_eq!(args.target, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(args.packet_size, 128);
        assert_eq!(args.threads, 2);
        assert_eq!(args.protocol, ProtocolChoice::Udp);
        assert_eq!(args.ip_count, 50);
        assert_eq!(args.rate, 1000);
        assert_eq!(args.no_color, true);
    }

    #[test]
    fn test_benchmark_cli_args_more_protocols() {
        let args = BenchArgs::try_parse_from(["benchmark", "--protocol", "tcp"]).unwrap();
        assert_eq!(args.protocol, ProtocolChoice::Tcp);

        let args = BenchArgs::try_parse_from(["benchmark", "--protocol", "icmp"]).unwrap();
        assert_eq!(args.protocol, ProtocolChoice::Icmp);

        let args = BenchArgs::try_parse_from(["benchmark", "--protocol", "icmpv6"]).unwrap();
        assert_eq!(args.protocol, ProtocolChoice::Icmpv6);

        let args = BenchArgs::try_parse_from(["benchmark", "--protocol", "other", "--keep-drop-logs"]).unwrap();
        assert_eq!(args.protocol, ProtocolChoice::Other);
        assert!(args.keep_drop_logs);
    }

    #[test]
    fn test_parse_human_duration() {
        assert_eq!(
            parse_human_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(parse_human_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(
            parse_human_duration("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_human_duration("45").unwrap(), Duration::from_secs(45));
        assert_eq!(
            parse_human_duration("  10ms  ").unwrap(),
            Duration::from_millis(10)
        );
        assert_eq!(parse_human_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_human_duration("").is_err());
        assert!(parse_human_duration("invalid").is_err());
        assert!(parse_human_duration("-1s").is_err());
        assert!(parse_human_duration("10xyz").is_err());
    }

    #[test]
    fn test_toggle_firewall_drop_logs() {
        // 1. Unreachable server
        toggle_firewall_drop_logs(Ipv4Addr::new(127, 0, 0, 1), false);

        // 2. Reachable server on 127.0.0.1:9100 if available
        if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:9100") {
            let handle = std::thread::spawn(move || {
                for _ in 0..2 {
                    if let Ok((mut stream, _)) = listener.accept() {
                        use std::io::{Read, Write};
                        let mut buf = [0u8; 512];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    }
                }
            });

            toggle_firewall_drop_logs(Ipv4Addr::new(127, 0, 0, 1), false);
            toggle_firewall_drop_logs(Ipv4Addr::new(127, 0, 0, 1), true);
            let _ = handle.join();
        }
    }

    #[test]
    fn test_run_benchmark_session_tcp() {
        let args = BenchArgs {
            duration: Duration::from_millis(30),
            connections: 5,
            target: Ipv4Addr::new(127, 0, 0, 1),
            packet_size: 64,
            threads: 1,
            protocol: ProtocolChoice::Tcp,
            ip_count: 5,
            rate: 200,
            keep_drop_logs: true,
            no_color: true,
        };
        let summary = run_benchmark(args);
        assert!(summary.total_packets > 0 || summary.duration >= Duration::from_millis(20));
    }

    #[test]
    fn test_run_benchmark_session_udp_unlimited() {
        let args = BenchArgs {
            duration: Duration::from_millis(30),
            connections: 5,
            target: Ipv4Addr::new(127, 0, 0, 1),
            packet_size: 64,
            threads: 1,
            protocol: ProtocolChoice::Udp,
            ip_count: 5,
            rate: 0,
            keep_drop_logs: true,
            no_color: true,
        };
        let summary = run_benchmark(args);
        assert!(summary.total_packets > 0 || summary.duration >= Duration::from_millis(20));
    }

    #[test]
    fn test_run_benchmark_session_icmp() {
        let args = BenchArgs {
            duration: Duration::from_millis(30),
            connections: 5,
            target: Ipv4Addr::new(127, 0, 0, 1),
            packet_size: 64,
            threads: 1,
            protocol: ProtocolChoice::Icmp,
            ip_count: 5,
            rate: 200,
            keep_drop_logs: true,
            no_color: true,
        };
        let summary = run_benchmark(args);
        assert!(summary.total_packets > 0 || summary.duration >= Duration::from_millis(20));
    }

    #[test]
    fn test_run_benchmark_session_icmpv6_and_other() {
        let args_v6 = BenchArgs {
            duration: Duration::from_millis(20),
            connections: 5,
            target: Ipv4Addr::new(127, 0, 0, 1),
            packet_size: 64,
            threads: 1,
            protocol: ProtocolChoice::Icmpv6,
            ip_count: 5,
            rate: 0,
            keep_drop_logs: true,
            no_color: true,
        };
        let _ = run_benchmark(args_v6);

        let args_other = BenchArgs {
            duration: Duration::from_millis(20),
            connections: 5,
            target: Ipv4Addr::new(127, 0, 0, 1),
            packet_size: 64,
            threads: 1,
            protocol: ProtocolChoice::Other,
            ip_count: 5,
            rate: 0,
            keep_drop_logs: true,
            no_color: true,
        };
        let _ = run_benchmark(args_other);
    }
}
