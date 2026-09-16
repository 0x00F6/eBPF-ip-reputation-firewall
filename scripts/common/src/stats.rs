//! High-performance benchmark telemetry, thread aggregation, and report formatting.

use crate::console::*;
use std::time::Duration;

/// Formats an unsigned integer with space thousand separators (e.g. 45680888 -> "45 680 888").
pub fn format_int_with_spaces(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut parts = Vec::new();
    while n > 0 {
        let rem = n % 1000;
        n /= 1000;
        if n > 0 {
            parts.push(format!("{:03}", rem));
        } else {
            parts.push(format!("{}", rem));
        }
    }
    parts.reverse();
    parts.join(" ")
}

/// Formats a floating-point number with space thousand separators on the integer part.
/// e.g. 1310100.06 with decimals=2 -> "1 310 100.06"
pub fn format_float_with_spaces(val: f64, decimals: usize) -> String {
    if val.is_nan() || val.is_infinite() {
        return format!("{val}");
    }
    let int_part = val.trunc().abs() as u64;
    let sign = if val < 0.0 { "-" } else { "" };
    let formatted_int = format_int_with_spaces(int_part);
    if decimals == 0 {
        format!("{sign}{formatted_int}")
    } else {
        let frac_str = format!("{:.prec$}", val.fract().abs(), prec = decimals);
        let frac_part = frac_str.strip_prefix("0.").unwrap_or(&frac_str);
        format!("{sign}{formatted_int}.{frac_part}")
    }
}

/// Thread-local metrics counter without lock contention.
#[repr(align(64))]
#[derive(Debug, Clone, Default)]
pub struct ThreadStats {
    pub thread_id: usize,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub icmpv6_packets: u64,
    pub other_packets: u64,
    pub expected_dropped: u64,
    pub expected_accepted: u64,
    pub errors: u64,
}

impl ThreadStats {
    pub fn new(thread_id: usize) -> Self {
        Self {
            thread_id,
            ..Default::default()
        }
    }

    #[inline(always)]
    pub fn record_tcp(&mut self, bytes: usize, dropped: bool) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.tcp_packets += 1;
        if dropped {
            self.expected_dropped += 1;
        } else {
            self.expected_accepted += 1;
        }
    }

    #[inline(always)]
    pub fn record_udp(&mut self, bytes: usize, dropped: bool) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.udp_packets += 1;
        if dropped {
            self.expected_dropped += 1;
        } else {
            self.expected_accepted += 1;
        }
    }

    #[inline(always)]
    pub fn record_icmp(&mut self, bytes: usize, dropped: bool) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.icmp_packets += 1;
        if dropped {
            self.expected_dropped += 1;
        } else {
            self.expected_accepted += 1;
        }
    }

    #[inline(always)]
    pub fn record_icmpv6(&mut self, bytes: usize, dropped: bool) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.icmpv6_packets += 1;
        if dropped {
            self.expected_dropped += 1;
        } else {
            self.expected_accepted += 1;
        }
    }

    #[inline(always)]
    pub fn record_other(&mut self, bytes: usize, dropped: bool) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.other_packets += 1;
        if dropped {
            self.expected_dropped += 1;
        } else {
            self.expected_accepted += 1;
        }
    }

    #[inline(always)]
    pub fn record_error(&mut self) {
        self.errors += 1;
    }
}

/// Aggregated multi-threaded benchmark summary.
#[derive(Debug, Clone)]
pub struct BenchmarkSummary {
    pub duration: Duration,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub expected_dropped: u64,
    pub expected_accepted: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub icmpv6_packets: u64,
    pub other_packets: u64,
    pub errors: u64,
    pub threads: usize,
    pub connections: usize,
    pub unique_ips: usize,
    pub avg_pps: f64,
    pub peak_pps: f64,
    pub throughput_mbps: f64,
    pub throughput_gbps: f64,
    pub cpu_user_secs: f64,
    pub cpu_sys_secs: f64,
    pub thread_breakdowns: Vec<ThreadStats>,
}

impl BenchmarkSummary {
    /// Aggregates per-thread stats and computes bandwidth / rates.
    pub fn aggregate(
        threads: Vec<ThreadStats>,
        duration: Duration,
        connections: usize,
        unique_ips: usize,
        peak_pps: f64,
        cpu_user_secs: f64,
        cpu_sys_secs: f64,
    ) -> Self {
        let num_threads = threads.len();
        let mut total_packets = 0u64;
        let mut total_bytes = 0u64;
        let mut expected_dropped = 0u64;
        let mut expected_accepted = 0u64;
        let mut tcp_packets = 0u64;
        let mut udp_packets = 0u64;
        let mut icmp_packets = 0u64;
        let mut icmpv6_packets = 0u64;
        let mut other_packets = 0u64;
        let mut errors = 0u64;

        for t in &threads {
            total_packets += t.packets_sent;
            total_bytes += t.bytes_sent;
            expected_dropped += t.expected_dropped;
            expected_accepted += t.expected_accepted;
            tcp_packets += t.tcp_packets;
            udp_packets += t.udp_packets;
            icmp_packets += t.icmp_packets;
            icmpv6_packets += t.icmpv6_packets;
            other_packets += t.other_packets;
            errors += t.errors;
        }

        let secs = duration.as_secs_f64().max(0.0001);
        let avg_pps = (total_packets as f64) / secs;
        let total_bits = (total_bytes as f64) * 8.0;
        let throughput_mbps = (total_bits / secs) / 1_000_000.0;
        let throughput_gbps = throughput_mbps / 1000.0;
        let effective_peak_pps = peak_pps.max(avg_pps);

        Self {
            duration,
            total_packets,
            total_bytes,
            expected_dropped,
            expected_accepted,
            tcp_packets,
            udp_packets,
            icmp_packets,
            icmpv6_packets,
            other_packets,
            errors,
            threads: num_threads,
            connections,
            unique_ips,
            avg_pps,
            peak_pps: effective_peak_pps,
            throughput_mbps,
            throughput_gbps,
            cpu_user_secs,
            cpu_sys_secs,
            thread_breakdowns: threads,
        }
    }

    /// Formats total bytes into human-readable representation with spaces.
    pub fn format_bytes(bytes: u64) -> String {
        const KIB: f64 = 1024.0;
        const MIB: f64 = 1024.0 * 1024.0;
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

        let b = bytes as f64;
        let bytes_sp = format_int_with_spaces(bytes);
        if b >= GIB {
            format!("{:.2} GiB ({} bytes)", b / GIB, bytes_sp)
        } else if b >= MIB {
            format!("{:.2} MiB ({} bytes)", b / MIB, bytes_sp)
        } else if b >= KIB {
            format!("{:.2} KiB ({} bytes)", b / KIB, bytes_sp)
        } else {
            format!("{} bytes", bytes_sp)
        }
    }

    /// Renders the comprehensive performance report in English with numbers formatted with spaces.
    pub fn format_report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}\n",
            cyan_bold("==========================================================")
        ));
        out.push_str(&format!(
            "{}\n",
            cyan_bold("          🚀 Benchmark completed successfully")
        ));
        out.push_str(&format!(
            "{}\n",
            cyan_bold("==========================================================")
        ));

        out.push_str(&format!(
            "⏱️ Duration                    : {}\n",
            bold(format!("{:.2}s", self.duration.as_secs_f64()))
        ));
        out.push_str(&format!(
            "📦 Packets sent                : {}\n",
            bold(format!(
                "{} packets",
                format_int_with_spaces(self.total_packets)
            ))
        ));
        let drop_pct = if self.total_packets > 0 {
            (self.expected_dropped as f64 / self.total_packets as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "🚫 Packets expected to be dropped : {}\n",
            yellow_bold(format!(
                "{} packets ({:.1}%)",
                format_int_with_spaces(self.expected_dropped),
                drop_pct
            ))
        ));
        out.push_str(&format!(
            "📊 Packets per second (avg)    : {}\n",
            bold(format!("{} pps", format_float_with_spaces(self.avg_pps, 2)))
        ));
        out.push_str(&format!(
            "📈 Packets per second (peak)   : {}\n",
            bold(format!(
                "{} pps",
                format_float_with_spaces(self.peak_pps, 2)
            ))
        ));
        out.push_str(&format!(
            "💾 Total bytes sent            : {}\n",
            bold(Self::format_bytes(self.total_bytes))
        ));
        out.push_str(&format!(
            "🌐 Bandwidth / throughput      : {}\n",
            bold(format!(
                "{} Mbit/s ({} Gbit/s)",
                format_float_with_spaces(self.throughput_mbps, 2),
                format_float_with_spaces(self.throughput_gbps, 4)
            ))
        ));
        out.push_str(&format!(
            "🔗 Number of connections       : {}\n",
            bold(format_int_with_spaces(self.connections as u64))
        ));
        out.push_str(&format!(
            "🧵 Number of threads           : {}\n",
            bold(format_int_with_spaces(self.threads as u64))
        ));
        out.push_str(&format!(
            "🌐 Unique attacker IPs tested  : {}\n",
            bold(format!(
                "{} IPs",
                format_int_with_spaces(self.unique_ips as u64)
            ))
        ));

        out.push_str(&format!(
            "{}\n",
            cyan_bold("----------------------------------------------------------")
        ));
        out.push_str(&format!("{}\n", cyan_bold("📡 Protocol Breakdown:")));

        let pct = |count: u64| -> f64 {
            if self.total_packets > 0 {
                (count as f64 / self.total_packets as f64) * 100.0
            } else {
                0.0
            }
        };

        out.push_str(&format!(
            "   📡 TCP packets              : {}\n",
            bold(format!(
                "{} ({:.1}%)",
                format_int_with_spaces(self.tcp_packets),
                pct(self.tcp_packets)
            ))
        ));
        out.push_str(&format!(
            "   📡 UDP packets              : {}\n",
            bold(format!(
                "{} ({:.1}%)",
                format_int_with_spaces(self.udp_packets),
                pct(self.udp_packets)
            ))
        ));
        out.push_str(&format!(
            "   📡 ICMP packets             : {}\n",
            bold(format!(
                "{} ({:.1}%)",
                format_int_with_spaces(self.icmp_packets),
                pct(self.icmp_packets)
            ))
        ));
        if self.icmpv6_packets > 0 {
            out.push_str(&format!(
                "   📡 ICMPv6 packets           : {}\n",
                bold(format!(
                    "{} ({:.1}%)",
                    format_int_with_spaces(self.icmpv6_packets),
                    pct(self.icmpv6_packets)
                ))
            ));
        }
        out.push_str(&format!(
            "   📡 Other packets (raw IP)   : {}\n",
            bold(format!(
                "{} ({:.1}%)",
                format_int_with_spaces(self.other_packets),
                pct(self.other_packets)
            ))
        ));
        let err_str = format_int_with_spaces(self.errors);
        if self.errors > 0 {
            out.push_str(&format!(
                "❌ Errors                      : {}\n",
                red_bold(err_str)
            ));
        } else {
            out.push_str(&format!(
                "❌ Errors                      : {}\n",
                bold(err_str)
            ));
        }

        out.push_str(&format!(
            "{}\n",
            cyan_bold("----------------------------------------------------------")
        ));
        out.push_str(&format!(
            "{}\n",
            cyan_bold("🧵 Per-Thread Packet Distribution:")
        ));
        for t in &self.thread_breakdowns {
            out.push_str(&format!(
                "   🧵 Thread #{:02}                : {}\n",
                t.thread_id,
                bold(format!(
                    "{} packets ({})",
                    format_int_with_spaces(t.packets_sent),
                    Self::format_bytes(t.bytes_sent)
                ))
            ));
        }

        out.push_str(&format!(
            "{}\n",
            cyan_bold("----------------------------------------------------------")
        ));
        out.push_str(&format!(
            "⚙️ CPU Resource Consumption    : {}\n",
            bold(format!(
                "User: {:.2}s | System: {:.2}s (Total: {:.2}s)",
                self.cpu_user_secs,
                self.cpu_sys_secs,
                self.cpu_user_secs + self.cpu_sys_secs
            ))
        ));
        out.push_str(&format!(
            "{}\n",
            cyan_bold("==========================================================")
        ));

        out
    }
}

/// Reads current process CPU time using `libc::getrusage`.
pub fn get_cpu_times() -> (f64, f64) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 {
        let user = usage.ru_utime.tv_sec as f64 + (usage.ru_utime.tv_usec as f64 / 1_000_000.0);
        let sys = usage.ru_stime.tv_sec as f64 + (usage.ru_stime.tv_usec as f64 / 1_000_000.0);
        (user, sys)
    } else {
        (0.0, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_int_with_spaces() {
        assert_eq!(format_int_with_spaces(0), "0");
        assert_eq!(format_int_with_spaces(9), "9");
        assert_eq!(format_int_with_spaces(999), "999");
        assert_eq!(format_int_with_spaces(1000), "1 000");
        assert_eq!(format_int_with_spaces(45680888), "45 680 888");
        assert_eq!(format_int_with_spaces(1000000), "1 000 000");
        assert_eq!(format_int_with_spaces(1234567890), "1 234 567 890");
    }

    #[test]
    fn test_format_float_with_spaces() {
        assert_eq!(format_float_with_spaces(0.0, 2), "0.00");
        assert_eq!(format_float_with_spaces(1310100.06, 2), "1 310 100.06");
        assert_eq!(format_float_with_spaces(0.6708, 4), "0.6708");
        assert_eq!(format_float_with_spaces(1440204.0, 0), "1 440 204");
    }

    #[test]
    fn test_thread_stats_recording() {
        let mut t = ThreadStats::new(0);
        t.record_tcp(64, true);
        t.record_udp(128, true);
        t.record_icmp(32, false);
        t.record_other(64, true);
        t.record_error();

        assert_eq!(t.packets_sent, 4);
        assert_eq!(t.bytes_sent, 288);
        assert_eq!(t.tcp_packets, 1);
        assert_eq!(t.udp_packets, 1);
        assert_eq!(t.icmp_packets, 1);
        assert_eq!(t.other_packets, 1);
        assert_eq!(t.expected_dropped, 3);
        assert_eq!(t.expected_accepted, 1);
        assert_eq!(t.errors, 1);
    }

    #[test]
    fn test_multithread_aggregation_and_throughput() {
        let mut t0 = ThreadStats::new(0);
        t0.record_tcp(100, true);
        t0.record_tcp(100, true);

        let mut t1 = ThreadStats::new(1);
        t1.record_udp(200, true);
        t1.record_icmp(100, false);

        let duration = Duration::from_secs(2);
        let summary = BenchmarkSummary::aggregate(vec![t0, t1], duration, 50, 10, 5.0, 0.1, 0.2);

        assert_eq!(summary.total_packets, 4);
        assert_eq!(summary.total_bytes, 500);
        assert_eq!(summary.expected_dropped, 3);
        assert_eq!(summary.expected_accepted, 1);
        assert_eq!(summary.threads, 2);
        assert_eq!(summary.connections, 50);
        assert_eq!(summary.unique_ips, 10);
        assert_eq!(summary.avg_pps, 2.0);
        assert_eq!(summary.peak_pps, 5.0);

        // 500 bytes * 8 bits = 4000 bits. 4000 / 2s = 2000 bits/s = 0.002 Mbit/s
        assert!((summary.throughput_mbps - 0.002).abs() < 1e-6);

        let report = summary.format_report();
        assert!(report.contains("🚀 Benchmark completed"));
        assert!(report.contains("TCP packets"));
        assert!(report.contains("UDP packets"));
        assert!(report.contains("ICMP packets"));
        assert!(report.contains("4 packets"));
    }

    #[test]
    fn test_stats_edge_cases_and_icmpv6() {
        let mut t = ThreadStats::new(1);
        t.record_icmpv6(64, true);
        t.record_error();
        assert_eq!(t.icmpv6_packets, 1);
        assert_eq!(t.errors, 1);

        // format_bytes GiB, MiB, KiB
        assert!(BenchmarkSummary::format_bytes(1024 * 1024 * 1024 * 2).contains("GiB"));
        assert!(BenchmarkSummary::format_bytes(1024 * 1024 * 5).contains("MiB"));
        assert!(BenchmarkSummary::format_bytes(1024 * 10).contains("KiB"));

        // format_float_with_spaces edge cases
        assert_eq!(format_float_with_spaces(f64::NAN, 2), "NaN");
        assert_eq!(format_float_with_spaces(f64::INFINITY, 2), "inf");
        assert_eq!(format_float_with_spaces(-42.5, 1), "-42.5");

        // get_cpu_times
        let (u, s) = get_cpu_times();
        assert!(u >= 0.0);
        assert!(s >= 0.0);

        // Summary report with icmpv6 and errors
        let summary = BenchmarkSummary::aggregate(vec![t], Duration::from_secs(1), 1, 1, 0.0, u, s);
        let rep = summary.format_report();
        assert!(rep.contains("ICMPv6 packets"));
        assert!(rep.contains("Errors"));
    }

    #[test]
    fn test_accepted_counter_branches_and_zero_totals() {
        // Exercise the dropped=false (accepted) branches for every protocol variant.
        let mut t = ThreadStats::new(0);
        t.record_tcp(100, false);
        t.record_udp(200, false);
        t.record_icmp(50, false);
        t.record_icmpv6(75, false);
        t.record_other(25, false);
        assert_eq!(t.expected_accepted, 5);
        assert_eq!(t.expected_dropped, 0);
        assert_eq!(t.packets_sent, 5);

        // An empty aggregation triggers the zero-total percentage paths (drop_pct = 0.0,
        // pct closure returns 0.0, division-safe branch for 0 packets).
        let empty_summary = BenchmarkSummary::aggregate(vec![], Duration::from_secs(1), 0, 0, 0.0, 0.0, 0.0);
        assert_eq!(empty_summary.total_packets, 0);
        let report = empty_summary.format_report();
        assert!(report.contains("0 packets"));
        // Zero percentages are printed without NaN/inf.
        assert!(!report.contains("NaN"));
        assert!(!report.contains("inf"));
    }
}
