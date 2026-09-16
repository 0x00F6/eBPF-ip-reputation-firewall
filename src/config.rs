use crate::console::CLAP_STYLING;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XdpModeChoice {
    /// Try Native/Driver mode first, fallback to Generic (SKB) mode
    #[default]
    Auto,
    /// High-performance Driver/Native mode (requires driver support)
    Driver,
    /// Universal Generic/SKB mode (works in containers, VMs, and all NICs)
    Generic,
    /// SmartNIC Hardware offloaded mode
    Hardware,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "firewall",
    styles = CLAP_STYLING,
    author = "Firewall Team",
    version = "0.1.0",
    about = "\x1b[1;36mHigh-Performance eBPF IP Reputation Ingress Firewall in Rust\x1b[0m",
    long_about = "A production-grade \x1b[1meBPF firewall\x1b[0m using \x1b[1mAya\x1b[0m to block malicious incoming traffic \
                  at the network interface driver level via \x1b[1mXDP\x1b[0m, with exact \x1b[1mHashMap\x1b[0m, \
                  \x1b[1mLPM Trie CIDR matching\x1b[0m, and real-time \x1b[1mRing Buffer\x1b[0m telemetry."
)]
pub struct Config {
    /// Network interface to attach the XDP firewall to
    #[arg(
        short,
        long,
        env = "FIREWALL_IFACE",
        default_value = "eth0",
        help = "Network interface to attach the \x1b[1mXDP firewall\x1b[0m to (e.g. \x1b[1meth0\x1b[0m, \x1b[1mlo\x1b[0m, \x1b[1mens3\x1b[0m)"
    )]
    pub iface: String,

    /// Paths to blocklist rule files containing IP addresses and CIDR blocks
    #[arg(
        short,
        long,
        env = "FIREWALL_RULES",
        value_delimiter = ',',
        default_values_os_t = [
            PathBuf::from("rules/blocklist.txt"),
            PathBuf::from("rules/blocklist_v6.txt"),
            PathBuf::from("rules/cidr_ranges.txt")
        ],
        help = "Paths to \x1b[1mblocklist rule files\x1b[0m containing IP addresses and CIDR blocks"
    )]
    pub rules: Vec<PathBuf>,

    /// XDP attachment mode: auto, driver, generic, hardware
    #[arg(
        short,
        long,
        value_enum,
        default_value_t = XdpModeChoice::Auto,
        help = "\x1b[1mXDP attachment mode\x1b[0m: auto, driver, generic, hardware"
    )]
    pub mode: XdpModeChoice,

    /// Watch rule files for live hot-reloading without restarting the firewall
    #[arg(
        short,
        long,
        help = "Watch rule files for \x1b[1mlive hot-reloading\x1b[0m without restarting the firewall"
    )]
    pub watch: bool,

    /// Emit blocked packet telemetry logs in structured JSON format (SIEM ready)
    #[arg(
        long,
        help = "Emit blocked packet telemetry logs in structured \x1b[1mJSON format\x1b[0m (SIEM ready)"
    )]
    pub json: bool,

    /// Disable logging of individual dropped packet events to console
    #[arg(
        short = 'q',
        long,
        env = "FIREWALL_QUIET",
        default_value_t = false,
        help = "Disable logging of individual \x1b[1mdropped packet events\x1b[0m to console (recommended during high-rate benchmarks)"
    )]
    pub quiet: bool,

    /// Interval in seconds for displaying live packet throughput and drop statistics
    #[arg(
        long,
        default_value_t = 5,
        help = "Interval in seconds for displaying \x1b[1mlive packet throughput\x1b[0m and drop statistics (0 = disabled)"
    )]
    pub stats_interval: u64,

    /// Prometheus metrics HTTP listen address
    #[arg(
        long,
        env = "METRICS_LISTEN_ADDRESS",
        default_value = "0.0.0.0:9100",
        help = "\x1b[1mPrometheus metrics\x1b[0m HTTP listen address (configurable via METRICS_LISTEN_ADDRESS)"
    )]
    pub metrics_listen_addr: String,

    /// Disable Prometheus metrics HTTP exporter
    #[arg(long, help = "Disable \x1b[1mPrometheus metrics\x1b[0m HTTP exporter")]
    pub no_metrics: bool,

    /// Custom path to the compiled eBPF object file (optional)
    #[arg(
        long,
        help = "Custom path to the compiled \x1b[1meBPF object file\x1b[0m (optional)"
    )]
    pub bpf_path: Option<PathBuf>,

    /// Logging level (trace, debug, info, warn, error)
    #[arg(
        long,
        env = "RUST_LOG",
        default_value = "info",
        help = "Logging level (\x1b[1mtrace\x1b[0m, \x1b[1mdebug\x1b[0m, \x1b[1minfo\x1b[0m, \x1b[1mwarn\x1b[0m, \x1b[1merror\x1b[0m)"
    )]
    pub log_level: String,

    /// Enable FireHOL blocklists synchronization and eBPF integration (enabled by default)
    #[arg(
        long,
        env = "FIREWALL_FIREHOL",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        help = "Enable \x1b[1mFireHOL blocklists\x1b[0m synchronization and eBPF integration"
    )]
    pub firehol: bool,

    /// Disable FireHOL blocklists synchronization and eBPF integration
    #[arg(
        long,
        env = "FIREWALL_NO_FIREHOL",
        default_value_t = false,
        action = clap::ArgAction::SetTrue,
        help = "Disable \x1b[1mFireHOL blocklists\x1b[0m synchronization and eBPF integration"
    )]
    pub no_firehol: bool,

    /// Local directory for FireHOL Git repository
    #[arg(
        long,
        env = "FIREWALL_FIREHOL_DIR",
        default_value = "rules/firehol-blocklist-ipsets",
        help = "Local directory for \x1b[1mFireHOL Git repository\x1b[0m"
    )]
    pub firehol_dir: PathBuf,

    /// Remote FireHOL Git repository URL
    #[arg(
        long,
        env = "FIREWALL_FIREHOL_URL",
        default_value = "https://github.com/firehol/blocklist-ipsets",
        help = "Remote \x1b[1mFireHOL Git repository URL\x1b[0m"
    )]
    pub firehol_url: String,

    /// Target Git branch for FireHOL
    #[arg(
        long,
        env = "FIREWALL_FIREHOL_BRANCH",
        default_value = "master",
        help = "Target \x1b[1mGit branch\x1b[0m for FireHOL"
    )]
    pub firehol_branch: String,

    /// On-disk RocksDB cache directory for FireHOL imports and metadata.
    ///
    /// When set, the verbose per-file metadata and per-target contexts are persisted here
    /// (LZ4-compressed, Cap'n Proto) instead of staying resident in RAM, drastically cutting
    /// memory for large blocklist sets. Temporary import generations are removed on drop.
    #[arg(
        long,
        env = "FIREWALL_FIREHOL_CACHE_DIR",
        default_value = "cache/firehol",
        help = "\x1b[1mRocksDB\x1b[0m cache directory for heavy FireHOL metadata (reduces RAM)"
    )]
    pub firehol_cache_dir: Option<PathBuf>,

    /// Disable colored and bold output in console and logs
    #[arg(
        long,
        env = "NO_COLOR",
        default_value_t = false,
        action = clap::ArgAction::SetTrue,
        help = "Disable \x1b[1mcolored and bold output\x1b[0m in console and logs"
    )]
    pub no_color: bool,

    /// Cron expression for periodic FireHOL blocklist updates (default: every hour)
    #[arg(
        long,
        env = "FIREHOL_UPDATE_CRON",
        default_value = "0 0 * * * *",
        help = "Cron expression for \x1b[1mperiodic FireHOL updates\x1b[0m (e.g. \x1b[1m0 0 * * * *\x1b[0m)"
    )]
    pub firehol_cron: String,

    /// Disable scheduled FireHOL periodic updates via cron
    #[arg(
        long,
        env = "FIREWALL_NO_CRON",
        default_value_t = false,
        action = clap::ArgAction::SetTrue,
        help = "Disable \x1b[1mFireHOL cron periodic updates\x1b[0m"
    )]
    pub no_cron: bool,

    /// Comma-separated list of IP addresses to ignore from FireHOL blocklists
    #[arg(
        long,
        env = "FIREHOL_IGNORE_IP",
        default_value = "",
        help = "Comma-separated list of \x1b[1mIP addresses to ignore\x1b[0m from FireHOL blocklists (e.g. \x1b[1m172.28.0.3, 10.0.0.1\x1b[0m)"
    )]
    pub firehol_ignore_ip: String,
}

impl Config {
    /// Returns true if FireHOL synchronization and eBPF integration is enabled.
    pub fn is_firehol_enabled(&self) -> bool {
        self.firehol && !self.no_firehol
    }

    /// Returns true if FireHOL periodic updates via cron are enabled.
    pub fn is_cron_enabled(&self) -> bool {
        self.is_firehol_enabled() && !self.no_cron
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_firehol_enabled_by_default() {
        let config = Config::parse_from(["firewall"]);
        assert!(config.is_firehol_enabled());
        assert!(config.firehol);
        assert!(!config.no_firehol);
    }

    #[test]
    fn test_cron_config_default_and_custom() {
        let default_config = Config::parse_from(["firewall"]);
        assert_eq!(default_config.firehol_cron, "0 0 * * * *");
        assert!(!default_config.no_cron);
        assert!(default_config.is_cron_enabled());

        let custom_config = Config::parse_from(["firewall", "--firehol-cron", "0 */30 * * * *"]);
        assert_eq!(custom_config.firehol_cron, "0 */30 * * * *");
        assert!(custom_config.is_cron_enabled());

        let disabled_config = Config::parse_from(["firewall", "--no-cron"]);
        assert!(disabled_config.no_cron);
        assert!(!disabled_config.is_cron_enabled());
    }

    #[test]
    fn test_firehol_disabled_via_no_firehol_flag() {
        let config = Config::parse_from(["firewall", "--no-firehol"]);
        assert!(!config.is_firehol_enabled());
        assert!(config.no_firehol);
    }

    #[test]
    fn test_firehol_disabled_via_firehol_false() {
        let config = Config::parse_from(["firewall", "--firehol", "false"]);
        assert!(!config.is_firehol_enabled());
    }

    #[test]
    fn test_firehol_flag_without_value() {
        let config = Config::parse_from(["firewall", "--firehol", "--no-cron"]);
        assert!(config.is_firehol_enabled());
        assert!(config.no_cron);
    }
}
