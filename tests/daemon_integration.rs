//! Process-level startup, reload, shutdown and tool tests, inside an isolated netns.
mod support;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use support::*;

struct Daemon {
    child: Child,
    log: tempfile::NamedTempFile,
}
impl Daemon {
    fn start(rules: &Path, args: &[&str]) -> Self {
        let log = tempfile::NamedTempFile::new().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_firewall"))
            .args([
                "--mode",
                "generic",
                "--no-color",
                "--no-firehol",
                "--no-cron",
                "--stats-interval",
                "0",
            ])
            .arg("--bpf-path")
            .arg(bpf_path())
            .arg("--rules")
            .arg(rules)
            .args(args)
            .env_remove("NO_COLOR")
            .env("FIREWALL_IFACE", "lo")
            .stdout(Stdio::from(log.reopen().unwrap()))
            .stderr(Stdio::from(log.reopen().unwrap()))
            .spawn()
            .unwrap();
        Self { child, log }
    }
    fn output(&self) -> String {
        fs::read_to_string(self.log.path()).unwrap()
    }
    fn wait_for(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let output = self.output();
            if output.contains(text) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "daemon exited waiting for {text}: {output}"
            );
            assert!(
                Instant::now() < deadline,
                "timeout waiting for {text}: {output}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not exit: {}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn stop(&mut self, signal: i32) {
        self.wait_for("Press Ctrl+C to stop");
        // Signal handlers are installed immediately after the readiness log.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(unsafe { libc::kill(self.child.id() as i32, signal) }, 0);
        assert!(self.wait_exit().success(), "{}", self.output());
        assert!(self.output().contains("Firewall shutdown complete"));
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn metrics_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn http(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).unwrap();
    output
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn daemon_loads_before_attach_hot_reloads_and_shuts_down() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("static.rules");
    fs::write(&rules, "192.0.2.1\n").unwrap();
    let addr = metrics_address();
    let mut daemon = Daemon::start(
        &rules,
        &["--watch", "--json", "--metrics-listen-addr", &addr],
    );
    daemon.wait_for("Rule file watcher active");
    let output = daemon.output();
    assert!(
        output.find("eBPF maps synchronized").unwrap()
            < output.find("Attaching XDP firewall hook").unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(&addr).is_err() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(http(&addr, "/metrics").contains("firewall_up 1"));
    fs::write(&rules, "192.0.2.2\n2001:db8::1\n198.51.100.0/24\n").unwrap();
    daemon.wait_for("Hot-reload complete!");
    let metrics = http(&addr, "/metrics");
    assert!(metrics.contains("firewall_map_entries"));
    assert!(daemon.output().contains("Removed: -1 stale entries"));
    // A read error during a later reload must not kill the running daemon.
    fs::remove_file(&rules).unwrap();
    fs::create_dir(&rules).unwrap();
    daemon.wait_for("Failed to parse modified rule files");
    assert!(http(&addr, "/metrics").contains("firewall_up 1"));
    daemon.stop(libc::SIGTERM);
    assert!(daemon.output().contains("Rule watcher received shutdown"));
    assert!(
        TcpStream::connect(&addr).is_err(),
        "metrics listener released"
    );
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn daemon_alternative_configuration_and_startup_failures() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("static.rules");
    fs::write(&rules, "192.0.2.1\n").unwrap();
    let mut daemon = Daemon::start(&rules, &["--quiet", "--no-metrics"]);
    daemon.wait_for("FIREWALL READY");
    daemon.stop(libc::SIGINT);
    let mut daemon = Daemon::start(&rules, &["--metrics-listen-addr", "invalid-address"]);
    daemon.wait_for("Invalid METRICS_LISTEN_ADDRESS");
    daemon.stop(libc::SIGTERM);
    // Valid ELF but an unavailable interface is a fatal attach failure.
    let mut daemon = Daemon::start(&rules, &["--iface", "missing-iface"]);
    assert_eq!(daemon.wait_exit().code(), Some(1));
    assert!(daemon.output().contains("Failed to attach eBPF XDP hook"));
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn daemon_firehol_cache_and_scheduler_start_and_stop() {
    let dir = tempfile::tempdir().unwrap();
    let repo = git2::Repository::init(dir.path().join("upstream")).unwrap();
    repo.set_head("refs/heads/feeds").unwrap();
    commit(&repo, "# Category: malware\n192.0.2.9\n2001:db8:9::1\n");
    let local = dir.path().join("checkout");
    let cache = dir.path().join("cache");
    let rules = dir.path().join("static.rules");
    fs::write(&rules, "198.51.100.9\n").unwrap();
    // Daemon::start's explicit --no-firehol/--no-cron must be removed for this configuration.
    let log = tempfile::NamedTempFile::new().unwrap();
    let addr = metrics_address();
    let child = Command::new(env!("CARGO_BIN_EXE_firewall"))
        .args([
            "--iface",
            "lo",
            "--mode",
            "auto",
            "--no-color",
            "--stats-interval",
            "1",
        ])
        .arg("--bpf-path")
        .arg(bpf_path())
        .arg("--rules")
        .arg(&rules)
        .args([
            "--firehol",
            "--firehol-url",
            repo.workdir().unwrap().to_str().unwrap(),
            "--firehol-branch",
            "feeds",
            "--firehol-ignore-ip",
            "192.0.2.10",
            "--firehol-cron",
            "0 0 0 1 1 *",
            "--metrics-listen-addr",
            &addr,
        ])
        .arg("--firehol-dir")
        .arg(&local)
        .arg("--firehol-cache-dir")
        .arg(&cache)
        .env_remove("NO_COLOR")
        .stdout(Stdio::from(log.reopen().unwrap()))
        .stderr(Stdio::from(log.reopen().unwrap()))
        .spawn()
        .unwrap();
    let mut daemon = Daemon { child, log };
    daemon.wait_for("Press Ctrl+C to stop");
    assert!(daemon.output().contains("initial rules synchronized: 2"));
    assert!(cache.is_dir());
    daemon.stop(libc::SIGTERM);
    assert!(daemon
        .output()
        .contains("FireHOL cron scheduler stopped cleanly"));
}

#[test]
#[ignore = "isolated Linux BPF integration"]
fn malformed_firehol_feed_aborts_before_attachment() {
    let dir = tempfile::tempdir().unwrap();
    let repo = git2::Repository::init(dir.path().join("upstream")).unwrap();
    repo.set_head("refs/heads/feeds").unwrap();
    commit(&repo, "192.0.2.1\ninvalid-feed-entry\n");
    let result = Command::new(env!("CARGO_BIN_EXE_firewall"))
        .args(["--iface", "lo", "--no-color", "--firehol", "--no-cron"])
        .arg("--bpf-path")
        .arg(bpf_path())
        .args([
            "--firehol-url",
            repo.workdir().unwrap().to_str().unwrap(),
            "--firehol-branch",
            "feeds",
        ])
        .arg("--firehol-dir")
        .arg(dir.path().join("checkout"))
        .arg("--firehol-cache-dir")
        .arg(dir.path().join("cache"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(
        output.contains("Aborting firewall startup (fail-safe mode)"),
        "{output}"
    );
    assert!(!output.contains("Attaching XDP firewall hook"));
    assert!(!output.contains("FIREWALL READY"));
}
