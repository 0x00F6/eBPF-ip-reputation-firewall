use clap::Parser;
use firewall_lib::{
    cache_rocksdb::CacheRocksDb,
    config::Config,
    console::*,
    firehol::{
        execute_firehol_sync, FireholBlockList, FireholConfig, FireholScheduler, FireholSyncOutcome,
    },
    loader::{RuleLoader, StaticRuleRegistry},
    maps::MapManager,
    metrics::{MetricsServer, PrometheusMetrics},
    ringbuf::RingBufConsumer,
    stats::StatsReporter,
    xdp::XdpFirewall,
};
use notify::{event::ModifyKind, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::atomic::AtomicBool,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Listen for termination signals (SIGINT / Ctrl+C or SIGTERM)
#[cfg(unix)]
async fn wait_for_shutdown() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

/// Compute a quick fingerprint of the rule files (mtime and size) to avoid false hot-reload triggers.
fn compute_fingerprint(paths: &[PathBuf]) -> Vec<(PathBuf, Option<SystemTime>, u64)> {
    paths
        .iter()
        .map(|p| {
            let meta = std::fs::metadata(p).ok();
            let mtime = meta.as_ref().and_then(|m| m.modified().ok());
            let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            (p.clone(), mtime, len)
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    // 1. Initialize Console styling and Tracing Subscriber
    firewall_lib::console::init_color(config.no_color);
    let level = Level::from_str(&config.log_level).unwrap_or(Level::INFO);
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy()
        .add_directive("tokio_cron_scheduler=warn".parse().unwrap())
        .add_directive("croner=warn".parse().unwrap());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_ansi(!firewall_lib::console::is_no_color())
        .with_ansi_sanitization(false)
        .finish();
    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Failed to set tracing subscriber: {e}");
        std::process::exit(1);
    }

    info!(
        "{}",
        cyan_bold("==================================================================")
    );
    info!(
        "{}",
        cyan_bold("🛡️  High-Performance eBPF IP Reputation Firewall (Aya / XDP) 🦀")
    );
    info!(
        "{}",
        cyan_bold("==================================================================")
    );
    info!("🔌 Interface       : {}", bold(&config.iface));
    info!(
        "⚙️  Attachment Mode : {}",
        bold(format!("{:?}", config.mode))
    );
    info!(
        "📋 Rule Files      : {}",
        bold(format!("{:?}", config.rules))
    );
    info!(
        "👀 Hot-Reload      : {}",
        if config.watch {
            green_bold("Enabled 🟢")
        } else {
            yellow("Disabled ⚪")
        }
    );
    info!("📊 Stats Interval  : {}s", bold_num(config.stats_interval));
    info!(
        "📄 JSON Output     : {}",
        if config.json {
            green_bold("Enabled 🟢")
        } else {
            yellow("Disabled ⚪")
        }
    );
    info!(
        "🤫 Drop Logs       : {}",
        if config.quiet {
            yellow("Disabled (Quiet mode) ⚪")
        } else {
            green_bold("Enabled 🟢")
        }
    );
    info!(
        "📈 Prometheus HTTP : {}",
        if !config.no_metrics {
            green_bold(format!("http://{}/metrics 🟢", config.metrics_listen_addr))
        } else {
            yellow("Disabled ⚪")
        }
    );
    let firehol_enabled = config.is_firehol_enabled();

    info!(
        "🌐 FireHOL Sync    : {}",
        if firehol_enabled {
            green_bold("Enabled 🟢 (Automatic Startup Initializer)")
        } else {
            yellow("Disabled ⚪")
        }
    );
    if firehol_enabled {
        info!(
            "📁 FireHOL Repo    : {}",
            bold(format!("{:?}", config.firehol_dir))
        );
        info!("🔗 FireHOL URL     : {}", bold(&config.firehol_url));
        info!(
            "⏰ FireHOL Cron    : {}",
            if config.is_cron_enabled() {
                green_bold(format!("{} 🟢", bold(&config.firehol_cron)))
            } else {
                yellow("Disabled ⚪")
            }
        );
        if !config.firehol_ignore_ip.is_empty() {
            info!(
                "🚫 FireHOL Ignore  : [{}] 🟢",
                bold(&config.firehol_ignore_ip)
            );
        }
    }
    info!(
        "{}",
        cyan_bold("------------------------------------------------------------------")
    );

    // 2. Initialize Prometheus Metrics Registry (if not disabled)
    let metrics = if !config.no_metrics {
        match PrometheusMetrics::new() {
            Ok(m) => Some(Arc::new(m)),
            Err(e) => {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ Failed to initialize Prometheus metrics registry: {}",
                        e
                    ))
                );
                None
            }
        }
    } else {
        None
    };

    // 3. Load eBPF bytecode without attaching hook yet (enables map population before live traffic)
    let mut xdp_firewall = match XdpFirewall::load(config.bpf_path.as_ref()) {
        Ok(fw) => fw,
        Err(err) => {
            error!(
                "{}",
                red_bold(format!("❌ Failed to load eBPF firewall bytecode: {}", err))
            );
            if let Some(m) = &metrics {
                m.record_error("ebpf_load");
            }
            std::process::exit(1);
        }
    };

    let drop_logs_enabled = Arc::new(AtomicBool::new(!config.quiet));

    // Parse FIREHOL_IGNORE_IP
    let ignore_ips = if !config.firehol_ignore_ip.is_empty() {
        firewall_lib::firehol::parser::parse_ignore_ips(&config.firehol_ignore_ip)
    } else {
        std::env::var("FIREHOL_IGNORE_IP")
            .map(|val| firewall_lib::firehol::parser::parse_ignore_ips(&val))
            .unwrap_or_default()
    };

    // Initialize FireHOL blocklist manager
    let firehol_config = FireholConfig {
        repo_url: config.firehol_url.clone(),
        local_path: config.firehol_dir.clone(),
        default_branch: config.firehol_branch.clone(),
        enabled: firehol_enabled,
        ignore_ips,
    };
    let firehol_metrics = metrics.as_ref().map(|m| Arc::new(m.firehol.clone()));

    // Open an optional on-disk RocksDB cache for the heavy FireHOL metadata. When configured,
    // the verbose per-file metadata and per-target contexts are persisted here (LZ4 + Cap'n
    // Proto) instead of being kept resident in RAM, cutting the process footprint substantially
    // for large blocklist sets while preserving the same lookups.
    let firehol_cache = if firehol_enabled {
        match &config.firehol_cache_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).ok();
                match CacheRocksDb::open(dir) {
                    Ok(cache) => {
                        info!(
                            "{}",
                            blue_bold(format!(
                                "🗄️  FireHOL heavy metadata cache active (RocksDB/LZ4) at '{}'",
                                dir.display()
                            ))
                        );
                        Some(Arc::new(cache))
                    }
                    Err(e) => {
                        warn!(
                            "{}",
                            yellow_bold(format!(
                                "⚠️  Failed to open FireHOL RocksDB cache '{}': {e}; falling back to in-memory metadata",
                                dir.display()
                            ))
                        );
                        None
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };

    let firehol_blocklist = Arc::new(FireholBlockList::with_cache(
        firehol_config,
        firehol_metrics,
        firehol_cache,
    ));

    // Shared registry of static rule metadata (file:line). Populated on every static load
    // (initial + hot-reload) and read by the Ring Buffer consumer so a match against a
    // static rule prints its correct `file:line` instead of showing `-`.
    let static_registry = Arc::new(StaticRuleRegistry::new());

    // 4. Extract RingBuffer Consumer BEFORE moving ebpf into MapManager
    let ringbuf_consumer = match RingBufConsumer::new(&mut xdp_firewall.ebpf, config.json) {
        Ok(mut rb) => {
            rb = rb.with_log_drops_flag(Arc::clone(&drop_logs_enabled));
            if let Some(m) = &metrics {
                rb = rb.with_metrics(Arc::clone(m));
            }
            if firehol_enabled {
                rb = rb.with_firehol_registry(Arc::clone(&firehol_blocklist));
            }
            rb = rb.with_static_registry(Arc::clone(&static_registry));
            rb
        }
        Err(err) => {
            error!(
                "{}",
                red_bold(format!("❌ Failed to initialize eBPF Ring Buffer: {}", err))
            );
            if let Some(m) = &metrics {
                m.record_error("ringbuf_init");
            }
            std::process::exit(1);
        }
    };

    // 5. Initialize MapManager
    let map_manager = match MapManager::new(&mut xdp_firewall.ebpf) {
        Ok(mgr) => Arc::new(Mutex::new(mgr)),
        Err(err) => {
            error!(
                "{}",
                red_bold(format!("❌ Failed to initialize eBPF Map Manager: {}", err))
            );
            if let Some(m) = &metrics {
                m.record_error("map_manager_init");
            }
            std::process::exit(1);
        }
    };

    // 6. FireHOL Automatic Startup Initializer (runs BEFORE attaching XDP to interface)
    // Pipeline: Check local repo -> Clone or Sync -> Parse .ipset/.netset -> Validate -> Separate -> Populate HashMaps -> Populate LPM Tries -> Associate metadata
    if firehol_enabled {
        match execute_firehol_sync(
            &firehol_blocklist,
            Some(&map_manager),
            metrics.as_ref(),
            true,
        )
        .await
        {
            Ok(FireholSyncOutcome::Updated(report)) => {
                info!(
                    "{}",
                    green_bold(format!(
                        "✅ FireHOL initial rules synchronized: {} active threat rules in eBPF",
                        bold_num(report.total_rules())
                    ))
                );
            }
            Ok(_) => {}
            Err(err) => {
                // FAIL-SAFE: Abort startup immediately; do NOT start firewall with partial/inconsistent data
                error!(
                    "{}",
                    red_bold(format!(
                        "❌ FATAL: FireHOL startup initialization failed: {}. Aborting firewall startup (fail-safe mode).",
                        err
                    ))
                );
                if let Some(m) = &metrics {
                    m.record_error("firehol_startup_failed");
                }
                std::process::exit(1);
            }
        }
    } else {
        info!("ℹ️  FireHOL subsystem disabled. Loading local static rule files only...");
    }

    // 7. Load local static rule files (if specified)
    if !config.rules.is_empty() {
        info!(
            "📥 Parsing static rule set from {}...",
            bold(format!("{:?}", config.rules))
        );
        match RuleLoader::load_from_paths_with_meta(&config.rules) {
            Ok((rules, static_meta)) => {
                static_registry.set(static_meta);
                info!(
                    "📦 Loaded {} static rules (Exact IPv4: {}, Exact IPv6: {}, LPM IPv4: {}, LPM IPv6: {})",
                    bold_num(rules.total_rules),
                    bold_num(rules.exact_v4.len()),
                    bold_num(rules.exact_v6.len()),
                    bold_num(rules.lpm_v4.len()),
                    bold_num(rules.lpm_v6.len()),
                );
                let sync_start = Instant::now();
                let mut mgr = map_manager.lock().await;
                if let Err(e) = mgr.sync_rules(&rules) {
                    warn!(
                        "{}",
                        yellow_bold(format!(
                            "⚠️ Failed to synchronize static rules into eBPF maps: {}",
                            e
                        ))
                    );
                    if let Some(m) = &metrics {
                        m.record_error("static_rules_sync");
                    }
                } else if let Some(m) = &metrics {
                    m.observe_rule_sync_duration(sync_start.elapsed());
                    m.update_map_entries(
                        mgr.total_exact_v4(),
                        mgr.total_exact_v6(),
                        mgr.total_lpm_v4(),
                        mgr.total_lpm_v6(),
                    );
                }
            }
            Err(err) => {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️  Failed to load static rule files: {}. Continuing with existing rules...",
                        err
                    ))
                );
                if let Some(m) = &metrics {
                    m.record_error("rule_load");
                }
            }
        }
    }

    // 8. Attach XDP Program to Network Interface (ONLY after all maps are successfully populated and validated)
    info!(
        "⚡ Attaching XDP firewall hook to interface '{}' in {:?} mode...",
        bold(&config.iface),
        config.mode
    );
    if let Err(err) = xdp_firewall.attach(&config.iface, config.mode) {
        error!(
            "{}",
            red_bold(format!(
                "❌ Failed to attach eBPF XDP hook to '{}': {}",
                config.iface, err
            ))
        );
        if let Some(m) = &metrics {
            m.record_error("xdp_attach");
        }
        std::process::exit(1);
    }

    info!(
        "{}",
        green_bold("==================================================================")
    );
    info!(
        "{}",
        green_bold("🚀 FIREWALL READY: All blocklists initialized, XDP live on network!")
    );
    info!(
        "{}",
        green_bold("==================================================================")
    );

    // 7. Setup Graceful Shutdown Coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 8. Spawn Prometheus HTTP Metrics Server
    let metrics_handle = if let Some(m) = &metrics {
        match config.metrics_listen_addr.parse::<SocketAddr>() {
            Ok(addr) => {
                let srv = MetricsServer::new(Arc::clone(m), addr)
                    .with_drop_logs_flag(Arc::clone(&drop_logs_enabled));
                let srv_shutdown_rx = shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    if let Err(err) = srv.run(srv_shutdown_rx).await {
                        error!(
                            "{}",
                            red_bold(format!("❌ Metrics HTTP server error: {}", err))
                        );
                    }
                }))
            }
            Err(e) => {
                error!(
                    "{}",
                    red_bold(format!(
                        "❌ Invalid METRICS_LISTEN_ADDRESS '{}': {}",
                        config.metrics_listen_addr, e
                    ))
                );
                None
            }
        }
    } else {
        None
    };

    // 9. Spawn RingBuffer Telemetry Consumer Task
    let rb_shutdown_rx = shutdown_rx.clone();
    let rb_handle = tokio::spawn(async move {
        if let Err(err) = ringbuf_consumer.run(rb_shutdown_rx).await {
            error!(
                "{}",
                red_bold(format!(
                    "❌ Ring Buffer consumer encountered an error: {}",
                    err
                ))
            );
        }
    });

    // 10. Spawn Stats Reporter Task
    let stats_handle = if config.stats_interval > 0 || metrics.is_some() {
        let stats_mgr = Arc::clone(&map_manager);
        let stats_shutdown_rx = shutdown_rx.clone();
        let mut reporter = StatsReporter::new(stats_mgr, config.stats_interval);
        if let Some(m) = &metrics {
            reporter = reporter.with_metrics(Arc::clone(m));
        }
        Some(tokio::spawn(async move {
            reporter.run(stats_shutdown_rx).await;
        }))
    } else {
        None
    };

    // 11. Spawn Hot-Reload Watcher Task if requested
    let watcher_handle = if config.watch {
        let watch_mgr = Arc::clone(&map_manager);
        let watch_rules = config.rules.clone();
        let watch_metrics = metrics.clone();
        let watch_static = Arc::clone(&static_registry);
        let mut watch_shutdown_rx = shutdown_rx.clone();

        Some(tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel(32);
            let mut watcher = match RecommendedWatcher::new(
                move |res: notify::Result<Event>| {
                    if let Ok(event) = res {
                        // Filter out access / read events to avoid infinite feedback loops
                        let is_content_change = matches!(
                            event.kind,
                            notify::EventKind::Modify(ModifyKind::Data(_))
                                | notify::EventKind::Modify(ModifyKind::Name(_))
                                | notify::EventKind::Modify(ModifyKind::Any)
                                | notify::EventKind::Create(_)
                                | notify::EventKind::Remove(_)
                        );
                        if is_content_change {
                            let _ = tx.blocking_send(event);
                        }
                    }
                },
                notify::Config::default(),
            ) {
                Ok(w) => w,
                Err(err) => {
                    error!(
                        "{}",
                        red_bold(format!("❌ Failed to initialize file watcher: {}", err))
                    );
                    return;
                }
            };

            for path in &watch_rules {
                if let Some(parent) = path.parent() {
                    let watch_path = if parent.as_os_str().is_empty() {
                        PathBuf::from(".")
                    } else {
                        parent.to_path_buf()
                    };
                    if let Err(err) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
                        warn!(
                            "{}",
                            yellow_bold(format!(
                                "⚠️ Could not watch directory {:?}: {}",
                                watch_path, err
                            ))
                        );
                    }
                }
            }

            info!("{}", green_bold("👀 Rule file watcher active. Live hot-reloading is listening for updates... 🔄"));

            let mut last_fingerprint = compute_fingerprint(&watch_rules);

            loop {
                tokio::select! {
                    _ = watch_shutdown_rx.changed() => {
                        info!("{}", yellow_bold("🛑 Rule watcher received shutdown signal."));
                        break;
                    }
                    Some(_event) = rx.recv() => {
                        // Debounce by consuming any immediate subsequent events
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        while rx.try_recv().is_ok() {}

                        // Verify that file modification time or size actually changed
                        let current_fingerprint = compute_fingerprint(&watch_rules);
                        if current_fingerprint == last_fingerprint {
                            continue;
                        }
                        last_fingerprint = current_fingerprint;

                        info!("{}", cyan_bold("🔄 Rule file change detected! Reloading rules from disk..."));
                        match RuleLoader::load_from_paths_with_meta(&watch_rules) {
                            Ok((new_rules, static_meta)) => {
                                watch_static.set(static_meta);
                                let sync_start = Instant::now();
                                let mut mgr = watch_mgr.lock().await;
                                match mgr.sync_rules(&new_rules) {
                                    Ok(report) => {
                                        if let Some(m) = &watch_metrics {
                                            m.observe_rule_sync_duration(sync_start.elapsed());
                                            m.update_map_entries(
                                                mgr.total_exact_v4(),
                                                mgr.total_exact_v6(),
                                                mgr.total_lpm_v4(),
                                                mgr.total_lpm_v6(),
                                            );
                                        }
                                        info!(
                                            "{}",
                                            green_bold(format!(
                                                "✅ Hot-reload complete! Installed: +{} exact, +{} LPM. Removed: -{} stale entries.",
                                                format_int_with_spaces((report.ipv4_exact_inserted + report.ipv6_exact_inserted) as u64),
                                                format_int_with_spaces((report.ipv4_lpm_inserted + report.ipv6_lpm_inserted) as u64),
                                                format_int_with_spaces(report.entries_removed as u64),
                                            ))
                                        );
                                    }
                                    Err(e) => {
                                        error!("{}", red_bold(format!("❌ Failed to sync new rules to eBPF maps: {}", e)));
                                        if let Some(m) = &watch_metrics {
                                            m.record_error("map_sync");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("{}", yellow_bold(format!("⚠️ Failed to parse modified rule files: {}", e)));
                                if let Some(m) = &watch_metrics {
                                    m.record_error("watcher_parse");
                                }
                            }
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    // 11b. Spawn FireHOL Cron Scheduler (periodic synchronization)
    let firehol_scheduler = if config.is_cron_enabled() {
        match FireholScheduler::new(
            &config.firehol_cron,
            Arc::clone(&firehol_blocklist),
            Some(Arc::clone(&map_manager)),
            metrics.clone(),
        )
        .await
        {
            Ok(sched) => match sched.start().await {
                Ok(()) => Some(sched),
                Err(e) => {
                    error!(
                        "{}",
                        red_bold(format!("❌ Failed to start FireHOL scheduler: {}", e))
                    );
                    None
                }
            },
            Err(e) => {
                error!(
                    "{}",
                    red_bold(format!(
                        "❌ Failed to configure FireHOL scheduler with cron \x27{}\x27: {}",
                        config.firehol_cron, e
                    ))
                );
                None
            }
        }
    } else {
        None
    };

    // 12. Wait for Termination Signal (SIGINT / SIGTERM)
    info!(
        "{}",
        green_bold("🚀 Firewall active and filtering ingress traffic. Press Ctrl+C to stop.")
    );
    if let Err(e) = wait_for_shutdown().await {
        error!(
            "{}",
            red_bold(format!("❌ Failed to listen for termination signal: {}", e))
        );
        std::process::exit(1);
    }
    info!(
        "{}",
        yellow_bold("🛑 Shutdown signal received. Initiating graceful shutdown... ⏳")
    );

    // 13. Mark Prometheus metric as shutting down
    if let Some(m) = &metrics {
        m.firewall_up.set(0);
    }

    // 14. Broadcast Shutdown Signal
    let _ = shutdown_tx.send(true);

    // 15. Await Task Completions
    let _ = rb_handle.await;
    if let Some(handle) = stats_handle {
        let _ = handle.await;
    }
    if let Some(handle) = watcher_handle {
        let _ = handle.await;
    }
    if let Some(handle) = metrics_handle {
        let _ = handle.await;
    }
    if let Some(mut sched) = firehol_scheduler {
        if let Err(e) = sched.shutdown().await {
            warn!(
                "{}",
                yellow_bold(format!("⚠️ Error stopping FireHOL scheduler: {}", e))
            );
        } else {
            info!(
                "{}",
                yellow_bold("🛑 FireHOL cron scheduler stopped cleanly.")
            );
        }
    }

    info!(
        "{}",
        green_bold("👋 Firewall shutdown complete. All resources detached cleanly. Stay safe! 🛡️")
    );
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_fingerprint() {
        let tmp = NamedTempFile::new().unwrap();
        let paths = vec![tmp.path().to_path_buf(), PathBuf::from("/non/existent/path")];
        let fp = compute_fingerprint(&paths);
        assert_eq!(fp.len(), 2);
        assert!(fp[0].1.is_some());
        assert_eq!(fp[1].1, None);
        assert_eq!(fp[1].2, 0);
    }
}
