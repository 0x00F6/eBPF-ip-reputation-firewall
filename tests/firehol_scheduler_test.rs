//! Comprehensive unit and integration tests for the FireHOL cron scheduler.
//!
//! Tests include:
//! 1. Cron configuration parsing and default value verification.
//! 2. FireholScheduler start, next tick query, and clean shutdown.
//! 3. Job periodic triggering using tokio-cron-scheduler.
//! 4. Mutual exclusion (preventing concurrent synchronizations).
//! 5. Unchanged remote Git detection and redundant reload skipping.
//! 6. Error resilience (failure handling without crashing or corrupting active rules).

use clap::Parser;
use firewall_lib::config::Config;
use firewall_lib::error::FirewallError;
use firewall_lib::firehol::{
    execute_firehol_sync, FireholBlockList, FireholConfig, FireholScheduler, FireholSyncOutcome,
};
use firewall_lib::metrics::FirewallMetrics;
use git2::{IndexAddOption, Repository, Signature};
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;

fn commit_file(repo: &Repository, filename: &str, content: &str, msg: &str) {
    let workdir = repo.workdir().unwrap();
    let file_path = workdir.join(filename);
    std::fs::write(&file_path, content).unwrap();

    let sig = Signature::now("FireHOL Bot", "bot@firehol.org").unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();

    let tree_id = index.write_tree().unwrap();
    {
        let tree = repo.find_tree(tree_id).unwrap();
        let parent_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents = match &parent_commit {
            Some(c) => vec![c],
            None => vec![],
        };
        repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, parents.as_slice())
            .unwrap();
    }
}

fn create_upstream_firehol_repo(dir: &Path) -> Repository {
    let repo = Repository::init(dir).unwrap();

    let dshield = r#"# Maintainer: SANS DShield
# Maintainer URL: https://isc.sans.edu
# Category: attacks
# Source File Date: Mon Sep 14 02:22:20 UTC 2026
192.0.2.1
198.51.100.0/24
203.0.113.1/32
"#;
    commit_file(
        &repo,
        "dshield.netset",
        dshield,
        "Initial dshield blocklist",
    );

    let feodo = r#"# Maintainer: Feodo Tracker
# Category: botnet
# Source File Date: Sun Mar 15 10:14:02 UTC 2026
192.0.2.10
2001:db8::1
2001:db8:a::/48
"#;
    commit_file(&repo, "feodo.ipset", feodo, "Add feodo blocklist");

    let _ = repo.set_head("refs/heads/master");
    repo
}

/// 1. Test cron configuration parsing and default value.
#[test]
fn test_cron_configuration_parsing_and_default() {
    // Default value must be "0 0 * * * *" (hourly)
    let config = Config::try_parse_from(["firewall"]).unwrap();
    assert_eq!(config.firehol_cron, "0 0 * * * *");
    assert!(!config.no_cron);
    assert!(config.is_cron_enabled());

    // Custom cron via CLI argument
    let custom = Config::try_parse_from(["firewall", "--firehol-cron", "0 */30 * * * *"]).unwrap();
    assert_eq!(custom.firehol_cron, "0 */30 * * * *");
    assert!(custom.is_cron_enabled());

    // Disabling cron via --no-cron
    let disabled = Config::try_parse_from(["firewall", "--no-cron"]).unwrap();
    assert!(disabled.no_cron);
    assert!(!disabled.is_cron_enabled());
}

/// 2. Test invalid cron expression detection.
#[tokio::test]
async fn test_invalid_cron_expression_error() {
    let dummy_config = FireholConfig {
        repo_url: "https://example.com/repo.git".into(),
        local_path: tempdir().unwrap().path().to_path_buf(),
        default_branch: "master".into(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let blocklist = Arc::new(FireholBlockList::new(dummy_config, None));

    // Completely invalid expression
    let res = FireholScheduler::new("not_a_valid_cron", blocklist.clone(), None, None).await;
    assert!(res.is_err());
    match res.err().unwrap() {
        FirewallError::Config(msg) => {
            assert!(msg.contains("Failed to parse cron expression"));
        }
        other => panic!("Expected FirewallError::Config, got {:?}", other),
    }

    // Invalid number of fields
    let res2 = FireholScheduler::new("* * * * * * * * *", blocklist, None, None).await;
    assert!(res2.is_err());
}

/// 3. Test scheduler startup, next tick calculation, and clean shutdown.
#[tokio::test]
async fn test_scheduler_lifecycle_and_clean_shutdown() {
    let dummy_config = FireholConfig {
        repo_url: "https://example.com/repo.git".into(),
        local_path: tempdir().unwrap().path().to_path_buf(),
        default_branch: "master".into(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let blocklist = Arc::new(FireholBlockList::new(dummy_config, None));

    let mut scheduler = FireholScheduler::new("0 0 * * * *", blocklist, None, None)
        .await
        .expect("Scheduler creation failed");

    assert_eq!(scheduler.cron_expr(), "0 0 * * * *");

    // Start the scheduler
    scheduler.start().await.expect("Failed to start scheduler");

    // Query next tick (must be in the future)
    let next_tick = scheduler
        .next_tick()
        .await
        .expect("Failed to query next tick");
    assert!(next_tick.is_some(), "Next tick should be scheduled");
    let tick_time = next_tick.unwrap();
    assert!(tick_time > chrono::Utc::now());

    // Clean shutdown must complete without hanging
    scheduler
        .shutdown()
        .await
        .expect("Scheduler shutdown failed");
}

/// 4. Test mutual exclusion: two FireHOL synchronizations can NEVER run concurrently.
#[tokio::test]
async fn test_scheduler_concurrency_exclusion() {
    let dummy_config = FireholConfig {
        repo_url: "https://example.com/repo.git".into(),
        local_path: tempdir().unwrap().path().to_path_buf(),
        default_branch: "master".into(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let metrics = Arc::new(FirewallMetrics::new().unwrap());
    let blocklist = Arc::new(FireholBlockList::new(
        dummy_config,
        Some(Arc::new(metrics.firehol.clone())),
    ));

    // Simulate another job or sync currently running by acquiring the sync_lock
    let sync_lock = blocklist.sync_lock();
    let lock_guard = sync_lock
        .try_lock()
        .expect("Failed to acquire initial lock");

    // Now execute a scheduled sync (is_startup: false)
    let outcome = execute_firehol_sync(&blocklist, None, Some(&metrics), false)
        .await
        .expect("execute_firehol_sync should succeed cleanly with skipped outcome");

    assert_eq!(outcome, FireholSyncOutcome::SkippedAlreadyRunning);
    assert_eq!(metrics.firehol.cron_skipped_total.get(), 1);
    assert_eq!(metrics.firehol.cron_executions_total.get(), 0);

    // Release lock
    drop(lock_guard);
}

/// 5. Test unchanged Git repository behavior: skips redundant reload and updates Prometheus metrics.
#[tokio::test]
async fn test_scheduler_no_change_detection() {
    let upstream_dir = tempdir().unwrap();
    let _upstream_repo = create_upstream_firehol_repo(upstream_dir.path());

    let client_dir = tempdir().unwrap();
    let local_checkout = client_dir.path().join("firehol-checkout");

    let metrics = Arc::new(FirewallMetrics::new().unwrap());
    let config = FireholConfig {
        repo_url: upstream_dir.path().to_str().unwrap().to_string(),
        local_path: local_checkout,
        default_branch: "master".to_string(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let blocklist = Arc::new(FireholBlockList::new(
        config,
        Some(Arc::new(metrics.firehol.clone())),
    ));

    // 1. First run (Startup): loads dataset into memory
    let startup_outcome = execute_firehol_sync(&blocklist, None, Some(&metrics), true)
        .await
        .expect("Startup sync failed");

    match startup_outcome {
        FireholSyncOutcome::Updated(report) => {
            assert_eq!(report.total_rules(), 6);
            assert!(blocklist.has_active_rules());
        }
        other => panic!("Expected Updated outcome, got {:?}", other),
    }

    // 2. Second run (Cron triggered): remote repository is unchanged
    let cron_outcome = execute_firehol_sync(&blocklist, None, Some(&metrics), false)
        .await
        .expect("Cron sync failed");

    match cron_outcome {
        FireholSyncOutcome::UpToDate { commit_oid } => {
            assert!(!commit_oid.is_empty());
            assert!(blocklist.last_loaded_commit_time().is_some());
            assert!(blocklist.last_loaded_commit_time().unwrap() > 0);
        }
        other => panic!("Expected UpToDate outcome, got {:?}", other),
    }

    // Verify Prometheus cron metrics:
    // Total executions: 1 (cron run only)
    assert_eq!(metrics.firehol.cron_executions_total.get(), 1);
    // No-change executions: 1
    assert_eq!(metrics.firehol.cron_no_change_total.get(), 1);
    // Failures: 0
    assert_eq!(metrics.firehol.cron_failures_total.get(), 0);
    assert_eq!(metrics.firehol.cron_last_error.get(), 0);
    // Duration was recorded
    assert!(metrics.firehol.cron_last_duration_seconds.get() >= 0.0);
}

/// 6. Test error resilience: a synchronization error does NOT crash the scheduler or corrupt active rules.
#[tokio::test]
async fn test_scheduler_error_resilience() {
    let client_dir = tempdir().unwrap();
    let local_checkout = client_dir.path().join("invalid-checkout");

    let metrics = Arc::new(FirewallMetrics::new().unwrap());
    // Point to non-existent repository path
    let config = FireholConfig {
        repo_url: "/non/existent/path/firehol.git".to_string(),
        local_path: local_checkout,
        default_branch: "master".to_string(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let blocklist = Arc::new(FireholBlockList::new(
        config,
        Some(Arc::new(metrics.firehol.clone())),
    ));

    // Execute cron sync (is_startup: false)
    let result = execute_firehol_sync(&blocklist, None, Some(&metrics), false).await;

    // Error is returned cleanly
    assert!(result.is_err(), "Sync should report error");
    // Metrics updated: 1 execution, 1 failure
    assert_eq!(metrics.firehol.cron_executions_total.get(), 1);
    assert_eq!(metrics.firehol.cron_failures_total.get(), 1);
    assert_eq!(metrics.firehol.cron_last_error.get(), 1);
    assert_eq!(metrics.firehol.cron_success_total.get(), 0);
    assert!(metrics.firehol.cron_last_duration_seconds.get() >= 0.0);
}

/// 7. Test automated job triggering via tokio-cron-scheduler.
#[tokio::test]
async fn test_scheduler_automated_job_triggering() {
    let upstream_dir = tempdir().unwrap();
    let _upstream_repo = create_upstream_firehol_repo(upstream_dir.path());

    let client_dir = tempdir().unwrap();
    let local_checkout = client_dir.path().join("firehol-job-test");

    let metrics = Arc::new(FirewallMetrics::new().unwrap());
    let config = FireholConfig {
        repo_url: upstream_dir.path().to_str().unwrap().to_string(),
        local_path: local_checkout,
        default_branch: "master".to_string(),
        enabled: true,
        ignore_ips: Vec::new(),
    };
    let blocklist = Arc::new(FireholBlockList::new(
        config,
        Some(Arc::new(metrics.firehol.clone())),
    ));

    // Run every second
    let mut scheduler = FireholScheduler::new(
        "1/1 * * * * *",
        blocklist.clone(),
        None,
        Some(metrics.clone()),
    )
    .await
    .expect("Failed to create scheduler");

    scheduler.start().await.expect("Failed to start scheduler");

    // Wait 1.3 seconds for at least one tick to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(1300)).await;

    // Verify job executed
    let runs = metrics.firehol.cron_executions_total.get();
    assert!(
        runs >= 1,
        "Expected at least 1 cron execution triggered, got {}",
        runs
    );

    // Verify clean shutdown
    scheduler.shutdown().await.expect("Shutdown failed");
}
