//! Cron-based periodic scheduler for automated FireHOL blocklist synchronization.
//!
//! Uses `tokio-cron-scheduler` to periodically evaluate remote repository changes,
//! download updates, parse blocklists in parallel, and atomically reload eBPF maps
//! without dropping active traffic or disrupting packet processing.

use crate::console::*;
use crate::error::FirewallError;
use crate::firehol::blocklist::FireholBlockList;
use crate::firehol::sync::FireholSyncReport;
use crate::maps::MapManager;
use crate::metrics::FirewallMetrics;
use std::sync::Arc;
use std::time::Instant;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Outcome of a FireHOL synchronization pipeline execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FireholSyncOutcome {
    /// New rules were parsed, validated, and loaded into eBPF maps.
    Updated(FireholSyncReport),
    /// Remote Git repository has no upstream changes; reload was skipped.
    UpToDate { commit_oid: String },
    /// Synchronization was skipped because another sync job is currently running.
    SkippedAlreadyRunning,
}

/// Execute the complete unified FireHOL synchronization pipeline.
///
/// This unified function is called BOTH at firewall startup AND by the periodic cron job:
///
/// 1. Check local FireHOL repository
/// 2. Check remote repository
/// 3. Fetch/update only if necessary
/// 4. Parse .ipset and .netset files
/// 5. Validate parsed data
/// 6. Prepare IPv4 / IPv6 / CIDR entries
/// 7. Update eBPF HashMaps
/// 8. Update eBPF LPM Trie
/// 9. Update Prometheus metrics
///
/// If the remote repository has not changed, the process exits early without touching eBPF maps.
/// If an error occurs, existing eBPF rules and metadata remain completely intact.
pub async fn execute_firehol_sync(
    blocklist: &Arc<FireholBlockList>,
    map_manager: Option<&Arc<tokio::sync::Mutex<MapManager>>>,
    metrics: Option<&Arc<FirewallMetrics>>,
    is_startup: bool,
) -> Result<FireholSyncOutcome, FirewallError> {
    // 1. Concurrency control: prevent overlapping synchronizations
    let sync_lock = blocklist.sync_lock();
    let _guard = if is_startup {
        sync_lock.lock().await
    } else {
        match sync_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(m) = metrics {
                    m.firehol.cron_skipped_total.inc();
                }
                warn!(
                    "{}",
                    yellow_bold("⚠️ FireHOL synchronization skipped: another synchronization is already in progress.")
                );
                return Ok(FireholSyncOutcome::SkippedAlreadyRunning);
            }
        }
    };

    // 2. Metrics recording for cron job trigger
    if !is_startup {
        if let Some(m) = metrics {
            m.firehol
                .cron_last_run_timestamp_seconds
                .set(chrono::Utc::now().timestamp());
            m.firehol.cron_executions_total.inc();
        }
    }

    // 3. Log start of synchronization
    if is_startup {
        info!(
            "{}",
            cyan_bold("==================================================================")
        );
        info!(
            "{}",
            cyan_bold("🛡️  INITIALIZING FIREHOL THREAT BLOCKLISTS (STARTUP PIPELINE)")
        );
        info!(
            "{}",
            cyan_bold("==================================================================")
        );
    } else {
        info!(
            "{}",
            cyan_bold("🚀 Starting FireHOL blocklists synchronization...")
        );
    }

    let start_time = Instant::now();

    // 4. Acquire MapManager lock (if available)
    let mut mgr_guard = match map_manager {
        Some(m) => Some(m.lock().await),
        None => None,
    };

    // 5. Execute core synchronization and load
    let result = blocklist.synchronize_and_load_internal(mgr_guard.as_deref_mut(), is_startup);
    let duration = start_time.elapsed().as_secs_f64();

    match result {
        Ok(report) => {
            if report.total_rules() == 0 && blocklist.has_active_rules() {
                // Remote repository was unchanged; parsing & map loading skipped
                let commit = blocklist
                    .last_loaded_commit()
                    .unwrap_or_else(|| "unknown".to_string());
                let commit_time = blocklist.last_loaded_commit_time().unwrap_or(0);
                let date_str = if commit_time > 0 {
                    chrono::DateTime::from_timestamp(commit_time, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                if let Some(m) = metrics {
                    m.firehol.cron_no_change_total.inc();
                    m.firehol.cron_last_error.set(0);
                    m.firehol.cron_last_duration_seconds.set(duration);
                }
                info!(
                    "{}",
                    green_bold(format!(
                        "✨ FireHOL repository is up-to-date (commit {}, date: {}); skipping redundant reload.",
                        bold(&commit[..std::cmp::min(7, commit.len())]),
                        bold(date_str)
                    ))
                );
                Ok(FireholSyncOutcome::UpToDate { commit_oid: commit })
            } else {
                // Rules successfully installed and updated
                if let Some(m) = metrics {
                    if !is_startup {
                        m.firehol.cron_success_total.inc();
                    }
                    m.firehol.cron_last_error.set(0);
                    m.firehol.cron_last_duration_seconds.set(duration);
                    m.firehol
                        .cron_last_success_timestamp_seconds
                        .set(chrono::Utc::now().timestamp());
                    m.update_map_entries(
                        report.exact_v4_count,
                        report.exact_v6_count,
                        report.lpm_v4_count,
                        report.lpm_v6_count,
                    );
                }
                info!(
                    "{}",
                    green_bold(format!(
                        "🎉 FireHOL synchronization completed successfully: {} active threat rules in eBPF kernel maps! 🛡️",
                        bold_num(report.total_rules())
                    ))
                );
                Ok(FireholSyncOutcome::Updated(report))
            }
        }
        Err(err) => {
            if let Some(m) = metrics {
                if !is_startup {
                    m.firehol.cron_failures_total.inc();
                }
                m.firehol.cron_last_error.set(1);
                m.firehol.cron_last_duration_seconds.set(duration);
                m.record_error("firehol_sync_failed");
            }
            error!(
                "{}",
                red_bold(format!(
                    "❌ FireHOL synchronization failed: {}. Existing active rules remain intact.",
                    err
                ))
            );
            Err(err)
        }
    }
}

/// Periodic cron scheduler for FireHOL blocklist synchronization.
pub struct FireholScheduler {
    scheduler: Arc<tokio::sync::Mutex<JobScheduler>>,
    job_id: Uuid,
    cron_expr: String,
}

impl FireholScheduler {
    /// Create a new FireholScheduler using the given cron expression.
    pub async fn new(
        cron_expr: &str,
        blocklist: Arc<FireholBlockList>,
        map_manager: Option<Arc<tokio::sync::Mutex<MapManager>>>,
        metrics: Option<Arc<FirewallMetrics>>,
    ) -> Result<Self, FirewallError> {
        let scheduler = JobScheduler::new().await.map_err(|e| {
            FirewallError::Config(format!("Failed to initialize JobScheduler: {}", e))
        })?;

        let blocklist_clone = Arc::clone(&blocklist);
        let map_mgr_clone = map_manager.clone();
        let metrics_clone = metrics.clone();

        let job = Job::new_async(cron_expr, move |uuid, mut lock| {
            let blocklist = Arc::clone(&blocklist_clone);
            let map_manager = map_mgr_clone.clone();
            let metrics = metrics_clone.clone();

            Box::pin(async move {
                let _ =
                    execute_firehol_sync(&blocklist, map_manager.as_ref(), metrics.as_ref(), false)
                        .await;

                if let Ok(Some(next_time)) = lock.next_tick_for_job(uuid).await {
                    info!(
                        "{}",
                        cyan_bold(format!(
                            "⏳ Next scheduled FireHOL synchronization at: {}",
                            bold(next_time.to_rfc3339())
                        ))
                    );
                }
            })
        })
        .map_err(|e| {
            FirewallError::Config(format!(
                "Failed to parse cron expression '{}': {}",
                cron_expr, e
            ))
        })?;

        let job_id = scheduler
            .add(job)
            .await
            .map_err(|e| FirewallError::Config(format!("Failed to add job to scheduler: {}", e)))?;

        Ok(Self {
            scheduler: Arc::new(tokio::sync::Mutex::new(scheduler)),
            job_id,
            cron_expr: cron_expr.to_string(),
        })
    }

    /// Start the scheduler task loop.
    pub async fn start(&self) -> Result<(), FirewallError> {
        let mut sched = self.scheduler.lock().await;
        sched
            .start()
            .await
            .map_err(|e| FirewallError::Config(format!("Failed to start JobScheduler: {}", e)))?;

        info!(
            "{}",
            green_bold(format!(
                "⏰ FireHOL cron scheduler started with expression: '{}'",
                bold(&self.cron_expr)
            ))
        );

        if let Ok(Some(next_time)) = sched.next_tick_for_job(self.job_id).await {
            info!(
                "{}",
                cyan_bold(format!(
                    "⏳ Next scheduled FireHOL synchronization at: {}",
                    bold(next_time.to_rfc3339())
                ))
            );
        }

        Ok(())
    }

    /// Query the next scheduled trigger instant.
    pub async fn next_tick(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>, FirewallError> {
        let mut sched = self.scheduler.lock().await;
        sched
            .next_tick_for_job(self.job_id)
            .await
            .map_err(|e| FirewallError::Config(format!("Failed to query next tick: {}", e)))
    }

    /// Gracefully stop the scheduler.
    pub async fn shutdown(&mut self) -> Result<(), FirewallError> {
        let mut sched = self.scheduler.lock().await;
        sched
            .shutdown()
            .await
            .map_err(|e| FirewallError::Config(format!("Failed to shutdown JobScheduler: {}", e)))
    }

    /// Access the configured cron expression.
    pub fn cron_expr(&self) -> &str {
        &self.cron_expr
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehol::blocklist::FireholConfig;
    use git2::Repository;
    use std::path::Path;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scheduler_invalid_cron() {
        let local_dir = tempdir().unwrap();
        let config = FireholConfig {
            repo_url: "dummy".to_string(),
            local_path: local_dir.path().to_path_buf(),
            default_branch: "master".to_string(),
            enabled: true,
            ignore_ips: vec![],
        };
        let blocklist = Arc::new(FireholBlockList::new(config, None));
        let res = FireholScheduler::new("invalid cron expr", blocklist, None, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_scheduler_lifecycle() {
        let local_dir = tempdir().unwrap();
        let config = FireholConfig {
            repo_url: "dummy".to_string(),
            local_path: local_dir.path().to_path_buf(),
            default_branch: "master".to_string(),
            enabled: true,
            ignore_ips: vec![],
        };
        let blocklist = Arc::new(FireholBlockList::new(config, None));
        let mut sched = FireholScheduler::new("0 0 * * * *", blocklist, None, None)
            .await
            .unwrap();

        assert_eq!(sched.cron_expr(), "0 0 * * * *");
        let tick = sched.next_tick().await.unwrap();
        assert!(tick.is_some());

        sched.start().await.unwrap();
        sched.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_firehol_sync_lifecycle() {
        // Create mock remote repo with test.ipset
        let remote_dir = tempdir().unwrap();
        let _bare = Repository::init_bare(remote_dir.path()).unwrap();

        let work_dir = tempdir().unwrap();
        let work_repo = Repository::clone(remote_dir.path().to_str().unwrap(), work_dir.path()).unwrap();

        let sig = git2::Signature::now("Tester", "test@example.com").unwrap();
        let file_path = work_dir.path().join("test.ipset");
        std::fs::write(&file_path, "192.0.2.1\n192.0.2.2\n").unwrap();

        let mut index = work_repo.index().unwrap();
        index.add_path(Path::new("test.ipset")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = work_repo.find_tree(tree_id).unwrap();
        let _commit_oid = work_repo
            .commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        let mut remote = work_repo.find_remote("origin").unwrap();
        remote.push(&["refs/heads/master:refs/heads/master"], None).unwrap();

        let local_dir = tempdir().unwrap();
        let config = FireholConfig {
            repo_url: remote_dir.path().to_str().unwrap().to_string(),
            local_path: local_dir.path().to_path_buf(),
            default_branch: "master".to_string(),
            enabled: true,
            ignore_ips: vec![],
        };

        let blocklist = Arc::new(FireholBlockList::new(config, None));

        // 1. Startup sync
        let outcome = execute_firehol_sync(&blocklist, None, None, true).await.unwrap();
        match outcome {
            FireholSyncOutcome::Updated(report) => {
                assert_eq!(report.exact_v4_count, 2);
            }
            _ => panic!("Expected Updated outcome"),
        }

        // 2. Up to date sync
        let outcome2 = execute_firehol_sync(&blocklist, None, None, false).await.unwrap();
        assert!(matches!(outcome2, FireholSyncOutcome::UpToDate { .. }));

        // 3. Concurrency lock: skipped already running
        let lock_arc = blocklist.sync_lock();
        let guard = lock_arc.lock().await;
        let outcome3 = execute_firehol_sync(&blocklist, None, None, false).await.unwrap();
        assert_eq!(outcome3, FireholSyncOutcome::SkippedAlreadyRunning);
        drop(guard);
    }
}
