//! High-level FireHOL blocklist manager coordinating repository sync, parsing, and atomic eBPF loading.

use crate::cache_rocksdb::CacheRocksDb;
use crate::console::*;
use crate::error::FirewallError;
use crate::firehol::{
    git_repository::{
        FireholGitRepository, SyncStatus, FIREHOL_DEFAULT_BRANCH, FIREHOL_DEFAULT_GIT_URL,
    },
    metadata::{FireholMetadataRegistry, FireholRuleInfo},
    metrics::FireholMetrics,
    parser::{FireholDataSet, FireholParser},
    sync::{FireholSyncManager, FireholSyncReport},
};
use crate::maps::MapManager;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};
use tracing::{debug, info};

/// Configuration options for the FireHOL blocklist subsystem.
#[derive(Debug, Clone)]
pub struct FireholConfig {
    /// Remote Git repository URL
    pub repo_url: String,
    /// Local filesystem path for the Git checkout
    pub local_path: PathBuf,
    /// Target Git branch to track
    pub default_branch: String,
    /// Whether FireHOL synchronization is enabled
    pub enabled: bool,
    /// List of IP addresses to ignore during FireHOL parsing (e.g. Prometheus scraper, gateways)
    pub ignore_ips: Vec<std::net::IpAddr>,
}

impl Default for FireholConfig {
    fn default() -> Self {
        let ignore_ips = std::env::var("FIREHOL_IGNORE_IP")
            .map(|val| crate::firehol::parser::parse_ignore_ips(&val))
            .unwrap_or_default();

        Self {
            repo_url: FIREHOL_DEFAULT_GIT_URL.to_string(),
            local_path: PathBuf::from("rules/firehol-blocklist-ipsets"),
            default_branch: FIREHOL_DEFAULT_BRANCH.to_string(),
            enabled: true,
            ignore_ips,
        }
    }
}

/// Central coordinator for FireHOL blocklist synchronization, parsing, and atomic eBPF map installation.
pub struct FireholBlockList {
    pub config: FireholConfig,
    git_repo: Mutex<FireholGitRepository>,
    metrics: Option<Arc<FireholMetrics>>,
    /// Optional on-disk RocksDB cache for the heavy rule metadata/contexts, so
    /// those large payloads are not resident in RAM. `None` keeps the classic
    /// fully-in-memory behavior (used by tests and small deployments).
    cache: Option<Arc<CacheRocksDb>>,
    active_registry: RwLock<Arc<FireholMetadataRegistry>>,
    last_loaded_commit: RwLock<Option<String>>,
    last_loaded_commit_time: RwLock<Option<i64>>,
    sync_lock: Arc<tokio::sync::Mutex<()>>,
}

impl FireholBlockList {
    /// Create a new FireHOL blocklist manager without an on-disk cache.
    pub fn new(config: FireholConfig, metrics: Option<Arc<FireholMetrics>>) -> Self {
        Self::with_cache(config, metrics, None)
    }

    /// Create a FireHOL blocklist manager backed by a shared RocksDB cache: the
    /// verbose per-file metadata and per-target contexts are persisted (LZ4 +
    /// Cap'n Proto) instead of being kept resident in RAM, cutting the process
    /// footprint for large blocklist sets while preserving the same lookups.
    pub fn with_cache(
        config: FireholConfig,
        metrics: Option<Arc<FireholMetrics>>,
        cache: Option<Arc<CacheRocksDb>>,
    ) -> Self {
        Self {
            config,
            git_repo: Mutex::new(FireholGitRepository::new()),
            metrics,
            cache,
            active_registry: RwLock::new(Arc::new(FireholMetadataRegistry::new())),
            last_loaded_commit: RwLock::new(None),
            last_loaded_commit_time: RwLock::new(None),
            sync_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Access the active metadata registry for eBPF Ring Buffer drop event lookups.
    pub fn registry(&self) -> Arc<FireholMetadataRegistry> {
        self.active_registry.read().unwrap().clone()
    }

    /// Resolve an eBPF rule ID into its detailed FireHOL rule and threat metadata.
    pub fn resolve_rule(&self, rule_id: u32) -> Option<FireholRuleInfo> {
        self.active_registry
            .read()
            .unwrap()
            .resolve_rule(rule_id)
            .map(|r| FireholRuleInfo {
                rule_id,
                metadata_id: r.metadata_id,
                category: r.category,
                line: r.line,
            })
    }

    /// Check whether active rules are currently loaded in memory.
    pub fn has_active_rules(&self) -> bool {
        !self.active_registry.read().unwrap().is_empty()
    }

    /// Access the synchronization mutex to prevent concurrent sync operations.
    pub fn sync_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.sync_lock)
    }

    /// Retrieve the commit hash of the currently loaded active FireHOL rules.
    pub fn last_loaded_commit(&self) -> Option<String> {
        self.last_loaded_commit.read().unwrap().clone()
    }

    /// Retrieve the commit timestamp of the currently loaded active FireHOL rules.
    pub fn last_loaded_commit_time(&self) -> Option<i64> {
        *self.last_loaded_commit_time.read().unwrap()
    }

    /// Execute the complete startup initialization pipeline before attaching the firewall:
    ///
    /// 1. Check local FireHOL repository
    /// 2. If it exists, check if up-to-date and fetch new modifications
    /// 3. If it doesn't exist, automatically clone it
    /// 4. Once synchronized, parse all .ipset / .netset files
    /// 5. Validate all parsed entries strictly
    /// 6. Separate entries: exact IPv4, exact IPv6, CIDR IPv4, CIDR IPv6
    /// 7. Populate exact IP addresses in BPF HashMaps
    /// 8. Populate CIDR networks in BPF LPM Trie
    /// 9. Associate FireHOL metadata and threat categories
    /// 10. Report readiness so the firewall can start packet processing.
    ///
    /// This function is FAIL-SAFE: if any step fails, the firewall will not start.
    pub fn startup_initialize(
        &self,
        map_manager: &mut MapManager,
    ) -> Result<FireholSyncReport, FirewallError> {
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

        self.synchronize_and_load_internal(Some(map_manager), true)
    }

    /// Execute the complete atomic synchronization pipeline:
    ///
    /// 1. Download (shallow clone or shallow fetch with hard reset)
    /// 2. Parse (.ipset & .netset files in parallel, sorted by size)
    /// 3. Validate (strict check of all entries)
    /// 4. Prepare (partition into HashMap exact IPs and LPM Trie CIDRs)
    /// 5. Load (atomically install rules into live eBPF maps)
    ///
    /// If ANY step fails, existing firewall rules and metadata are left completely intact.
    pub fn synchronize_and_load(
        &self,
        map_manager: &mut MapManager,
    ) -> Result<FireholSyncReport, FirewallError> {
        self.synchronize_and_load_internal(Some(map_manager), false)
    }

    pub fn synchronize_and_load_internal(
        &self,
        map_manager: Option<&mut MapManager>,
        is_startup: bool,
    ) -> Result<FireholSyncReport, FirewallError> {
        let prefix = if is_startup { "Startup" } else { "Runtime" };

        // 1. Check if local FireHOL repository exists
        let git_dir = self.config.local_path.join(".git");
        let repo_exists = self.config.local_path.exists() && git_dir.exists();
        info!(
            "{}",
            cyan_bold(format!(
                "🔍 [Step 1/8] Checking local FireHOL repository at '{}'...",
                self.config.local_path.display()
            ))
        );
        if repo_exists {
            info!(
                "📁 Local repository detected at '{}'. Will check upstream status.",
                self.config.local_path.display()
            );
        } else {
            info!(
                "📥 No repository found at '{}'. Automatic shallow clone required.",
                self.config.local_path.display()
            );
        }

        // 2 & 3. Clone or synchronize repository
        info!(
            "{}",
            cyan_bold(format!(
                "🌐 [Step 2/8] Synchronizing FireHOL repository from '{}' (branch '{}')...",
                self.config.repo_url, self.config.default_branch
            ))
        );
        let sync_start = Instant::now();
        let (repo_path, sync_status) = {
            let mut git = self.git_repo.lock().unwrap();
            let status = git
                .synchronize(
                    &self.config.local_path,
                    &self.config.repo_url,
                    &self.config.default_branch,
                    self.metrics.as_deref(),
                )
                .map_err(|e| {
                    FirewallError::Config(format!("FireHOL Git synchronization failed: {}", e))
                })?;
            (self.config.local_path.clone(), status)
        };
        let sync_duration = sync_start.elapsed();

        let (commit_oid, commit_time) = match &sync_status {
            SyncStatus::Cloned {
                commit_oid,
                commit_time,
            } => {
                let date_str = if *commit_time > 0 {
                    chrono::DateTime::from_timestamp(*commit_time, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                info!(
                    "{}",
                    green_bold(format!(
                        "📥 FireHOL shallow clone completed (commit {}, date: {}) in {:.2?}",
                        &commit_oid[..std::cmp::min(7, commit_oid.len())],
                        date_str,
                        sync_duration
                    ))
                );
                (commit_oid.clone(), *commit_time)
            }
            SyncStatus::Updated {
                commit_oid,
                commit_time,
            } => {
                let date_str = if *commit_time > 0 {
                    chrono::DateTime::from_timestamp(*commit_time, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                info!(
                    "{}",
                    green_bold(format!(
                        "🔄 Fetched upstream changes to commit {} (date: {}, took {:.2?})",
                        &commit_oid[..std::cmp::min(7, commit_oid.len())],
                        date_str,
                        sync_duration
                    ))
                );
                (commit_oid.clone(), *commit_time)
            }
            SyncStatus::UpToDate {
                commit_oid,
                commit_time,
            } => {
                let date_str = if *commit_time > 0 {
                    chrono::DateTime::from_timestamp(*commit_time, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                info!(
                    "{}",
                    green_bold(format!(
                        "✅ FireHOL repository is already up-to-date with remote HEAD (commit {}, date: {})",
                        &commit_oid[..std::cmp::min(7, commit_oid.len())],
                        date_str
                    ))
                );

                // Optimization: if repository is unchanged and active dataset is already loaded and valid, skip reload!
                if !is_startup
                    && self.last_loaded_commit.read().unwrap().as_deref()
                        == Some(commit_oid.as_str())
                    && self.has_active_rules()
                {
                    info!(
                        "{}",
                        cyan_bold(format!(
                            "✨ Remote repository unchanged (commit {}, date: {}) and active rules are valid; skipping redundant reload.",
                            &commit_oid[..std::cmp::min(7, commit_oid.len())],
                            date_str
                        ))
                    );
                    return Ok(FireholSyncReport::default());
                }
                (commit_oid.clone(), *commit_time)
            }
        };

        // 4. Parse .ipset / .netset files
        info!(
            "{}",
            cyan_bold("📂 [Step 3/8] Parsing FireHOL .ipset and .netset files in parallel...")
        );
        let parse_start = Instant::now();
        let mut dataset = FireholParser::parse_directory_spooled(
            &repo_path,
            &self.config.ignore_ips,
            self.metrics.as_deref(),
            self.cache.clone(),
        )
        .map_err(|e| FirewallError::Config(format!("FireHOL parsing failed: {}", e)))?;
        let parse_duration = parse_start.elapsed();
        info!(
            "{}",
            green_bold(format!(
                "📑 Parsed {} files ({} raw entries) in {:.2?}",
                dataset.total_files,
                dataset.total_entries(),
                parse_duration
            ))
        );

        // 5. Validate all parsed entries
        info!(
            "{}",
            cyan_bold("🛡️  [Step 4/8] Validating parsed FireHOL entries...")
        );
        if dataset.is_empty() {
            return Err(FirewallError::Config(
                "FireHOL dataset validation failed: 0 entries found in repository".into(),
            ));
        }
        info!(
            "{}",
            green_bold(format!(
                "✅ Strict validation successful: {} blocklists and {} entries strictly verified",
                dataset.registry.total_blocklists(),
                dataset.total_entries()
            ))
        );

        // 6. Prepare IPv4 / IPv6 / CIDR entries
        info!(
            "{}",
            cyan_bold("⚙️  [Step 5/8] Preparing and partitioning IPv4, IPv6, and CIDR rules with deduplication...")
        );
        let (prepared_rules, report_draft) = FireholSyncManager::try_prepare_rules(&dataset)?;
        // Release raw entries before eBPF synchronization allocates its working state.
        dataset.entries = Vec::new();
        if let Some(cache) = dataset.stored_entries.take() {
            cache.clear_entries()?;
        }
        debug!(
            "📊 Rules breakdown: {} exact IPv4, {} exact IPv6, {} LPM IPv4 CIDR, {} LPM IPv6 CIDR ({} duplicates deduplicated)",
            bold(report_draft.exact_v4_count),
            bold(report_draft.exact_v6_count),
            bold(report_draft.lpm_v4_count),
            bold(report_draft.lpm_v6_count),
            bold(report_draft.duplicates_deduped)
        );

        // 7. Populate exact IP addresses in BPF HashMaps
        info!(
            "{}",
            cyan_bold(format!(
                "📥 [Step 6/8] Populating eBPF HashMaps with {} exact IP addresses...",
                bold(prepared_rules.exact_v4.len() + prepared_rules.exact_v6.len())
            ))
        );

        // 8. Populate CIDR networks in BPF LPM Trie
        info!(
            "{}",
            cyan_bold(format!(
                "🌳 [Step 7/8] Populating eBPF LPM Tries with {} CIDR subnet blocks...",
                bold_num(prepared_rules.lpm_v4.len() + prepared_rules.lpm_v6.len())
            ))
        );
        let map_load_start = Instant::now();
        let report = if let Some(mgr) = map_manager {
            FireholSyncManager::load_into_maps(mgr, &prepared_rules, report_draft)?
        } else {
            report_draft
        };
        let map_load_duration = map_load_start.elapsed();

        if let Some(m) = &self.metrics {
            m.map_load_duration_seconds
                .observe(map_load_duration.as_secs_f64());
        }

        info!(
            "{}",
            green_bold(format!(
                "✅ eBPF maps populated in {:.2?} (+{} exact IPv4, +{} exact IPv6, +{} LPM IPv4, +{} LPM IPv6)",
                map_load_duration,
                bold_num(report.exact_v4_count),
                bold_num(report.exact_v6_count),
                bold_num(report.lpm_v4_count),
                bold_num(report.lpm_v6_count)
            ))
        );

        // 9. Associate FireHOL metadata and categories
        info!(
            "{}",
            cyan_bold("🏷️  [Step 8/8] Associating FireHOL threat metadata and categories...")
        );
        // Move the registry into active use (zero-copy, no clone) and drop the now-unused
        // `FireholDataSet` along with its large `entries` vector: it is never referenced again
        // after the eBPF maps are populated, so retaining it would waste significant RAM.
        let FireholDataSet { registry, .. } = dataset;
        *self.active_registry.write().unwrap() = Arc::new(registry);
        *self.last_loaded_commit.write().unwrap() = Some(commit_oid.clone());
        *self.last_loaded_commit_time.write().unwrap() = Some(commit_time);

        info!(
            "{}",
            green_bold(format!(
                "✅ FireHOL threat metadata active: {} rules mapped to threat categories.",
                bold_num(report.total_rules())
            ))
        );

        info!(
            "{}",
            green_bold(format!(
                "🎉 FireHOL {} completed successfully: {} active rules in eBPF kernel maps! 🛡️",
                prefix,
                bold_num(report.total_rules())
            ))
        );

        Ok(report)
    }

    /// Check if remote repository has newer commits and update only when necessary.
    pub fn reload_if_updated(
        &self,
        map_manager: &mut MapManager,
    ) -> Result<Option<FireholSyncReport>, FirewallError> {
        let report = self.synchronize_and_load(map_manager)?;
        if report.total_rules() == 0 && self.has_active_rules() {
            // Already up-to-date and skipped
            Ok(None)
        } else {
            Ok(Some(report))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_firehol_config_defaults() {
        let cfg = FireholConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.repo_url, crate::firehol::git_repository::FIREHOL_DEFAULT_GIT_URL);
        assert_eq!(cfg.default_branch, "master");
    }

    #[test]
    fn test_firehol_blocklist_flow_without_maps() {
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
        let commit_oid = work_repo
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

        let blocklist = FireholBlockList::new(config, None);
        assert!(!blocklist.has_active_rules());
        assert!(blocklist.last_loaded_commit().is_none());
        assert!(blocklist.last_loaded_commit_time().is_none());
        let _lock = blocklist.sync_lock();

        // 1. Initial startup load (without map_manager)
        let report = blocklist.synchronize_and_load_internal(None, true).unwrap();
        assert_eq!(report.exact_v4_count, 2);
        assert!(blocklist.has_active_rules());
        assert_eq!(blocklist.last_loaded_commit().as_deref(), Some(commit_oid.to_string().as_str()));
        assert!(blocklist.last_loaded_commit_time().is_some());

        let reg = blocklist.registry();
        assert!(!reg.is_empty());
        let resolved = blocklist.resolve_rule(1);
        assert!(resolved.is_some());

        // 2. Runtime reload with no changes -> skips reload!
        let report2 = blocklist.synchronize_and_load_internal(None, false).unwrap();
        assert_eq!(report2.total_rules(), 0);
    }
}
