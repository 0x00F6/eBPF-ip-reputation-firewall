//! FireHOL Git repository synchronization via `git2` (libgit2).
//!
//! Replicates the high-reliability synchronization behavior of the C++ reference:
//! 1. Checks if the repository exists locally; if not, performs a shallow clone (`depth=1`).
//! 2. If present, verifies `origin` remote URL against expected URL.
//! 3. Inspects remote `HEAD` over network without fetching; if commit hashes match, terminates immediately.
//! 4. If remote has changed, performs shallow fetch (`depth=1`).
//! 5. Compares commit timestamps and performs `git reset --hard` to align the working tree.
//! 6. Updates Prometheus metrics tracking operations, latencies, timestamps, and commit hashes.

use crate::console::*;
use crate::firehol::metrics::FireholMetrics;
use git2::{
    build::{CheckoutBuilder, RepoBuilder},
    AutotagOption, Direction, FetchOptions, Oid, RemoteCallbacks, Repository, ResetType,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicI64,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

/// Default upstream FireHOL repository URL.
pub const FIREHOL_DEFAULT_GIT_URL: &str = "https://github.com/firehol/blocklist-ipsets";

/// Default Git branch for FireHOL.
pub const FIREHOL_DEFAULT_BRANCH: &str = "master";

/// Status result of a repository synchronization attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Newly cloned from remote
    Cloned {
        commit_oid: String,
        commit_time: i64,
    },
    /// Existing repo updated to newer remote commit
    Updated {
        commit_oid: String,
        commit_time: i64,
    },
    /// Existing repo is already identical to remote HEAD (zero fetch done)
    UpToDate {
        commit_oid: String,
        commit_time: i64,
    },
}

/// Errors occurring during Git repository operations.
#[derive(thiserror::Error, Debug)]
pub enum GitRepoError {
    #[error("Git operation failed: {0}")]
    Git(#[from] git2::Error),

    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Repository remote origin URL mismatch: expected '{expected}', found '{actual}'")]
    RemoteUrlMismatch { expected: String, actual: String },

    #[error("Failed to parse remote HEAD branch")]
    MissingHead,

    #[error("Repository at '{path}' is corrupted or uninitialized: {reason}")]
    Corrupted { path: PathBuf, reason: String },
}

/// Manager for cloning, fetching, and maintaining the FireHOL blocklist Git repository.
pub struct FireholGitRepository {
    repo: Option<Repository>,
    last_commit_time: AtomicI64,
    last_commit_oid: Option<String>,
}

impl Default for FireholGitRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl FireholGitRepository {
    /// Create an uninitialized repository manager.
    pub fn new() -> Self {
        Self {
            repo: None,
            last_commit_time: AtomicI64::new(0),
            last_commit_oid: None,
        }
    }

    /// Check whether the Git repository exists and has a valid `.git` directory at `path`.
    pub fn exists_at(&self, path: &Path) -> bool {
        let git_dir = path.join(".git");
        if !git_dir.exists() {
            return false;
        }
        Repository::open(path).is_ok()
    }

    /// Return the commit OID of the currently loaded repository HEAD, if known.
    pub fn last_commit_oid(&self) -> Option<&str> {
        self.last_commit_oid.as_deref()
    }

    /// Return the commit timestamp of the currently loaded repository HEAD.
    pub fn last_commit_time(&self) -> i64 {
        self.last_commit_time
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Convenience helper to clone or synchronize and return the local checkout path.
    pub fn prepare_repository(
        &mut self,
        repo_url: &str,
        local_path: &Path,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<PathBuf, GitRepoError> {
        self.synchronize(local_path, repo_url, default_branch, metrics)?;
        Ok(local_path.to_path_buf())
    }

    /// Convenience helper to synchronize with (repo_url, local_path, default_branch, metrics) signature.
    pub fn execute_sync(
        &mut self,
        repo_url: &str,
        local_path: &Path,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<SyncStatus, GitRepoError> {
        self.synchronize(local_path, repo_url, default_branch, metrics)
    }

    /// Synchronize the FireHOL repository.
    ///
    /// 1. Clones the repository with depth=1 if it does not exist locally.
    /// 2. If it exists, connects to the remote to check the remote HEAD commit.
    /// 3. If remote commit matches local commit, terminates immediately without fetching.
    /// 4. If remote has newer changes, executes a shallow fetch and `git reset --hard` to align.
    pub fn synchronize(
        &mut self,
        local_path: &Path,
        repo_url: &str,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<SyncStatus, GitRepoError> {
        let overall_start = Instant::now();

        // Ensure parent directory exists
        if let Some(parent) = local_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 1. Check if repository exists locally
        let is_existing = self.exists_at(local_path);

        if !is_existing {
            // Shallow clone (depth = 1)
            let clone_start = Instant::now();
            let status = self.shallow_clone(local_path, repo_url, default_branch, metrics)?;
            let duration = clone_start.elapsed().as_secs_f64();

            if let Some(m) = metrics {
                m.git_clones_total.inc();
                m.git_clone_duration_seconds.observe(duration);
                m.git_sync_duration_seconds
                    .observe(overall_start.elapsed().as_secs_f64());
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                m.git_last_sync_timestamp.set(now);
            }

            Ok(status)
        } else {
            // Open existing repository
            if self.repo.is_none() {
                self.repo = Some(Repository::open(local_path)?);
            }

            let sync_result = self.fetch_and_reset(repo_url, default_branch, metrics);

            let total_dur = overall_start.elapsed().as_secs_f64();
            if let Some(m) = metrics {
                m.git_sync_duration_seconds.observe(total_dur);
                if sync_result.is_err() {
                    m.git_errors_total.inc();
                } else {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    m.git_last_sync_timestamp.set(now);
                }
            }

            sync_result
        }
    }

    /// Performs a shallow clone (`depth=1`) of the target branch.
    fn shallow_clone(
        &mut self,
        local_path: &Path,
        repo_url: &str,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<SyncStatus, GitRepoError> {
        info!(
            "{}",
            cyan_bold(format!(
                "📥 Performing shallow clone of FireHOL repository from '{}' (branch: '{}')...",
                repo_url, default_branch
            ))
        );

        // If local_path exists but is empty or broken, clean it up before cloning
        if local_path.exists() {
            let _ = std::fs::remove_dir_all(local_path);
        }

        let mut fetch_opts = FetchOptions::new();
        // Depth 1 shallow clone
        if repo_url.starts_with("http") {
            fetch_opts.depth(1);
        }
        fetch_opts.download_tags(AutotagOption::None);

        let mut builder = RepoBuilder::new();
        builder.branch(default_branch);
        builder.fetch_options(fetch_opts);

        let cloned_repo = builder.clone(repo_url, local_path).inspect_err(|_e| {
            if let Some(m) = metrics {
                m.git_errors_total.inc();
            }
        })?;

        let mut commit_oid = String::new();
        let mut commit_time: i64 = 0;

        if let Ok(head) = cloned_repo.head() {
            if let Ok(commit) = head.peel_to_commit() {
                commit_oid = commit.id().to_string();
                commit_time = commit.time().seconds();
            }
        }

        self.last_commit_time
            .store(commit_time, std::sync::atomic::Ordering::Relaxed);
        self.last_commit_oid = Some(commit_oid.clone());
        self.repo = Some(cloned_repo);

        if let Some(m) = metrics {
            m.git_last_commit_timestamp.set(commit_time);
        }

        Ok(SyncStatus::Cloned {
            commit_oid,
            commit_time,
        })
    }

    /// Ensure repository exists and is open. Returns `true` if shallow clone was executed, `false` if existing.
    pub fn ensure_repository(
        &mut self,
        local_path: &Path,
        repo_url: &str,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<bool, GitRepoError> {
        if self.exists_at(local_path) {
            if self.repo.is_none() {
                self.repo = Some(Repository::open(local_path)?);
            }
            Ok(false)
        } else {
            let start = Instant::now();
            info!(
                "{}",
                cyan_bold(format!(
                    "📥 FireHOL repository not found at '{}'; performing shallow clone...",
                    local_path.display()
                ))
            );

            if local_path.exists() {
                let _ = std::fs::remove_dir_all(local_path);
            }

            let mut fetch_opts = FetchOptions::new();
            if repo_url.starts_with("http") {
                fetch_opts.depth(1);
            }
            fetch_opts.download_tags(AutotagOption::None);

            let mut builder = RepoBuilder::new();
            builder.branch(default_branch);
            builder.fetch_options(fetch_opts);

            let cloned_repo = builder.clone(repo_url, local_path)?;
            let duration = start.elapsed().as_secs_f64();

            if let Some(m) = metrics {
                m.git_clones_total.inc();
                m.git_clone_duration_seconds.observe(duration);
            }

            info!(
                "{}",
                green_bold(format!(
                    "✅ FireHOL shallow clone completed in {:.2}s",
                    bold(format!("{:.2}", duration))
                ))
            );

            self.repo = Some(cloned_repo);
            Ok(true)
        }
    }

    /// Fetches remote changes only when remote HEAD has changed, then hard resets working copy.
    fn fetch_and_reset(
        &mut self,
        repo_url: &str,
        default_branch: &str,
        metrics: Option<&FireholMetrics>,
    ) -> Result<SyncStatus, GitRepoError> {
        let repo = self.repo.as_ref().ok_or_else(|| GitRepoError::Corrupted {
            path: PathBuf::new(),
            reason: "Repository instance uninitialized".into(),
        })?;

        // 1. Verify remote 'origin' matches expected URL
        let mut remote = repo.find_remote("origin")?;
        let origin_url = remote.url().unwrap_or("");
        if origin_url != repo_url {
            return Err(GitRepoError::RemoteUrlMismatch {
                expected: repo_url.to_string(),
                actual: origin_url.to_string(),
            });
        }

        // 2. Get local HEAD commit OID and timestamp
        let mut local_oid: Option<Oid> = None;
        let mut local_time: i64 = 0;
        if let Ok(head_ref) = repo.head() {
            if let Some(target) = head_ref.target() {
                local_oid = Some(target);
            }
            if let Ok(commit) = head_ref.peel_to_commit() {
                local_time = commit.time().seconds();
            }
        }

        // 3. Connect to remote and inspect remote HEAD without fetching (with retry)
        let mut needs_fetch = true;
        let mut connect_err: Option<git2::Error> = None;
        let max_retries = 3;

        for attempt in 1..=max_retries {
            let callbacks = RemoteCallbacks::new();
            match remote.connect_auth(Direction::Fetch, Some(callbacks), None) {
                Ok(conn) => {
                    connect_err = None;
                    let target_ref_name = format!("refs/heads/{}", default_branch);
                    if let Ok(list) = conn.list() {
                        for head in list {
                            if head.name() == target_ref_name {
                                if let Some(loc) = local_oid {
                                    if loc == head.oid() {
                                        needs_fetch = false;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    break;
                }
                Err(err) => {
                    connect_err = Some(err);
                    if attempt < max_retries {
                        warn!(
                            "{}",
                            yellow_bold(format!(
                                "⚠️ Connection to remote Git '{}' attempt {}/{} failed: {}. Retrying in {}s...",
                                repo_url, attempt, max_retries, connect_err.as_ref().unwrap(), attempt * 2
                            ))
                        );
                        std::thread::sleep(std::time::Duration::from_secs((attempt * 2) as u64));
                    }
                }
            }
        }

        if let Some(err) = connect_err {
            if let Some(m) = metrics {
                m.git_errors_total.inc();
            }
            return Err(GitRepoError::Git(err));
        }

        let local_oid_str = local_oid.map(|o| o.to_string()).unwrap_or_default();

        // 4. Terminate immediately without fetch if hashes match
        if !needs_fetch {
            let commit_date = if local_time > 0 {
                chrono::DateTime::from_timestamp(local_time, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };
            info!(
                "Local FireHOL repository is already up-to-date (commit: {}, date: {})",
                local_oid_str, commit_date
            );
            if let Some(m) = metrics {
                m.git_up_to_date_total.inc();
            }
            self.last_commit_time
                .store(local_time, std::sync::atomic::Ordering::Relaxed);
            self.last_commit_oid = Some(local_oid_str.clone());
            return Ok(SyncStatus::UpToDate {
                commit_oid: local_oid_str,
                commit_time: local_time,
            });
        }

        // 5. Shallow fetch remote branch (with retry)
        info!(
            "{}",
            cyan_bold(format!(
                "🔄 Changes detected upstream, fetching FireHOL branch '{}'...",
                default_branch
            ))
        );
        let fetch_start = Instant::now();
        let refspec = format!(
            "+refs/heads/{}:refs/remotes/origin/{}",
            default_branch, default_branch
        );

        let mut fetch_err: Option<git2::Error> = None;
        for attempt in 1..=max_retries {
            let mut fetch_opts = FetchOptions::new();
            if repo_url.starts_with("http") {
                fetch_opts.depth(1);
            }
            fetch_opts.download_tags(AutotagOption::None);

            match remote.fetch(&[&refspec], Some(&mut fetch_opts), None) {
                Ok(()) => {
                    fetch_err = None;
                    break;
                }
                Err(err) => {
                    fetch_err = Some(err);
                    if attempt < max_retries {
                        warn!(
                            "{}",
                            yellow_bold(format!(
                                "⚠️ Git fetch '{}' attempt {}/{} failed: {}. Retrying in {}s...",
                                default_branch,
                                attempt,
                                max_retries,
                                fetch_err.as_ref().unwrap(),
                                attempt * 2
                            ))
                        );
                        std::thread::sleep(std::time::Duration::from_secs((attempt * 2) as u64));
                    }
                }
            }
        }

        if let Some(err) = fetch_err {
            if let Some(m) = metrics {
                m.git_errors_total.inc();
            }
            return Err(GitRepoError::Git(err));
        }

        let fetch_dur = fetch_start.elapsed().as_secs_f64();
        if let Some(m) = metrics {
            m.git_fetches_total.inc();
            m.git_fetch_duration_seconds.observe(fetch_dur);
        }

        // 6. Hard reset working tree to upstream remote reference
        let remote_ref_name = format!("refs/remotes/origin/{}", default_branch);
        let remote_ref = repo.find_reference(&remote_ref_name)?;
        let remote_commit = remote_ref.peel_to_commit()?;
        let remote_oid = remote_commit.id().to_string();
        let remote_time = remote_commit.time().seconds();

        let mut checkout = CheckoutBuilder::new();
        checkout.force();

        repo.reset(
            remote_commit.as_object(),
            ResetType::Hard,
            Some(&mut checkout),
        )?;

        self.last_commit_time
            .store(remote_time, std::sync::atomic::Ordering::Relaxed);
        self.last_commit_oid = Some(remote_oid.clone());

        if let Some(m) = metrics {
            m.git_last_commit_timestamp.set(remote_time);
        }

        Ok(SyncStatus::Updated {
            commit_oid: remote_oid,
            commit_time: remote_time,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tempfile::tempdir;

    // Explicit branch and timestamps keep these local-only fixtures independent of Git config.
    fn commit_feed(repo: &Repository, contents: &str, timestamp: i64) -> Oid {
        std::fs::write(repo.workdir().unwrap().join("feed.ipset"), contents).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("feed.ipset")).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let signature = git2::Signature::new(
            "Test",
            "test@example.invalid",
            &git2::Time::new(timestamp, 0),
        )
        .unwrap();
        let parent = repo.head().ok().map(|head| head.peel_to_commit().unwrap());
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Update feed",
            &tree,
            &parent.iter().collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn sync_updates_checkout_and_metrics_then_skips_redundant_fetch() {
        let dir = tempdir().unwrap();
        let upstream = Repository::init(dir.path().join("upstream")).unwrap();
        upstream.set_head("refs/heads/feeds").unwrap();
        let first = commit_feed(&upstream, "192.0.2.1\n", 1_700_000_000);
        let url = upstream.workdir().unwrap().to_str().unwrap();
        let checkout = dir.path().join("nested/checkout");
        let metrics = FireholMetrics::new(&prometheus::Registry::new()).unwrap();
        let mut manager = FireholGitRepository::default();
        assert_eq!(
            manager
                .prepare_repository(url, &checkout, "feeds", Some(&metrics))
                .unwrap(),
            checkout
        );
        assert_eq!(manager.last_commit_oid(), Some(first.to_string().as_str()));
        assert_eq!(metrics.git_clones_total.get(), 1);
        assert_eq!(metrics.git_clone_duration_seconds.get_sample_count(), 1);

        // A restarted daemon must reopen the checkout and replace stale tracked content.
        let mut manager = FireholGitRepository::new();
        std::fs::write(checkout.join("feed.ipset"), "local modification\n").unwrap();
        let second = commit_feed(&upstream, "198.51.100.2\n", 1_700_000_100);
        assert_eq!(
            manager
                .execute_sync(url, &checkout, "feeds", Some(&metrics))
                .unwrap(),
            SyncStatus::Updated {
                commit_oid: second.to_string(),
                commit_time: 1_700_000_100
            }
        );
        assert_eq!(
            std::fs::read_to_string(checkout.join("feed.ipset")).unwrap(),
            "198.51.100.2\n"
        );
        assert_eq!(
            Repository::open(&checkout)
                .unwrap()
                .head()
                .unwrap()
                .target(),
            Some(second)
        );
        assert_eq!(manager.last_commit_oid(), Some(second.to_string().as_str()));
        assert_eq!(manager.last_commit_time(), 1_700_000_100);
        assert_eq!(metrics.git_last_commit_timestamp.get(), 1_700_000_100);
        assert_eq!(metrics.git_fetches_total.get(), 1);
        assert_eq!(metrics.git_fetch_duration_seconds.get_sample_count(), 1);

        assert_eq!(
            manager
                .execute_sync(url, &checkout, "feeds", Some(&metrics))
                .unwrap(),
            SyncStatus::UpToDate {
                commit_oid: second.to_string(),
                commit_time: 1_700_000_100
            }
        );
        assert_eq!(metrics.git_fetches_total.get(), 1);
        assert_eq!(metrics.git_up_to_date_total.get(), 1);
        assert_eq!(metrics.git_sync_duration_seconds.get_sample_count(), 3);
        assert!(metrics.git_last_sync_timestamp.get() > 0);
        assert_eq!(metrics.git_errors_total.get(), 0);
    }

    #[test]
    fn ensure_repository_repairs_invalid_checkout_and_reuses_existing_clone() {
        let dir = tempdir().unwrap();
        let upstream = Repository::init(dir.path().join("upstream")).unwrap();
        upstream.set_head("refs/heads/feeds").unwrap();
        commit_feed(&upstream, "203.0.113.1\n", 1_700_000_000);
        let url = upstream.workdir().unwrap().to_str().unwrap();
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::write(checkout.join("stale"), "broken checkout").unwrap();
        let metrics = FireholMetrics::new(&prometheus::Registry::new()).unwrap();
        let mut manager = FireholGitRepository::new();
        assert!(!manager.exists_at(&checkout));
        assert!(manager
            .ensure_repository(&checkout, url, "feeds", Some(&metrics))
            .unwrap());
        assert!(manager.exists_at(&checkout));
        assert!(!checkout.join("stale").exists());
        assert_eq!(
            std::fs::read_to_string(checkout.join("feed.ipset")).unwrap(),
            "203.0.113.1\n"
        );
        let mut restarted = FireholGitRepository::new();
        assert!(!restarted
            .ensure_repository(&checkout, url, "feeds", Some(&metrics))
            .unwrap());
        assert_eq!(metrics.git_clones_total.get(), 1);
        assert!(matches!(
            restarted
                .execute_sync(url, &checkout, "feeds", None)
                .unwrap(),
            SyncStatus::UpToDate { .. }
        ));
    }

    #[test]
    fn failed_clone_records_error_without_publishing_success() {
        let dir = tempdir().unwrap();
        let metrics = FireholMetrics::new(&prometheus::Registry::new()).unwrap();
        let mut manager = FireholGitRepository::new();
        let result = manager.synchronize(
            &dir.path().join("checkout"),
            dir.path().join("missing-upstream").to_str().unwrap(),
            "feeds",
            Some(&metrics),
        );
        assert!(matches!(result, Err(GitRepoError::Git(_))));
        assert_eq!(manager.last_commit_oid(), None);
        assert_eq!(manager.last_commit_time(), 0);
        assert_eq!(metrics.git_errors_total.get(), 1);
        assert_eq!(metrics.git_clones_total.get(), 0);
        assert_eq!(metrics.git_last_sync_timestamp.get(), 0);
    }

    #[test]
    fn test_git_remote_url_mismatch() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        repo.remote("origin", "https://example.com/other-repo.git")
            .unwrap();

        let mut git_repo = FireholGitRepository {
            repo: Some(repo),
            last_commit_time: AtomicI64::new(0),
            last_commit_oid: None,
        };

        let res = git_repo.fetch_and_reset(
            "https://github.com/firehol/blocklist-ipsets",
            "master",
            None,
        );

        assert!(matches!(res, Err(GitRepoError::RemoteUrlMismatch { .. })));
    }

    #[test]
    fn test_git_clone_and_up_to_date() {
        // Create a local bare repository as mock remote
        let remote_dir = tempdir().unwrap();
        let _bare_repo = Repository::init_bare(remote_dir.path()).unwrap();

        // Create initial commit in a working clone
        let work_dir = tempdir().unwrap();
        let work_repo =
            Repository::clone(remote_dir.path().to_str().unwrap(), work_dir.path()).unwrap();

        let sig = git2::Signature::now("Tester", "test@example.com").unwrap();
        let file_path = work_dir.path().join("test.ipset");
        std::fs::write(&file_path, "192.0.2.1\n").unwrap();

        let mut index = work_repo.index().unwrap();
        index.add_path(Path::new("test.ipset")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = work_repo.find_tree(tree_id).unwrap();
        let commit_oid = work_repo
            .commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        // Push to bare remote
        let mut remote = work_repo.find_remote("origin").unwrap();
        remote
            .push(&["refs/heads/master:refs/heads/master"], None)
            .unwrap();

        // Now test our FireholGitRepository
        let local_dest = tempdir().unwrap();
        let mut git_repo = FireholGitRepository::new();
        let remote_url = remote_dir.path().to_str().unwrap();

        let status = git_repo
            .synchronize(local_dest.path(), remote_url, "master", None)
            .unwrap();

        assert_eq!(
            status,
            SyncStatus::Cloned {
                commit_oid: commit_oid.to_string(),
                commit_time: git_repo.last_commit_time(),
            }
        );

        // Second synchronization with unchanged mock remote should return UpToDate
        let status2 = git_repo
            .synchronize(local_dest.path(), remote_url, "master", None)
            .unwrap();

        assert_eq!(
            status2,
            SyncStatus::UpToDate {
                commit_oid: commit_oid.to_string(),
                commit_time: git_repo.last_commit_time(),
            }
        );
    }
}
