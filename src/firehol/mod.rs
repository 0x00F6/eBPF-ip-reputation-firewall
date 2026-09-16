//! FireHOL Blocklist Integration Subsystem
//!
//! Provides automated Git synchronization, parallel parsing, and atomic eBPF map integration
//! for the upstream FireHOL reputation blocklists (https://github.com/firehol/blocklist-ipsets).

pub mod blocklist;
pub mod entry;
pub mod git_repository;
pub mod metadata;
pub mod metrics;
pub mod parser;
pub mod scheduler;
pub mod sync;

pub use blocklist::{FireholBlockList, FireholConfig};
pub use entry::{FireholEntry, FireholIpTarget};
pub use git_repository::{FireholGitRepository, GitRepoError, SyncStatus};
pub use metadata::{
    normalize_firehol_date, FireholCategory, FireholMetadata, FireholMetadataRegistry,
    FireholRuleInfo,
};
pub use metrics::FireholMetrics;
pub use parser::{FireholDataSet, FireholParseError, FireholParser};
pub use scheduler::{execute_firehol_sync, FireholScheduler, FireholSyncOutcome};
pub use sync::{FireholSyncManager, FireholSyncReport};
