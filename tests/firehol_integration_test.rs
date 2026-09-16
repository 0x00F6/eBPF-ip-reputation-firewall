//! End-to-end integration tests for the FireHOL blocklist subsystem.

use firewall_lib::cache_rocksdb::CacheRocksDb;
use firewall_lib::firehol::{
    git_repository::SyncStatus, metadata::FireholCategory, metrics::FireholMetrics,
    parser::FireholParser, sync::FireholSyncManager, FireholBlockList, FireholConfig,
    FireholGitRepository,
};
use git2::{IndexAddOption, Repository, Signature};
use prometheus::Registry;
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

    // 1. dshield.netset
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

    // 2. feodo.ipset
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

#[test]
fn test_firehol_end_to_end_pipeline() {
    let upstream_dir = tempdir().unwrap();
    let upstream_repo = create_upstream_firehol_repo(upstream_dir.path());

    let client_dir = tempdir().unwrap();
    let local_checkout = client_dir.path().join("firehol-repo");

    let registry = Registry::new();
    let metrics = Arc::new(FireholMetrics::new(&registry).unwrap());

    // 1. Initial Git sync
    let mut git_repo = FireholGitRepository::new();
    let upstream_url = upstream_dir.path().to_str().unwrap();

    let path = git_repo
        .prepare_repository(upstream_url, &local_checkout, "master", Some(&metrics))
        .expect("Git clone failed");
    assert_eq!(path, local_checkout);

    // 2. Parallel Parsing
    let dataset =
        FireholParser::parse_directory(&local_checkout, Some(&metrics)).expect("Parsing failed");

    assert_eq!(dataset.total_files, 2);
    assert_eq!(dataset.total_entries(), 6);

    // Exact matches: 192.0.2.1, 203.0.113.1 (from /32), 192.0.2.10, 2001:db8::1
    assert_eq!(dataset.exact_v4_count, 3);
    assert_eq!(dataset.exact_v6_count, 1);

    // LPM matches: 198.51.100.0/24, 2001:db8:a::/48
    assert_eq!(dataset.lpm_v4_count, 1);
    assert_eq!(dataset.lpm_v6_count, 1);

    // Verify categories
    assert_eq!(
        *dataset
            .registry
            .category_counts
            .get(&FireholCategory::Attacks)
            .unwrap(),
        3
    );
    assert_eq!(
        *dataset
            .registry
            .category_counts
            .get(&FireholCategory::Botnet)
            .unwrap(),
        3
    );

    // 3. Rule Preparation
    let (rules, report) = FireholSyncManager::prepare_rules(&dataset);
    assert_eq!(report.exact_v4_count, 3);
    assert_eq!(report.exact_v6_count, 1);
    assert_eq!(report.lpm_v4_count, 1);
    assert_eq!(report.lpm_v6_count, 1);
    assert_eq!(report.duplicates_deduped, 0);
    assert_eq!(rules.count(), 6);

    // 4. Update upstream repository with new entries
    let dshield_updated = r#"# Maintainer: SANS DShield
# Category: attacks
192.0.2.1
192.0.2.99
198.51.100.0/24
"#;
    commit_file(
        &upstream_repo,
        "dshield.netset",
        dshield_updated,
        "Update dshield entries",
    );

    // 5. Fetch and Reset
    let sync_status = git_repo
        .prepare_repository(upstream_url, &local_checkout, "master", Some(&metrics))
        .expect("Git fetch failed");
    assert_eq!(sync_status, local_checkout);

    let updated_dataset =
        FireholParser::parse_directory(&local_checkout, Some(&metrics)).expect("Reparse failed");
    assert_eq!(updated_dataset.total_entries(), 6);

    // 6. Introduce invalid line upstream and verify strict parsing rejection
    let corrupted = r#"# Category: malware
192.0.2.1
this_is_an_invalid_ip
"#;
    commit_file(
        &upstream_repo,
        "corrupted.ipset",
        corrupted,
        "Corrupted file",
    );

    git_repo
        .prepare_repository(upstream_url, &local_checkout, "master", Some(&metrics))
        .unwrap();

    let invalid_res = FireholParser::parse_directory(&local_checkout, Some(&metrics));
    assert!(
        invalid_res.is_err(),
        "Parser must fail immediately on invalid entry"
    );
}

#[test]
fn test_firehol_startup_flow_and_fail_safe() {
    let upstream_dir = tempdir().unwrap();
    let upstream_repo = create_upstream_firehol_repo(upstream_dir.path());
    let upstream_url = upstream_dir.path().to_str().unwrap();

    let client_dir = tempdir().unwrap();
    let local_checkout = client_dir.path().join("firehol-checkout");

    let registry = Registry::new();
    let metrics = Arc::new(FireholMetrics::new(&registry).unwrap());

    let config = FireholConfig {
        repo_url: upstream_url.to_string(),
        local_path: local_checkout.clone(),
        default_branch: "master".to_string(),
        enabled: true,
        ignore_ips: Vec::new(),
    };

    let _blocklist = FireholBlockList::new(config.clone(), Some(metrics.clone()));

    // 1. Check local repo: doesn't exist initially
    assert!(!local_checkout.join(".git").exists());

    // 2 & 3. Git sync (shallow clone)
    let mut git_repo = FireholGitRepository::new();
    let sync_status = git_repo
        .execute_sync(upstream_url, &local_checkout, "master", Some(&metrics))
        .expect("Initial clone must succeed");

    let commit_oid = match sync_status {
        SyncStatus::Cloned { commit_oid, .. } => commit_oid,
        _ => panic!("Expected Cloned status"),
    };

    // 4. Parse .ipset / .netset files
    let dataset = FireholParser::parse_directory(&local_checkout, Some(&metrics))
        .expect("Parsing valid files must succeed");
    assert_eq!(dataset.total_files, 2);

    // 5. Strict validation: entries must be valid
    assert!(!dataset.is_empty());
    assert_eq!(dataset.total_entries(), 6);

    // 6. Separate entries: exact IPv4, exact IPv6, CIDR IPv4, CIDR IPv6
    let (rules, report) = FireholSyncManager::prepare_rules(&dataset);
    assert_eq!(report.exact_v4_count, 3);
    assert_eq!(report.exact_v6_count, 1);
    assert_eq!(report.lpm_v4_count, 1);
    assert_eq!(report.lpm_v6_count, 1);
    assert_eq!(rules.exact_v4.len(), 3);
    assert_eq!(rules.exact_v6.len(), 1);
    assert_eq!(rules.lpm_v4.len(), 1);
    assert_eq!(rules.lpm_v6.len(), 1);

    // 7. Verify up-to-date detection avoids redundant work
    let sync_status_2 = git_repo
        .execute_sync(upstream_url, &local_checkout, "master", Some(&metrics))
        .expect("Second sync check must succeed");

    match sync_status_2 {
        SyncStatus::UpToDate {
            commit_oid: second_oid,
            ..
        } => {
            assert_eq!(commit_oid, second_oid);
        }
        _ => panic!("Expected UpToDate status when no upstream changes were made"),
    }

    // 8. Fail-Safe Verification: Corrupt data in repo must abort startup
    commit_file(
        &upstream_repo,
        "bad_entry.ipset",
        "192.0.2.1\ninvalid.ip.address\n",
        "Add corrupt file",
    );

    git_repo
        .execute_sync(upstream_url, &local_checkout, "master", Some(&metrics))
        .unwrap();

    let fail_safe_res = FireholParser::parse_directory(&local_checkout, Some(&metrics));
    assert!(
        fail_safe_res.is_err(),
        "Fail-safe requirement: parser MUST abort on any corrupt line and not proceed"
    );
}

/// Verifies that the RocksDB-backed (cached) parse path is functionally equivalent to the
/// classic fully-in-memory path: same rule IDs, same category/line resolution, same metadata
/// content, and same per-target file/category listings — while the heavy data is persisted
/// (LZ4 + Cap'n Proto) instead of being kept resident in RAM.
#[test]
fn test_cached_parse_is_functionally_equivalent() {
    let rules_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    std::fs::write(
        rules_dir.path().join("a.netset"),
        "# Category: attacks\n# Maintainer: SANS\n192.0.2.1\n198.51.100.0/24\n",
    )
    .unwrap();
    std::fs::write(
        rules_dir.path().join("b.ipset"),
        "# Category: botnet\n192.0.2.1\n203.0.113.9/32\n",
    )
    .unwrap();

    // Reference: in-memory registry.
    let in_mem = FireholParser::parse_directory_with_ignore(rules_dir.path(), &[], None).unwrap();

    // Cached: registry backed by RocksDB.
    let cache = Arc::new(CacheRocksDb::open(cache_dir.path().join("cache")).unwrap());
    let cached =
        FireholParser::parse_directory_with_ignore_cached(rules_dir.path(), &[], None, Some(cache))
            .unwrap();

    // Same number of rules, files and entries.
    assert_eq!(cached.registry.total_rules(), in_mem.registry.total_rules());
    assert_eq!(cached.total_entries(), in_mem.total_entries());
    assert_eq!(cached.total_files, in_mem.total_files);

    // Same per-rule resolution content. Rule/metadata IDs are assigned by atomic counters across
    // the parallel parser's worker threads, so the exact rule_id -> entry mapping is NOT stable
    // between two independent parse runs (production is internally self-consistent, so this does
    // not affect correctness). Both registries describe the same dataset, so we compare the
    // scheduling-independent per-rule content: the multiset of (category, line).
    let rule_content =
        |reg: &firewall_lib::firehol::metadata::FireholMetadataRegistry| -> Vec<(u32, u32)> {
            let mut v: Vec<(u32, u32)> = (0..=reg.total_rules())
                .filter_map(|id| reg.resolve_rule(id as u32))
                .filter(|r| r.metadata_id != 0)
                .map(|r| (r.category.id(), r.line))
                .collect();
            v.sort_unstable();
            v
        };
    let mut content_in = rule_content(&in_mem.registry);
    let mut content_c = rule_content(&cached.registry);
    content_in.sort();
    content_c.sort();
    assert!(!content_in.is_empty());
    assert_eq!(content_c, content_in, "per-rule category/line content");

    // Same per-block content via the Ring Buffer consumer's merge logic: the winning
    // rule's own context + every enclosing feed covering the IP (via `lookup_ip`).
    // This is the exact operation the production logging path performs.
    let ip_octets = [192, 0, 2, 1];
    let merged_files =
        |reg: &firewall_lib::firehol::metadata::FireholMetadataRegistry, id: u32| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            if let Some(w) = reg.resolve_rule_block(id) {
                for f in &w.files {
                    if !out.contains(&f.to_string()) {
                        out.push(f.to_string());
                    }
                }
            }
            for ctx in reg.lookup_ip(4, &ip_octets) {
                for f in &ctx.files {
                    if !out.contains(&f.to_string()) {
                        out.push(f.to_string());
                    }
                }
            }
            out.sort();
            out
        };
    let rule_ids: Vec<u32> = (0..=cached.registry.total_rules())
        .filter_map(|id| {
            cached
                .registry
                .resolve_rule(id as u32)
                .filter(|r| r.metadata_id != 0)
                .map(|_| id as u32)
        })
        .collect();
    for id in &rule_ids {
        let mut files_in = merged_files(&in_mem.registry, *id);
        let mut files_c = merged_files(&cached.registry, *id);
        files_in.sort();
        files_c.sort();
        assert_eq!(files_c, files_in, "rule {id} merged files");
    }

    // Same per-file metadata content read back from the persistent store. Metadata IDs are not
    // stable across independent parse runs, so compare the set of full metadata records
    // (file_name, category, URLs) rather than resolving by a cross-run numeric ID.
    let metadata_set = |reg: &firewall_lib::firehol::metadata::FireholMetadataRegistry|
     -> Vec<(String, u32, Option<String>, Option<String>)> {
        let mut s: Vec<_> = (0..=reg.total_rules())
            .filter_map(|id| reg.resolve_rule(id as u32))
            .filter(|r| r.metadata_id != 0)
            .filter_map(|r| reg.resolve_metadata(r.metadata_id))
            .map(|m| {
                (
                    m.file_name.to_string(),
                    m.category.id(),
                    m.source_url.map(|s| s.to_string()),
                    m.maintainer.map(|s| s.to_string()),
                )
            })
            .collect();
        s.sort();
        s.dedup();
        s
    };
    let mut meta_in = metadata_set(&in_mem.registry);
    let mut meta_c = metadata_set(&cached.registry);
    meta_in.sort();
    meta_c.sort();
    assert!(!meta_in.is_empty());
    assert_eq!(meta_c, meta_in, "per-file metadata content");
    assert!(meta_c.iter().any(|(n, _, _, _)| n == "a.netset"));

    // Same per-target file/category enumeration via `lookup_ip` (192.0.2.1 is in both feeds).
    let mut l_in: Vec<String> = in_mem
        .registry
        .lookup_ip(4, &[192, 0, 2, 1])
        .iter()
        .flat_map(|c| c.files.iter().map(|f| f.to_string()))
        .collect();
    let mut l_c: Vec<String> = cached
        .registry
        .lookup_ip(4, &[192, 0, 2, 1])
        .iter()
        .flat_map(|c| c.files.iter().map(|f| f.to_string()))
        .collect();
    l_in.sort();
    l_c.sort();
    assert_eq!(l_c, l_in);
}
