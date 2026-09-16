//! Regression tests for the static-vs-FireHOL rule ID namespace collision.
//!
//! Static rules (loaded from `rules/*.txt`, e.g. the private-range CIDR
//! `192.168.0.0/16`) and FireHOL blocklist rules share the same eBPF maps and
//! both used to be assigned rule IDs starting at 1. When a packet matched a
//! *static* rule, the eBPF program reported that static rule's numeric ID, which
//! the userspace layer then resolved against the *FireHOL* metadata registry.
//! The registry misattributed that ID to an unrelated FireHOL rule, producing a
//! log line whose file:line did not correspond to the matched IP (e.g. a
//! `192.168.1.254` mDNS packet being labelled `firehol_anonymous.netset:45,
//! firehol_proxies.netset:46`).
//!
//! The fix gives static rules their own disjoint ID range (`STATIC_RULE_BASE`),
//! so a static match is never looked up in the FireHOL registry and no wrong
//! file:line is ever reported.

use firewall_lib::firehol::entry::FireholIpTarget;
use firewall_lib::firehol::metadata::{FireholMetadata, FireholMetadataRegistry, FireholRuleInfo};
use firewall_lib::firehol::parser::FireholParser;
use firewall_lib::loader::RuleLoader;
use firewall_lib::loader::STATIC_RULE_BASE;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;

fn static_rule_id_for_192_168_0_0_16(paths: &[&Path]) -> u32 {
    let rules = RuleLoader::load_from_paths(paths).expect("load static rules");
    for (prefix, addr, val) in &rules.lpm_v4 {
        if *prefix == 16 && addr == &[192, 168, 0, 0] {
            return val.rule_id;
        }
    }
    panic!("192.168.0.0/16 not found in static rules");
}

#[test]
fn static_rule_ids_are_disjoint_from_firehol_range() {
    // Load the shipped static blocklists. The private-range CIDR that matched the
    // user's packet must live in the static namespace, i.e. >= STATIC_RULE_BASE.
    let paths = [
        Path::new("rules/blocklist.txt").to_path_buf(),
        Path::new("rules/blocklist_v6.txt").to_path_buf(),
        Path::new("rules/cidr_ranges.txt").to_path_buf(),
    ];
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let rules = RuleLoader::load_from_paths(&refs).expect("load static rules");

    let mut found = false;
    for (_prefix, _addr, val) in &rules.lpm_v4 {
        assert!(
            val.rule_id >= STATIC_RULE_BASE,
            "static LPM rule_id {} collides with the FireHOL namespace",
            val.rule_id
        );
        found = true;
    }
    for val in rules.exact_v4.values() {
        assert!(val.rule_id >= STATIC_RULE_BASE);
    }
    assert!(found, "expected at least one static LPM rule");
}

#[test]
fn elaborate_firehol_registry_never_resolves_a_static_rule_id() {
    // Build a small FireHOL dataset reminiscent of the user's setup:
    // firehol_anonymous.netset line 45 = exact IP 1.0.133.100 and
    // firehol_proxies.netset line 46 = exact IP 1.0.133.100, both categorized
    // as anonymizers and sharing a target.
    let dir = tempdir().unwrap();
    let anon = dir.path().join("firehol_anonymous.netset");
    let proxies = dir.path().join("firehol_proxies.netset");
    let mut a = File::create(&anon).unwrap();
    let mut p = File::create(&proxies).unwrap();
    for i in 1..45 {
        writeln!(a, "10.0.0.{}", i).unwrap();
    }
    writeln!(a, "1.0.133.100").unwrap(); // line 45
    writeln!(a, "1.0.136.7").unwrap();
    for i in 1..46 {
        writeln!(p, "10.0.0.{}", i).unwrap();
    }
    writeln!(p, "1.0.133.100").unwrap(); // line 46
    writeln!(p, "1.0.136.7").unwrap();

    let dataset = FireholParser::parse_directory(dir.path(), None).unwrap();
    let registry = &dataset.registry;

    // Locate the FireHOL rule that *would* be misattributed: exact IP 1.0.133.100.
    // It must still resolve through the (dense) FireHOL range.
    let victim = registry
        .resolve_rule_block(
            dataset
                .entries
                .iter()
                .find(|e| e.target == FireholIpTarget::ExactV4([1, 0, 133, 100]))
                .expect("firehol exact 1.0.133.100")
                .rule_id,
        )
        .expect("firehol rule context");
    let files: Vec<&str> = victim.files.iter().map(|f| f.as_ref()).collect();
    assert!(
        files.contains(&"firehol_anonymous.netset") && files.contains(&"firehol_proxies.netset"),
        "setup sanity: the firehol victim rule must resolve to its own files"
    );

    // The static rule that actually matched 192.168.1.254 must now live in the
    // disjoint static namespace.
    let static_paths = [Path::new("rules/cidr_ranges.txt").to_path_buf()];
    let refs: Vec<&Path> = static_paths.iter().map(|p| p.as_path()).collect();
    let static_rule_id = static_rule_id_for_192_168_0_0_16(&refs);
    assert!(
        static_rule_id >= STATIC_RULE_BASE,
        "static rule must be in its own namespace"
    );

    // A packet that matched the static 192.168.0.0/16 rule carries this id.
    // Resolving it in the FireHOL registry MUST be None -> the log prints "-"
    // instead of a wrong firehol file:line.
    assert!(
        registry.resolve_rule_block(static_rule_id).is_none(),
        "static rule_id {static_rule_id} must NOT resolve to any FireHOL rule"
    );
}

#[test]
fn manually_built_registry_is_unaffected_by_high_static_ids() {
    // Even a single-rule registry must never return a context for a static ID.
    let mut reg = FireholMetadataRegistry::new();
    reg.register_metadata(FireholMetadata {
        id: 1,
        category: firewall_lib::firehol::metadata::FireholCategory::Anonymizers,
        source_url: None,
        maintainer: None,
        maintainer_url: None,
        source_file_date: None,
        file_name: Arc::from("firehol_anonymous.netset"),
        version: None,
        update_frequency: None,
    });
    reg.register_rule(FireholRuleInfo {
        rule_id: 1,
        metadata_id: 1,
        category: firewall_lib::firehol::metadata::FireholCategory::Anonymizers,
        line: 45,
    });
    for id in [STATIC_RULE_BASE, STATIC_RULE_BASE + 1, u32::MAX - 1] {
        assert!(
            reg.resolve_rule_block(id).is_none(),
            "static id {id} must not resolve in the FireHOL registry"
        );
    }
}
