//! FireHOL eBPF map synchronization and atomic rule publication.
//!
//! Transforms parsed FireHOL datasets into eBPF-ready data structures:
//! - Exact single IP addresses are routed to O(1) HashMaps (`IPV4_EXACT_MAP`, `IPV6_EXACT_MAP`)
//! - CIDR subnets are routed to LPM Tries (`IPV4_LPM_MAP`, `IPV6_LPM_MAP`)
//! - Deduplication avoids redundant entries across HashMaps and LPM Tries
//! - Atomic publication ensures existing firewall rules are never disturbed if any step fails

use crate::error::Result;
use crate::firehol::{entry::FireholIpTarget, parser::FireholDataSet};
use crate::loader::ParsedRuleSet;
use crate::maps::{MapManager, SyncReport};
use firewall_common::RuleValue;
use std::collections::HashSet;

/// Report of the FireHOL synchronization operation into eBPF maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FireholSyncReport {
    pub map_report: SyncReport,
    pub exact_v4_count: usize,
    pub exact_v6_count: usize,
    pub lpm_v4_count: usize,
    pub lpm_v6_count: usize,
    pub duplicates_deduped: usize,
    pub allowlisted_skipped: usize,
}

impl FireholSyncReport {
    pub fn total_rules(&self) -> usize {
        self.exact_v4_count + self.exact_v6_count + self.lpm_v4_count + self.lpm_v6_count
    }
}

/// Prepares and commits FireHOL rules into eBPF maps atomically.
/// Check if an IPv4 address belongs to critical infrastructure (e.g., GitHub threat feed hosting AS36459).
pub fn is_infrastructure_allowlisted_v4(octets: &[u8; 4]) -> bool {
    // 140.82.112.0/20 (140.82.112.0 - 140.82.127.255, includes 140.82.121.3 and 140.82.121.4)
    if octets[0] == 140 && octets[1] == 82 && (112..=127).contains(&octets[2]) {
        return true;
    }
    // 192.30.252.0/22 (192.30.252.0 - 192.30.255.255)
    if octets[0] == 192 && octets[1] == 30 && (252..=255).contains(&octets[2]) {
        return true;
    }
    // 185.199.108.0/22 (185.199.108.0 - 185.199.111.255)
    if octets[0] == 185 && octets[1] == 199 && (108..=111).contains(&octets[2]) {
        return true;
    }
    // 143.55.64.0/20 (143.55.64.0 - 143.55.79.255)
    if octets[0] == 143 && octets[1] == 55 && (64..=79).contains(&octets[2]) {
        return true;
    }
    // Azure GitHub frontends
    if (octets[0] == 20 && octets[1] == 201 && octets[2] == 28 && octets[3] == 151)
        || (octets[0] == 20 && octets[1] == 205 && octets[2] == 243 && octets[3] == 166)
        || (octets[0] == 4 && octets[1] == 237 && (22..=23).contains(&octets[2]))
    {
        return true;
    }
    // Localhost loopback (127.0.0.0/8)
    if octets[0] == 127 {
        return true;
    }
    false
}

/// Check if an IPv4 CIDR subnet targets or encloses essential upstream infrastructure.
pub fn is_infrastructure_cidr_allowlisted_v4(prefix_len: u32, octets: &[u8; 4]) -> bool {
    // Exact GitHub CIDR blocks
    if prefix_len == 20 && octets[0] == 140 && octets[1] == 82 && octets[2] == 112 && octets[3] == 0
    {
        return true;
    }
    if prefix_len == 22 && octets[0] == 192 && octets[1] == 30 && octets[2] == 252 && octets[3] == 0
    {
        return true;
    }
    if prefix_len == 22
        && octets[0] == 185
        && octets[1] == 199
        && octets[2] == 108
        && octets[3] == 0
    {
        return true;
    }
    if prefix_len == 20 && octets[0] == 143 && octets[1] == 55 && octets[2] == 64 && octets[3] == 0
    {
        return true;
    }
    false
}

pub struct FireholSyncManager;

impl FireholSyncManager {
    /// Prepare an atomic `ParsedRuleSet` from the parsed `FireholDataSet`.
    pub fn prepare_rules(dataset: &FireholDataSet) -> (ParsedRuleSet, FireholSyncReport) {
        Self::try_prepare_rules(dataset).expect("FireHOL entry spool read failed")
    }

    pub(crate) fn try_prepare_rules(
        dataset: &FireholDataSet,
    ) -> Result<(ParsedRuleSet, FireholSyncReport)> {
        let mut rules = ParsedRuleSet::new();
        let mut report = FireholSyncReport::default();

        let mut seen_v4_lpm: HashSet<(u32, [u8; 4])> = HashSet::with_capacity(dataset.lpm_v4_count);
        let mut seen_v6_lpm: HashSet<(u32, [u8; 16])> =
            HashSet::with_capacity(dataset.lpm_v6_count);

        dataset.visit_entries(|entry| {
            let rule_val = RuleValue::drop(entry.rule_id);

            match entry.target {
                FireholIpTarget::ExactV4(octets) => {
                    if is_infrastructure_allowlisted_v4(&octets) {
                        report.allowlisted_skipped += 1;
                        return Ok(());
                    }
                    if let std::collections::hash_map::Entry::Vacant(slot) =
                        rules.exact_v4.entry(octets)
                    {
                        slot.insert(rule_val);
                        report.exact_v4_count += 1;
                    } else {
                        report.duplicates_deduped += 1;
                    }
                }
                FireholIpTarget::ExactV6(octets) => {
                    if let std::collections::hash_map::Entry::Vacant(slot) =
                        rules.exact_v6.entry(octets)
                    {
                        slot.insert(rule_val);
                        report.exact_v6_count += 1;
                    } else {
                        report.duplicates_deduped += 1;
                    }
                }
                FireholIpTarget::CidrV4(prefix_len, octets) => {
                    if prefix_len == 32 {
                        // Route single-IP subnet directly to HashMap!
                        if is_infrastructure_allowlisted_v4(&octets) {
                            report.allowlisted_skipped += 1;
                            return Ok(());
                        }
                        if let std::collections::hash_map::Entry::Vacant(slot) =
                            rules.exact_v4.entry(octets)
                        {
                            slot.insert(rule_val);
                            report.exact_v4_count += 1;
                        } else {
                            report.duplicates_deduped += 1;
                        }
                    } else if is_infrastructure_cidr_allowlisted_v4(prefix_len, &octets) {
                        report.allowlisted_skipped += 1;
                    } else if seen_v4_lpm.insert((prefix_len, octets)) {
                        rules.lpm_v4.push((prefix_len, octets, rule_val));
                        report.lpm_v4_count += 1;
                    } else {
                        report.duplicates_deduped += 1;
                    }
                }
                FireholIpTarget::CidrV6(prefix_len, octets) => {
                    if prefix_len == 128 {
                        // Route single-IP subnet directly to HashMap!
                        if let std::collections::hash_map::Entry::Vacant(slot) =
                            rules.exact_v6.entry(octets)
                        {
                            slot.insert(rule_val);
                            report.exact_v6_count += 1;
                        } else {
                            report.duplicates_deduped += 1;
                        }
                    } else if seen_v6_lpm.insert((prefix_len, octets)) {
                        rules.lpm_v6.push((prefix_len, octets, rule_val));
                        report.lpm_v6_count += 1;
                    } else {
                        report.duplicates_deduped += 1;
                    }
                }
            }
            Ok(())
        })?;

        rules.total_rules = rules.count();
        rules.skipped_rules = report.duplicates_deduped;

        Ok((rules, report))
    }

    /// Atomically load the prepared rules into the live eBPF maps via `MapManager`.
    pub fn load_into_maps(
        map_manager: &mut MapManager,
        prepared_rules: &ParsedRuleSet,
        mut report: FireholSyncReport,
    ) -> Result<FireholSyncReport> {
        let map_report = map_manager.sync_firehol_rules(prepared_rules)?;
        report.map_report = map_report;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehol::entry::FireholEntry;

    #[test]
    fn test_prepare_rules_deduplication_and_classification() {
        let mut dataset = FireholDataSet::default();

        // Add duplicate exact IPv4
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::ExactV4([10, 0, 0, 1]),
            1,
            1,
            1,
        ));
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::ExactV4([10, 0, 0, 1]),
            2,
            1,
            2,
        ));

        // Add IPv4 /32 subnet (must be routed to exact map!)
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::CidrV4(32, [10, 0, 0, 2]),
            3,
            1,
            3,
        ));

        // Add IPv4 CIDR /24
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::CidrV4(24, [192, 168, 1, 0]),
            4,
            1,
            4,
        ));

        // Add IPv6 /128 subnet (must be routed to exact map!)
        let v6_bytes = [1u8; 16];
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::CidrV6(128, v6_bytes),
            5,
            1,
            5,
        ));

        let (rules, report) = FireholSyncManager::prepare_rules(&dataset);

        // 10.0.0.1 was duplicated once -> 1 duplicate deduped
        assert_eq!(report.duplicates_deduped, 1);

        // Exact v4: 10.0.0.1 and 10.0.0.2 (from /32)
        assert_eq!(report.exact_v4_count, 2);
        assert_eq!(rules.exact_v4.len(), 2);
        assert!(rules.exact_v4.contains_key(&[10, 0, 0, 1]));
        assert!(rules.exact_v4.contains_key(&[10, 0, 0, 2]));

        // LPM v4: 192.168.1.0/24
        assert_eq!(report.lpm_v4_count, 1);
        assert_eq!(rules.lpm_v4.len(), 1);

        // Exact v6: 1 from /128
        assert_eq!(report.exact_v6_count, 1);
        assert_eq!(rules.exact_v6.len(), 1);
        assert!(rules.exact_v6.contains_key(&v6_bytes));

        assert_eq!(report.total_rules(), 4);
    }

    #[test]
    fn test_prepare_rules_github_allowlist() {
        let mut dataset = FireholDataSet::default();
        // GitHub IPs from vxvault.ipset
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::ExactV4([140, 82, 121, 4]),
            1,
            1,
            1,
        ));
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::ExactV4([140, 82, 121, 3]),
            2,
            1,
            2,
        ));
        // Normal malicious IP
        dataset.entries.push(FireholEntry::new(
            FireholIpTarget::ExactV4([198, 51, 100, 25]),
            3,
            1,
            3,
        ));

        let (rules, report) = FireholSyncManager::prepare_rules(&dataset);
        assert_eq!(report.allowlisted_skipped, 2);
        assert_eq!(report.exact_v4_count, 1);
        assert!(!rules.exact_v4.contains_key(&[140, 82, 121, 4]));
        assert!(!rules.exact_v4.contains_key(&[140, 82, 121, 3]));
        assert!(rules.exact_v4.contains_key(&[198, 51, 100, 25]));
    }

    #[test]
    fn test_is_infrastructure_allowlisted_v4_all_cidrs() {
        use is_infrastructure_allowlisted_v4 as check;

        // 140.82.112.0/20
        assert!(check(&[140, 82, 112, 0]));
        assert!(check(&[140, 82, 127, 255]));
        assert!(!check(&[140, 82, 111, 255]));
        // 192.30.252.0/22
        assert!(check(&[192, 30, 252, 0]));
        assert!(check(&[192, 30, 255, 255]));
        assert!(!check(&[192, 30, 251, 255]));
        // 185.199.108.0/22
        assert!(check(&[185, 199, 108, 0]));
        assert!(check(&[185, 199, 111, 255]));
        assert!(!check(&[185, 199, 112, 0]));
        // 143.55.64.0/20
        assert!(check(&[143, 55, 64, 0]));
        assert!(check(&[143, 55, 79, 255]));
        assert!(!check(&[143, 55, 80, 0]));
        // Azure GitHub frontends
        assert!(check(&[20, 201, 28, 151]));
        assert!(check(&[20, 205, 243, 166]));
        assert!(check(&[4, 237, 22, 7]));
        assert!(check(&[4, 237, 23, 9]));
        assert!(!check(&[4, 237, 24, 0]));
        // Loopback
        assert!(check(&[127, 0, 0, 1]));
        assert!(check(&[127, 255, 255, 254]));
        // Normal address
        assert!(!check(&[198, 51, 100, 1]));
    }

    #[test]
    fn test_is_infrastructure_cidr_allowlisted_v4() {
        use is_infrastructure_cidr_allowlisted_v4 as check;

        assert!(check(20, &[140, 82, 112, 0]));
        assert!(check(22, &[192, 30, 252, 0]));
        assert!(check(22, &[185, 199, 108, 0]));
        assert!(check(20, &[143, 55, 64, 0]));
        // Same networks with different prefix lengths must NOT match.
        assert!(!check(21, &[140, 82, 112, 0]));
        assert!(!check(23, &[192, 30, 252, 0]));
        assert!(!check(24, &[185, 199, 108, 0]));
        assert!(!check(19, &[143, 55, 64, 0]));
        // Unrelated network
        assert!(!check(24, &[192, 168, 0, 0]));
    }

    #[test]
    fn test_prepare_rules_full_branch_matrix() {
        let mut dataset = FireholDataSet::default();
        let mut id = 0u32;
        let mut next = |t: FireholIpTarget| {
            id += 1;
            FireholEntry::new(t, id, 1, id)
        };

        // ExactV6 + duplicate -> one entry, one dedup.
        dataset
            .entries
            .push(next(FireholIpTarget::ExactV6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x9a])));
        dataset
            .entries
            .push(next(FireholIpTarget::ExactV6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x9a])));

        // CidrV4 /32 with an allowlisted address -> skipped.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(32, [140, 82, 121, 4])));
        // CidrV4 /32 duplicate -> dedup.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(32, [198, 51, 100, 10])));
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(32, [198, 51, 100, 10])));

        // CidrV4 exact GitHub network -> allowlisted_skipped.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(20, [140, 82, 112, 0])));
        // CidrV4 duplicate /24 -> one lpm entry + one dedup.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(24, [192, 168, 1, 0])));
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV4(24, [192, 168, 1, 0])));

        // CidrV6 /128 + duplicate -> one exact v6 + one dedup.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV6(128, [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])));
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV6(128, [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])));
        // CidrV6 /48 + duplicate -> one lpm v6 + one dedup.
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV6(48, [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
        dataset
            .entries
            .push(next(FireholIpTarget::CidrV6(48, [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));

        let (rules, report) = FireholSyncManager::prepare_rules(&dataset);

        assert_eq!(report.exact_v6_count, 2, "unique exact v6 ip + /128");
        assert_eq!(report.exact_v4_count, 1, "unique /32 non-allowlisted");
        assert_eq!(report.lpm_v4_count, 1);
        assert_eq!(report.lpm_v6_count, 1);
        // Dedup: exact v6 (1), /32 (1), /24 (1), /128 (1), /48 (1) = 5
        assert_eq!(report.duplicates_deduped, 5);
        // Allowlisted: exact github /32 (1) + exact github /20 (1) = 2
        assert_eq!(report.allowlisted_skipped, 2);
        assert_eq!(report.total_rules(), 5);

        // /32 allowlisted address must NOT be present in exact map.
        assert!(!rules.exact_v4.contains_key(&[140, 82, 121, 4]));
        assert!(rules.exact_v4.contains_key(&[198, 51, 100, 10]));
    }
}
