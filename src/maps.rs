use crate::{
    console::*,
    error::{FirewallError, Result},
    loader::ParsedRuleSet,
};
use aya::{
    maps::{
        lpm_trie::{Key as LpmKey, LpmTrie},
        Array, HashMap, MapData,
    },
    Ebpf,
};
use firewall_common::{FirewallStats, RuleValue};
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Report generated after synchronizing rules into the eBPF maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub ipv4_exact_inserted: usize,
    pub ipv6_exact_inserted: usize,
    pub ipv4_lpm_inserted: usize,
    pub ipv6_lpm_inserted: usize,
    pub entries_removed: usize,
}

/// High-level manager for all eBPF maps used by the firewall.
pub struct MapManager {
    ipv4_exact: HashMap<MapData, [u8; 4], RuleValue>,
    ipv6_exact: HashMap<MapData, [u8; 16], RuleValue>,
    ipv4_lpm: LpmTrie<MapData, [u8; 4], RuleValue>,
    ipv6_lpm: LpmTrie<MapData, [u8; 16], RuleValue>,
    stats_map: Array<MapData, FirewallStats>,
    installed_firehol_v4_exact: HashSet<[u8; 4]>,
    installed_firehol_v6_exact: HashSet<[u8; 16]>,
    installed_firehol_v4_lpm: HashSet<(u32, [u8; 4])>,
    installed_firehol_v6_lpm: HashSet<(u32, [u8; 16])>,
}

impl MapManager {
    /// Initialize `MapManager` by taking ownership of the maps from the loaded `Ebpf` instance.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self> {
        let ipv4_exact: HashMap<_, [u8; 4], RuleValue> = ebpf
            .take_map("IPV4_EXACT_MAP")
            .or_else(|| ebpf.take_map("EXACT_MATCH_MAP_V4"))
            .ok_or_else(|| FirewallError::Config("Map IPV4_EXACT_MAP not found in ELF".into()))?
            .try_into()?;

        let ipv6_exact: HashMap<_, [u8; 16], RuleValue> = ebpf
            .take_map("IPV6_EXACT_MAP")
            .or_else(|| ebpf.take_map("EXACT_MATCH_MAP_V6"))
            .ok_or_else(|| FirewallError::Config("Map IPV6_EXACT_MAP not found in ELF".into()))?
            .try_into()?;

        let ipv4_lpm: LpmTrie<_, [u8; 4], RuleValue> = ebpf
            .take_map("IPV4_LPM_MAP")
            .or_else(|| ebpf.take_map("LPM_MATCH_MAP_V4"))
            .ok_or_else(|| FirewallError::Config("Map IPV4_LPM_MAP not found in ELF".into()))?
            .try_into()?;

        let ipv6_lpm: LpmTrie<_, [u8; 16], RuleValue> = ebpf
            .take_map("IPV6_LPM_MAP")
            .or_else(|| ebpf.take_map("LPM_MATCH_MAP_V6"))
            .ok_or_else(|| FirewallError::Config("Map IPV6_LPM_MAP not found in ELF".into()))?
            .try_into()?;

        let stats_map: Array<_, FirewallStats> = ebpf
            .take_map("STATS")
            .or_else(|| ebpf.take_map("FIREWALL_STATS_MAP"))
            .ok_or_else(|| FirewallError::Config("Map STATS not found in ELF".into()))?
            .try_into()?;

        Ok(Self {
            ipv4_exact,
            ipv6_exact,
            ipv4_lpm,
            ipv6_lpm,
            stats_map,
            installed_firehol_v4_exact: HashSet::new(),
            installed_firehol_v6_exact: HashSet::new(),
            installed_firehol_v4_lpm: HashSet::new(),
            installed_firehol_v6_lpm: HashSet::new(),
        })
    }

    /// Reconstruct the currently installed static-only keys of a map.
    ///
    /// The shared kernel maps hold both static and FireHOL entries; this returns the
    /// keys that are not owned by FireHOL (i.e. the static ones).
    fn static_v4_exact(&self) -> HashSet<[u8; 4]> {
        self.current_v4_exact()
            .difference(&self.installed_firehol_v4_exact)
            .copied()
            .collect()
    }

    /// Reconstruct the currently installed static-only keys of a map.
    fn static_v6_exact(&self) -> HashSet<[u8; 16]> {
        self.current_v6_exact()
            .difference(&self.installed_firehol_v6_exact)
            .copied()
            .collect()
    }

    /// Reconstruct the currently installed static-only keys of a map.
    fn static_v4_lpm(&self) -> HashSet<(u32, [u8; 4])> {
        self.current_v4_lpm()
            .difference(&self.installed_firehol_v4_lpm)
            .copied()
            .collect()
    }

    /// Reconstruct the currently installed static-only keys of a map.
    fn static_v6_lpm(&self) -> HashSet<(u32, [u8; 16])> {
        self.current_v6_lpm()
            .difference(&self.installed_firehol_v6_lpm)
            .copied()
            .collect()
    }

    /// Read every key currently present in the IPv4 exact map.
    fn current_v4_exact(&self) -> HashSet<[u8; 4]> {
        self.ipv4_exact.keys().filter_map(|r| r.ok()).collect()
    }

    /// Read every key currently present in the IPv6 exact map.
    fn current_v6_exact(&self) -> HashSet<[u8; 16]> {
        self.ipv6_exact.keys().filter_map(|r| r.ok()).collect()
    }

    /// Read every key currently present in the IPv4 LPM map.
    fn current_v4_lpm(&self) -> HashSet<(u32, [u8; 4])> {
        self.ipv4_lpm
            .keys()
            .filter_map(|r| r.ok())
            .map(|key| (key.prefix_len(), key.data()))
            .collect()
    }

    /// Read every key currently present in the IPv6 LPM map.
    fn current_v6_lpm(&self) -> HashSet<(u32, [u8; 16])> {
        self.ipv6_lpm
            .keys()
            .filter_map(|r| r.ok())
            .map(|key| (key.prefix_len(), key.data()))
            .collect()
    }

    /// Add or update a single IPv4 exact block rule.
    #[allow(dead_code)]
    pub fn insert_exact_v4(&mut self, addr: [u8; 4], val: RuleValue) -> Result<()> {
        self.ipv4_exact.insert(addr, val, 0)?;
        Ok(())
    }

    /// Add or update a single IPv6 exact block rule.
    #[allow(dead_code)]
    pub fn insert_exact_v6(&mut self, addr: [u8; 16], val: RuleValue) -> Result<()> {
        self.ipv6_exact.insert(addr, val, 0)?;
        Ok(())
    }

    /// Add or update a CIDR subnet block in the IPv4 LPM Trie.
    #[allow(dead_code)]
    pub fn insert_lpm_v4(&mut self, prefix_len: u32, addr: [u8; 4], val: RuleValue) -> Result<()> {
        let key = LpmKey::new(prefix_len, addr);
        self.ipv4_lpm.insert(&key, val, 0)?;
        Ok(())
    }

    /// Add or update a CIDR subnet block in the IPv6 LPM Trie.
    #[allow(dead_code)]
    pub fn insert_lpm_v6(&mut self, prefix_len: u32, addr: [u8; 16], val: RuleValue) -> Result<()> {
        let key = LpmKey::new(prefix_len, addr);
        self.ipv6_lpm.insert(&key, val, 0)?;
        Ok(())
    }

    /// Remove a single IPv4 exact block rule.
    #[allow(dead_code)]
    pub fn remove_exact_v4(&mut self, addr: &[u8; 4]) -> Result<()> {
        self.ipv4_exact.remove(addr)?;
        Ok(())
    }

    /// Remove a single IPv6 exact block rule.
    #[allow(dead_code)]
    pub fn remove_exact_v6(&mut self, addr: &[u8; 16]) -> Result<()> {
        self.ipv6_exact.remove(addr)?;
        Ok(())
    }

    /// Remove a single IPv4 CIDR prefix from the LPM Trie.
    #[allow(dead_code)]
    pub fn remove_lpm_v4(&mut self, prefix_len: u32, addr: [u8; 4]) -> Result<()> {
        let key = LpmKey::new(prefix_len, addr);
        self.ipv4_lpm.remove(&key)?;
        Ok(())
    }

    /// Remove a single IPv6 CIDR prefix from the LPM Trie.
    #[allow(dead_code)]
    pub fn remove_lpm_v6(&mut self, prefix_len: u32, addr: [u8; 16]) -> Result<()> {
        let key = LpmKey::new(prefix_len, addr);
        self.ipv6_lpm.remove(&key)?;
        Ok(())
    }

    /// Synchronizes a full `ParsedRuleSet` into the eBPF maps.
    ///
    /// Performs differential synchronization:
    /// - Inserts all new and modified rules
    /// - Removes stale rules previously installed in maps that are absent in the new set
    pub fn sync_rules(&mut self, rules: &ParsedRuleSet) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        // 1. Synchronize IPv4 Exact Match
        let mut installed_v4 = HashSet::new();
        let mut v4_exact_warned = false;
        for (&addr, &val) in &rules.exact_v4 {
            if v4_exact_warned {
                continue;
            }
            if let Err(e) = self.ipv4_exact.insert(addr, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv4 exact match map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v4_exact_warned = true;
            } else {
                installed_v4.insert(addr);
                report.ipv4_exact_inserted += 1;
            }
        }
        for &addr in self.static_v4_exact().difference(&installed_v4) {
            if !self.installed_firehol_v4_exact.contains(&addr) {
                let _ = self.ipv4_exact.remove(&addr);
                report.entries_removed += 1;
            }
        }

        // 2. Synchronize IPv6 Exact Match
        let mut installed_v6 = HashSet::new();
        let mut v6_exact_warned = false;
        for (&addr, &val) in &rules.exact_v6 {
            if v6_exact_warned {
                continue;
            }
            if let Err(e) = self.ipv6_exact.insert(addr, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv6 exact match map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v6_exact_warned = true;
            } else {
                installed_v6.insert(addr);
                report.ipv6_exact_inserted += 1;
            }
        }
        for &addr in self.static_v6_exact().difference(&installed_v6) {
            if !self.installed_firehol_v6_exact.contains(&addr) {
                let _ = self.ipv6_exact.remove(&addr);
                report.entries_removed += 1;
            }
        }

        // 3. Synchronize IPv4 LPM Trie
        let mut current_v4_lpm = HashSet::new();
        let mut v4_lpm_warned = false;
        for &(prefix_len, addr, val) in &rules.lpm_v4 {
            if v4_lpm_warned {
                continue;
            }
            let key = LpmKey::new(prefix_len, addr);
            if let Err(e) = self.ipv4_lpm.insert(&key, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv4 LPM Trie map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v4_lpm_warned = true;
            } else {
                current_v4_lpm.insert((prefix_len, addr));
                report.ipv4_lpm_inserted += 1;
            }
        }
        for &(prefix_len, addr) in self.static_v4_lpm().difference(&current_v4_lpm) {
            if !self.installed_firehol_v4_lpm.contains(&(prefix_len, addr)) {
                let key = LpmKey::new(prefix_len, addr);
                let _ = self.ipv4_lpm.remove(&key);
                report.entries_removed += 1;
            }
        }

        // 4. Synchronize IPv6 LPM Trie
        let mut current_v6_lpm = HashSet::new();
        let mut v6_lpm_warned = false;
        for &(prefix_len, addr, val) in &rules.lpm_v6 {
            if v6_lpm_warned {
                continue;
            }
            let key = LpmKey::new(prefix_len, addr);
            if let Err(e) = self.ipv6_lpm.insert(&key, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv6 LPM Trie map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v6_lpm_warned = true;
            } else {
                current_v6_lpm.insert((prefix_len, addr));
                report.ipv6_lpm_inserted += 1;
            }
        }
        for &(prefix_len, addr) in self.static_v6_lpm().difference(&current_v6_lpm) {
            if !self.installed_firehol_v6_lpm.contains(&(prefix_len, addr)) {
                let key = LpmKey::new(prefix_len, addr);
                let _ = self.ipv6_lpm.remove(&key);
                report.entries_removed += 1;
            }
        }

        info!(
            "{}",
            green_bold(format!(
                "🗺️ eBPF maps synchronized: +{} exact IPv4 🎯, +{} exact IPv6 🎯, +{} LPM IPv4 🌲, +{} LPM IPv6 🌲, -{} stale removed 🧹",
                bold_num(report.ipv4_exact_inserted),
                bold_num(report.ipv6_exact_inserted),
                bold_num(report.ipv4_lpm_inserted),
                bold_num(report.ipv6_lpm_inserted),
                bold_num(report.entries_removed)
            ))
        );

        Ok(report)
    }

    pub fn total_exact_v4(&self) -> usize {
        self.current_v4_exact().len()
    }

    pub fn total_exact_v6(&self) -> usize {
        self.current_v6_exact().len()
    }

    pub fn total_lpm_v4(&self) -> usize {
        self.current_v4_lpm().len()
    }

    pub fn total_lpm_v6(&self) -> usize {
        self.current_v6_lpm().len()
    }

    /// Synchronizes FireHOL threat intelligence rules into eBPF maps without clobbering static rules.
    pub fn sync_firehol_rules(&mut self, rules: &ParsedRuleSet) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        // 1. Synchronize IPv4 Exact Match
        let mut installed_v4 = HashSet::new();
        let mut v4_exact_warned = false;
        for (&addr, &val) in &rules.exact_v4 {
            if v4_exact_warned {
                continue;
            }
            if let Err(e) = self.ipv4_exact.insert(addr, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv4 exact match map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v4_exact_warned = true;
            } else {
                installed_v4.insert(addr);
                report.ipv4_exact_inserted += 1;
            }
        }
        for &addr in self.installed_firehol_v4_exact.difference(&installed_v4) {
            if !self.static_v4_exact().contains(&addr) {
                let _ = self.ipv4_exact.remove(&addr);
                report.entries_removed += 1;
            }
        }
        self.installed_firehol_v4_exact = installed_v4;

        // 2. Synchronize IPv6 Exact Match
        let mut installed_v6 = HashSet::new();
        let mut v6_exact_warned = false;
        for (&addr, &val) in &rules.exact_v6 {
            if v6_exact_warned {
                continue;
            }
            if let Err(e) = self.ipv6_exact.insert(addr, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv6 exact match map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v6_exact_warned = true;
            } else {
                installed_v6.insert(addr);
                report.ipv6_exact_inserted += 1;
            }
        }
        for &addr in self.installed_firehol_v6_exact.difference(&installed_v6) {
            if !self.static_v6_exact().contains(&addr) {
                let _ = self.ipv6_exact.remove(&addr);
                report.entries_removed += 1;
            }
        }
        self.installed_firehol_v6_exact = installed_v6;

        // 3. Synchronize IPv4 LPM Trie
        let mut current_v4_lpm = HashSet::new();
        let mut v4_lpm_warned = false;
        for &(prefix_len, addr, val) in &rules.lpm_v4 {
            if v4_lpm_warned {
                continue;
            }
            let key = LpmKey::new(prefix_len, addr);
            if let Err(e) = self.ipv4_lpm.insert(&key, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv4 LPM Trie map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v4_lpm_warned = true;
            } else {
                current_v4_lpm.insert((prefix_len, addr));
                report.ipv4_lpm_inserted += 1;
            }
        }
        for &(prefix_len, addr) in self.installed_firehol_v4_lpm.difference(&current_v4_lpm) {
            if !self.static_v4_lpm().contains(&(prefix_len, addr)) {
                let key = LpmKey::new(prefix_len, addr);
                let _ = self.ipv4_lpm.remove(&key);
                report.entries_removed += 1;
            }
        }
        self.installed_firehol_v4_lpm = current_v4_lpm;

        // 4. Synchronize IPv6 LPM Trie
        let mut current_v6_lpm = HashSet::new();
        let mut v6_lpm_warned = false;
        for &(prefix_len, addr, val) in &rules.lpm_v6 {
            if v6_lpm_warned {
                continue;
            }
            let key = LpmKey::new(prefix_len, addr);
            if let Err(e) = self.ipv6_lpm.insert(&key, val, 0) {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ IPv6 LPM Trie map capacity reached or insert error: {}. Remaining rules will be skipped.",
                        e
                    ))
                );
                v6_lpm_warned = true;
            } else {
                current_v6_lpm.insert((prefix_len, addr));
                report.ipv6_lpm_inserted += 1;
            }
        }
        for &(prefix_len, addr) in self.installed_firehol_v6_lpm.difference(&current_v6_lpm) {
            if !self.static_v6_lpm().contains(&(prefix_len, addr)) {
                let key = LpmKey::new(prefix_len, addr);
                let _ = self.ipv6_lpm.remove(&key);
                report.entries_removed += 1;
            }
        }
        self.installed_firehol_v6_lpm = current_v6_lpm;

        info!(
            "{}",
            green_bold(format!(
                "🗺️ eBPF maps synchronized: +{} exact IPv4 🎯, +{} exact IPv6 🎯, +{} LPM IPv4 🌲, +{} LPM IPv6 🌲, -{} stale removed 🧹",
                bold_num(report.ipv4_exact_inserted),
                bold_num(report.ipv6_exact_inserted),
                bold_num(report.ipv4_lpm_inserted),
                bold_num(report.ipv6_lpm_inserted),
                bold_num(report.entries_removed)
            ))
        );

        Ok(report)
    }

    /// Read global packet and byte statistics from kernel space.
    pub fn get_stats(&self) -> Result<FirewallStats> {
        match self.stats_map.get(&0, 0) {
            Ok(stats) => Ok(stats),
            Err(e) => {
                debug!("⚠️ Failed to read stats map: {}", e);
                Ok(FirewallStats::default())
            }
        }
    }

    /// Reset global firewall counters to 0.
    #[allow(dead_code)]
    pub fn reset_stats(&mut self) -> Result<()> {
        self.stats_map.set(0, FirewallStats::default(), 0)?;
        Ok(())
    }
}
