use crate::console::*;
use crate::error::{FirewallError, Result};
use firewall_common::RuleValue;
use ipnet::IpNet;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};
use tracing::{debug, warn};

/// Starting rule ID for the static rules namespace.
///
/// Static rules (loaded from `rules/*.txt`) share the same eBPF maps as FireHOL
/// blocklist rules, and both are looked up in userspace by their numeric rule ID.
/// FireHOL rules use a dense range starting at 1 (and are indexed by that ID in
/// `FireholMetadataRegistry`). Assigning static rules a disjoint, high base
/// guarantees a static match is never accidentally resolved as a FireHOL rule,
/// which previously produced log lines whose file:line did not match the packet.
///
/// `2^28` leaves ample headroom above the realistic FireHOL rule count (several
/// million) while staying well below `u32::MAX`.
pub const STATIC_RULE_BASE: u32 = 1 << 28;

/// Metadata for a static (non-FireHOL) rule: the source file and 1-based line.
///
/// Kept in the disjoint `STATIC_RULE_BASE` namespace so it can never collide with
/// a FireHOL rule. The Ring Buffer consumer uses this to print the correct
/// `file:line` when a packet matches a static rule (previously such matches
/// showed either a wrong FireHOL attribution or no attribution at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticRuleInfo {
    /// Rule ID assigned to this entry (always >= `STATIC_RULE_BASE`).
    pub rule_id: u32,
    /// Source file the rule was loaded from (e.g. `cidr_ranges.txt`).
    pub file: Arc<str>,
    /// 1-based physical line in `file` where the rule is defined.
    pub line: u32,
}

/// Thread-safe holder for the set of active static rule metadata.
///
/// The underlying map is swapped atomically on (re)load so readers always see a
/// consistent snapshot, matching how `FireholMetadataRegistry` is published.
#[derive(Debug, Default)]
pub struct StaticRuleRegistry {
    inner: RwLock<Arc<HashMap<u32, StaticRuleInfo>>>,
}

impl StaticRuleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a new static metadata map.
    pub fn set(&self, map: HashMap<u32, StaticRuleInfo>) {
        *self.inner.write().unwrap() = Arc::new(map);
    }

    /// Resolve a rule ID (in the static namespace) to its metadata.
    pub fn get(&self, rule_id: u32) -> Option<StaticRuleInfo> {
        self.inner.read().unwrap().get(&rule_id).cloned()
    }
}

/// Structured representation of parsed firewall rules partitioned
/// by IP version and lookup type (exact HashMap vs LPM Trie).
#[derive(Debug, Clone, Default)]
pub struct ParsedRuleSet {
    /// Exact IPv4 addresses mapped to RuleValue (O(1) HashMap)
    pub exact_v4: HashMap<[u8; 4], RuleValue>,
    /// Exact IPv6 addresses mapped to RuleValue (O(1) HashMap)
    pub exact_v6: HashMap<[u8; 16], RuleValue>,
    /// IPv4 CIDR blocks: (prefix_len, network_address_bytes, RuleValue)
    pub lpm_v4: Vec<(u32, [u8; 4], RuleValue)>,
    /// IPv6 CIDR blocks: (prefix_len, network_address_bytes, RuleValue)
    pub lpm_v6: Vec<(u32, [u8; 16], RuleValue)>,
    /// Total number of unique rules parsed
    pub total_rules: usize,
    /// Number of duplicate or skipped entries
    pub skipped_rules: usize,
}

impl ParsedRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether the rule set is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.exact_v4.is_empty()
            && self.exact_v6.is_empty()
            && self.lpm_v4.is_empty()
            && self.lpm_v6.is_empty()
    }

    /// Total count of all rules across all categories.
    pub fn count(&self) -> usize {
        self.exact_v4.len() + self.exact_v6.len() + self.lpm_v4.len() + self.lpm_v6.len()
    }

    /// Merge another rule set into this one, combining exact and LPM rules.
    pub fn merge(&mut self, other: ParsedRuleSet) {
        for (k, v) in other.exact_v4 {
            self.exact_v4.insert(k, v);
        }
        for (k, v) in other.exact_v6 {
            self.exact_v6.insert(k, v);
        }
        self.lpm_v4.extend(other.lpm_v4);
        self.lpm_v6.extend(other.lpm_v6);
        self.total_rules = self.count();
        self.skipped_rules += other.skipped_rules;
    }
}

/// Rule loader that parses blocklist text files into eBPF-ready data structures.
pub struct RuleLoader;

impl RuleLoader {
    /// Load and merge rules from multiple file paths.
    pub fn load_from_paths<P: AsRef<Path>>(paths: &[P]) -> Result<ParsedRuleSet> {
        Ok(Self::load_from_paths_with_meta(paths)?.0)
    }

    /// Load static rules from disk together with their per-rule file:line metadata.
    ///
    /// The returned metadata map lets the Ring Buffer consumer print the correct
    /// `file:line` for a matched static rule without colliding with the FireHOL
    /// registry (rule IDs live in the disjoint `STATIC_RULE_BASE` namespace).
    pub fn load_from_paths_with_meta<P: AsRef<Path>>(
        paths: &[P],
    ) -> Result<(ParsedRuleSet, HashMap<u32, StaticRuleInfo>)> {
        let mut combined = ParsedRuleSet::new();
        let mut static_meta: HashMap<u32, StaticRuleInfo> = HashMap::new();
        let mut next_rule_id = STATIC_RULE_BASE;

        for path in paths {
            let path_ref = path.as_ref();
            if !path_ref.exists() {
                warn!(
                    "{}",
                    yellow_bold(format!(
                        "⚠️ Rule file does not exist: {}",
                        bold(format!("{:?}", path_ref))
                    ))
                );
                continue;
            }
            Self::load_file_into(path_ref, &mut combined, &mut static_meta, &mut next_rule_id)?;
        }

        combined.total_rules = combined.count();
        Ok((combined, static_meta))
    }

    /// Parse a single rule file and populate the rule set.
    #[allow(dead_code)]
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<ParsedRuleSet> {
        let mut rules = ParsedRuleSet::new();
        let mut static_meta: HashMap<u32, StaticRuleInfo> = HashMap::new();
        let mut next_rule_id = STATIC_RULE_BASE;
        Self::load_file_into(
            path.as_ref(),
            &mut rules,
            &mut static_meta,
            &mut next_rule_id,
        )?;
        rules.total_rules = rules.count();
        Ok(rules)
    }

    fn load_file_into(
        path: &Path,
        rules: &mut ParsedRuleSet,
        static_meta: &mut HashMap<u32, StaticRuleInfo>,
        next_rule_id: &mut u32,
    ) -> Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let file_name: Arc<str> = Arc::from(
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown"),
        );

        for (line_idx, line_res) in reader.lines().enumerate() {
            let line_number = line_idx + 1;
            let raw_line = line_res?;

            match Self::parse_line(&raw_line, *next_rule_id) {
                Ok(Some(parsed_entry)) => {
                    let rule_id = parsed_entry.rule_id();
                    static_meta.insert(
                        rule_id,
                        StaticRuleInfo {
                            rule_id,
                            file: Arc::clone(&file_name),
                            line: line_number as u32,
                        },
                    );
                    *next_rule_id += 1;
                    match parsed_entry {
                        ParsedEntry::ExactV4(addr, val) => {
                            if rules.exact_v4.insert(addr, val).is_some() {
                                rules.skipped_rules += 1;
                            }
                        }
                        ParsedEntry::ExactV6(addr, val) => {
                            if rules.exact_v6.insert(addr, val).is_some() {
                                rules.skipped_rules += 1;
                            }
                        }
                        ParsedEntry::LpmV4(prefix_len, addr, val) => {
                            rules.lpm_v4.push((prefix_len, addr, val));
                        }
                        ParsedEntry::LpmV6(prefix_len, addr, val) => {
                            rules.lpm_v6.push((prefix_len, addr, val));
                        }
                    }
                }
                Ok(None) => {
                    // Blank line or pure comment
                }
                Err(e) => {
                    warn!(
                        "{}",
                        yellow_bold(format!(
                            "⚠️ Skipping invalid rule at {}:{} ('{}'): {}",
                            bold(format!("{:?}", path)),
                            bold(line_number),
                            bold(raw_line.trim()),
                            e
                        ))
                    );
                    rules.skipped_rules += 1;
                }
            }
        }

        debug!(
            "📋 Loaded rules from {:?}: ExactV4={}, LpmV4={}, ExactV6={}, LpmV6={}",
            path,
            format_int_with_spaces(rules.exact_v4.len() as u64),
            format_int_with_spaces(rules.lpm_v4.len() as u64),
            format_int_with_spaces(rules.exact_v6.len() as u64),
            format_int_with_spaces(rules.lpm_v6.len() as u64)
        );

        Ok(())
    }

    /// Parse a single line containing an IP or CIDR block, stripping comments and whitespace.
    pub fn parse_line(raw_line: &str, rule_id: u32) -> Result<Option<ParsedEntry>> {
        // Strip inline comments starting with '#' and trim whitespace
        let line = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        }
        .trim();

        if line.is_empty() {
            return Ok(None);
        }

        let rule_val = RuleValue::drop(rule_id);

        // 1. Try parsing as a CIDR network (e.g. 192.168.1.0/24 or 2001:db8::/32)
        if let Ok(net) = IpNet::from_str(line) {
            match net {
                IpNet::V4(net4) => {
                    let prefix_len = net4.prefix_len() as u32;
                    let addr_octets = net4.network().octets();
                    // An IPv4 /32 is a single exact IP: store in O(1) HashMap!
                    if prefix_len == 32 {
                        return Ok(Some(ParsedEntry::ExactV4(addr_octets, rule_val)));
                    } else {
                        return Ok(Some(ParsedEntry::LpmV4(prefix_len, addr_octets, rule_val)));
                    }
                }
                IpNet::V6(net6) => {
                    let prefix_len = net6.prefix_len() as u32;
                    let addr_octets = net6.network().octets();
                    // An IPv6 /128 is a single exact IP: store in O(1) HashMap!
                    if prefix_len == 128 {
                        return Ok(Some(ParsedEntry::ExactV6(addr_octets, rule_val)));
                    } else {
                        return Ok(Some(ParsedEntry::LpmV6(prefix_len, addr_octets, rule_val)));
                    }
                }
            }
        }

        // 2. Try parsing as a single IP address (without CIDR slash)
        if let Ok(ip) = IpAddr::from_str(line) {
            match ip {
                IpAddr::V4(v4) => {
                    return Ok(Some(ParsedEntry::ExactV4(v4.octets(), rule_val)));
                }
                IpAddr::V6(v6) => {
                    return Ok(Some(ParsedEntry::ExactV6(v6.octets(), rule_val)));
                }
            }
        }

        Err(FirewallError::ParseError {
            line: 0,
            reason: format!("Unrecognized IP address or CIDR notation: '{line}'"),
        })
    }
}

/// An intermediate parsed rule entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEntry {
    ExactV4([u8; 4], RuleValue),
    ExactV6([u8; 16], RuleValue),
    LpmV4(u32, [u8; 4], RuleValue),
    LpmV6(u32, [u8; 16], RuleValue),
}

impl ParsedEntry {
    /// The rule ID carried by this entry (the one stored in the eBPF map value).
    pub fn rule_id(&self) -> u32 {
        match self {
            Self::ExactV4(_, v)
            | Self::ExactV6(_, v)
            | Self::LpmV4(_, _, v)
            | Self::LpmV6(_, _, v) => v.rule_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_parse_ipv4_single() {
        let entry = RuleLoader::parse_line("192.0.2.1", 1).unwrap().unwrap();
        match entry {
            ParsedEntry::ExactV4(octets, val) => {
                assert_eq!(octets, [192, 0, 2, 1]);
                assert_eq!(val.rule_id, 1);
            }
            _ => panic!("Expected ExactV4"),
        }
    }

    #[test]
    fn test_parse_ipv4_cidr_32_as_exact() {
        let entry = RuleLoader::parse_line("10.1.2.3/32", 2).unwrap().unwrap();
        match entry {
            ParsedEntry::ExactV4(octets, val) => {
                assert_eq!(octets, [10, 1, 2, 3]);
                assert_eq!(val.rule_id, 2);
            }
            _ => panic!("Expected ExactV4 for /32"),
        }
    }

    #[test]
    fn test_parse_ipv4_cidr_subnet() {
        let entry = RuleLoader::parse_line("10.0.0.0/8", 3).unwrap().unwrap();
        match entry {
            ParsedEntry::LpmV4(prefix_len, octets, val) => {
                assert_eq!(prefix_len, 8);
                assert_eq!(octets, [10, 0, 0, 0]);
                assert_eq!(val.rule_id, 3);
            }
            _ => panic!("Expected LpmV4"),
        }
    }

    #[test]
    fn test_parse_ipv6_single() {
        let entry = RuleLoader::parse_line("2001:db8::1", 4).unwrap().unwrap();
        match entry {
            ParsedEntry::ExactV6(octets, val) => {
                assert_eq!(val.rule_id, 4);
                let parsed_ip = Ipv6Addr::from(octets);
                assert_eq!(parsed_ip, Ipv6Addr::from_str("2001:db8::1").unwrap());
            }
            _ => panic!("Expected ExactV6"),
        }
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        let entry = RuleLoader::parse_line("2001:db8::/32", 5).unwrap().unwrap();
        match entry {
            ParsedEntry::LpmV6(prefix_len, _octets, val) => {
                assert_eq!(prefix_len, 32);
                assert_eq!(val.rule_id, 5);
            }
            _ => panic!("Expected LpmV6"),
        }
    }

    #[test]
    fn test_parse_comments_and_whitespace() {
        let entry = RuleLoader::parse_line("   172.16.0.0/12  # Private RFC1918   ", 6)
            .unwrap()
            .unwrap();
        match entry {
            ParsedEntry::LpmV4(prefix_len, octets, val) => {
                assert_eq!(prefix_len, 12);
                assert_eq!(octets, [172, 16, 0, 0]);
                assert_eq!(val.rule_id, 6);
            }
            _ => panic!("Expected LpmV4"),
        }
    }

    #[test]
    fn test_parsed_entry_rule_id() {
        let e1 = ParsedEntry::ExactV4([1, 2, 3, 4], RuleValue::drop(10));
        let e2 = ParsedEntry::ExactV6([0; 16], RuleValue::drop(20));
        let e3 = ParsedEntry::LpmV4(24, [10, 0, 0, 0], RuleValue::drop(30));
        let e4 = ParsedEntry::LpmV6(64, [0; 16], RuleValue::drop(40));
        assert_eq!(e1.rule_id(), 10);
        assert_eq!(e2.rule_id(), 20);
        assert_eq!(e3.rule_id(), 30);
        assert_eq!(e4.rule_id(), 40);
    }

    #[test]
    fn test_parse_ipv6_cidr_128_as_exact() {
        let entry = RuleLoader::parse_line("2001:db8::1/128", 44).unwrap().unwrap();
        match entry {
            ParsedEntry::ExactV6(octets, val) => {
                assert_eq!(val.rule_id, 44);
                let parsed_ip = Ipv6Addr::from(octets);
                assert_eq!(parsed_ip, Ipv6Addr::from_str("2001:db8::1").unwrap());
            }
            _ => panic!("Expected ExactV6 for /128"),
        }
    }

    #[test]
    fn test_parsed_rule_set_operations() {
        let mut set1 = ParsedRuleSet::new();
        assert!(set1.is_empty());
        assert_eq!(set1.count(), 0);

        set1.exact_v4.insert([192, 168, 1, 1], RuleValue::drop(1));
        assert!(!set1.is_empty());
        assert_eq!(set1.count(), 1);

        let mut set2 = ParsedRuleSet::new();
        set2.exact_v6.insert([0u8; 16], RuleValue::drop(2));
        set2.lpm_v4.push((24, [10, 0, 0, 0], RuleValue::drop(3)));
        set2.lpm_v6.push((64, [0u8; 16], RuleValue::drop(4)));
        set2.skipped_rules = 2;

        set1.merge(set2);
        assert_eq!(set1.count(), 4);
        assert_eq!(set1.total_rules, 4);
        assert_eq!(set1.skipped_rules, 2);
    }

    #[test]
    fn test_static_rule_registry() {
        let registry = StaticRuleRegistry::new();
        assert!(registry.get(100).is_none());

        let mut map = std::collections::HashMap::new();
        map.insert(
            STATIC_RULE_BASE + 1,
            StaticRuleInfo {
                rule_id: STATIC_RULE_BASE + 1,
                file: Arc::from("test.txt"),
                line: 10,
            },
        );
        registry.set(map);

        let info = registry.get(STATIC_RULE_BASE + 1).unwrap();
        assert_eq!(info.rule_id, STATIC_RULE_BASE + 1);
        assert_eq!(&*info.file, "test.txt");
        assert_eq!(info.line, 10);
    }

    #[test]
    fn test_load_from_paths_with_duplicates_and_missing() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "192.168.1.1").unwrap();
        writeln!(tmp, "192.168.1.1 # duplicate").unwrap();
        writeln!(tmp, "2001:db8::1").unwrap();
        writeln!(tmp, "2001:db8::1 # duplicate v6").unwrap();
        writeln!(tmp, "bad-line").unwrap();
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "   ").unwrap();
        tmp.flush().unwrap();

        let missing = Path::new("/path/that/does/not/exist/rules.txt");
        let (rules, meta) = RuleLoader::load_from_paths_with_meta(&[tmp.path(), missing]).unwrap();

        assert_eq!(rules.exact_v4.len(), 1);
        assert_eq!(rules.exact_v6.len(), 1);
        assert_eq!(rules.skipped_rules, 3); // 2 duplicate + 1 bad line
        assert_eq!(meta.len(), 4); // 4 valid lines got meta inserted

        let single = RuleLoader::load_file(tmp.path()).unwrap();
        assert_eq!(single.exact_v4.len(), 1);

        let paths_only = RuleLoader::load_from_paths(&[tmp.path()]).unwrap();
        assert_eq!(paths_only.exact_v4.len(), 1);
    }
}
