//! FireHOL metadata definitions, category classification, and registry.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, fmt, sync::Arc};

use crate::cache_rocksdb::{
    ctx_key_v4_exact, ctx_key_v4_lpm, ctx_key_v6_exact, ctx_key_v6_lpm, CacheRocksDb,
};
use crate::firehol::entry::{FireholEntry, FireholIpTarget};

/// High-level categorization of FireHOL blocklists.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize,
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[serde(rename_all = "lowercase")]
pub enum FireholCategory {
    Abuse,
    Attacks,
    Malware,
    Spam,
    Proxy,
    Botnet,
    Unroutable,
    Anonymizers,
    Other,
}

impl std::str::FromStr for FireholCategory {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::parse_category(s))
    }
}

impl FireholCategory {
    /// Return the canonical category label used in logs and Prometheus metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Abuse => "abuse",
            Self::Attacks => "attacks",
            Self::Malware => "malware",
            Self::Spam => "spam",
            Self::Proxy => "proxy",
            Self::Botnet => "botnet",
            Self::Unroutable => "unroutable",
            Self::Anonymizers => "anonymizers",
            Self::Other => "other",
        }
    }

    /// Parse a category string from a FireHOL `# Category : ...` comment line.
    pub fn parse_category(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "abuse" => Self::Abuse,
            "attacks" | "attack" => Self::Attacks,
            "malware" => Self::Malware,
            "spam" | "spammer" => Self::Spam,
            "proxy" | "proxies" => Self::Proxy,
            "botnet" | "bots" | "bot" => Self::Botnet,
            "unroutable" | "unallocated" => Self::Unroutable,
            "anonymizers" | "anonymous" | "anonymizer" => Self::Anonymizers,
            _ => Self::Other,
        }
    }

    /// Compact numeric identifier suitable for eBPF or memory-efficient mapping.
    pub fn id(&self) -> u32 {
        match self {
            Self::Abuse => 1,
            Self::Attacks => 2,
            Self::Malware => 3,
            Self::Spam => 4,
            Self::Proxy => 5,
            Self::Botnet => 6,
            Self::Unroutable => 7,
            Self::Anonymizers => 9,
            Self::Other => 8,
        }
    }

    /// Reconstruct category from its compact numeric identifier.
    pub fn from_id(id: u32) -> Self {
        match id {
            1 => Self::Abuse,
            2 => Self::Attacks,
            3 => Self::Malware,
            4 => Self::Spam,
            5 => Self::Proxy,
            6 => Self::Botnet,
            7 => Self::Unroutable,
            9 => Self::Anonymizers,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for FireholCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ArchivedFireholCategory> for FireholCategory {
    fn from(c: ArchivedFireholCategory) -> Self {
        match c {
            ArchivedFireholCategory::Abuse => Self::Abuse,
            ArchivedFireholCategory::Attacks => Self::Attacks,
            ArchivedFireholCategory::Malware => Self::Malware,
            ArchivedFireholCategory::Spam => Self::Spam,
            ArchivedFireholCategory::Proxy => Self::Proxy,
            ArchivedFireholCategory::Botnet => Self::Botnet,
            ArchivedFireholCategory::Unroutable => Self::Unroutable,
            ArchivedFireholCategory::Anonymizers => Self::Anonymizers,
            ArchivedFireholCategory::Other => Self::Other,
        }
    }
}

impl From<&ArchivedFireholCategory> for FireholCategory {
    fn from(c: &ArchivedFireholCategory) -> Self {
        (*c).into()
    }
}

impl ArchivedFireholCategory {
    /// Return the canonical category label used in logs and Prometheus metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Abuse => "abuse",
            Self::Attacks => "attacks",
            Self::Malware => "malware",
            Self::Spam => "spam",
            Self::Proxy => "proxy",
            Self::Botnet => "botnet",
            Self::Unroutable => "unroutable",
            Self::Anonymizers => "anonymizers",
            Self::Other => "other",
        }
    }

    /// Convert the archived category to its native representation.
    pub fn to_native(&self) -> FireholCategory {
        (*self).into()
    }
}

/// Check whether IPv4 `ip` falls inside the network `net`/`prefix`.
fn prefix_contains_v4(prefix: u8, net: &[u8; 4], ip: &[u8; 4]) -> bool {
    let mask = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from_be_bytes(*net) & mask) == (u32::from_be_bytes(*ip) & mask)
}

/// Check whether IPv6 `ip` falls inside the network `net`/`prefix`.
fn prefix_contains_v6(prefix: u8, net: &[u8; 16], ip: &[u8; 16]) -> bool {
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = prefix % 8;
    for i in 0..full_bytes {
        if net[i] != ip[i] {
            return false;
        }
    }
    if rem_bits > 0 && full_bytes < 16 {
        let mask = 0xFFu8 << (8 - rem_bits);
        if (net[full_bytes] & mask) != (ip[full_bytes] & mask) {
            return false;
        }
    }
    true
}

/// Mask an IPv4 address down to its `prefix`-bit network prefix.
fn mask_v4(prefix: u8, ip: &[u8; 4]) -> [u8; 4] {
    let mask = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from_be_bytes(*ip) & mask).to_be_bytes()
}

/// Mask an IPv6 address down to its `prefix`-bit network prefix.
fn mask_v6(prefix: u8, ip: &[u8; 16]) -> [u8; 16] {
    let mut out = *ip;
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if full < 16 {
        if rem > 0 {
            let mask = 0xFFu8 << (8 - rem);
            out[full] &= mask;
        }
        out[(full + 1)..16].fill(0);
    }
    out
}

/// Encode a FireHOL IP/CIDR target into its compact RocksDB key (tagged by kind).
fn target_key<'a>(target: &FireholIpTarget, buffer: &'a mut [u8; 18]) -> &'a [u8] {
    target.context_key(buffer)
}

pub fn normalize_firehol_date(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Try RFC3339 direct parse
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.to_rfc3339());
    }

    // 2. Standard FireHOL date format with UTC offset: "Mon Sep 14 02:22:20 UTC 2026"
    let with_offset = trimmed.replace(" UTC ", " +0000 ");
    if let Ok(dt) = chrono::DateTime::parse_from_str(&with_offset, "%a %b %e %H:%M:%S %z %Y") {
        return Some(dt.to_rfc3339());
    }

    // 3. Without timezone: "Mon Sep 14 02:22:20 2026"
    let without_utc = trimmed.replace(" UTC", "");
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(&without_utc, "%a %b %e %H:%M:%S %Y") {
        return Some(ndt.and_utc().to_rfc3339());
    }

    // 4. Standard ISO datetime: "2026-09-14 02:22:20"
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Some(ndt.and_utc().to_rfc3339());
    }

    // 5. Standard ISO date: "2026-09-14"
    if let Ok(nd) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        return Some(nd.and_hms_opt(0, 0, 0)?.and_utc().to_rfc3339());
    }

    // Fallback: keep sanitized string
    Some(trimmed.to_string())
}

/// Rich metadata extracted from FireHOL `.ipset` and `.netset` headers.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize,
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct FireholMetadata {
    /// Unique internal metadata identifier
    pub id: u32,
    /// Threat category
    pub category: FireholCategory,
    /// Upstream source URL
    #[serde(with = "option_arc_str_serde")]
    pub source_url: Option<Arc<str>>,
    /// Organization maintaining the blocklist
    #[serde(with = "option_arc_str_serde")]
    pub maintainer: Option<Arc<str>>,
    /// Maintainer official website
    #[serde(with = "option_arc_str_serde")]
    pub maintainer_url: Option<Arc<str>>,
    /// Normalized RFC3339 timestamp from the source file
    #[serde(with = "option_arc_str_serde")]
    pub source_file_date: Option<Arc<str>>,
    /// Physical file name in the repository (e.g. `dshield.netset`), shared via `Arc<str>`
    #[serde(with = "arc_str_serde")]
    pub file_name: Arc<str>,
    /// Blocklist version
    #[serde(with = "option_arc_str_serde")]
    pub version: Option<Arc<str>>,
    /// Expected refresh frequency
    #[serde(with = "option_arc_str_serde")]
    pub update_frequency: Option<Arc<str>>,
}

impl ArchivedFireholMetadata {
    /// Zero-copy access to the file name as a string slice.
    pub fn file_name_str(&self) -> &str {
        &self.file_name
    }

    /// Zero-copy access to the upstream source URL as an optional string slice.
    pub fn source_url_str(&self) -> Option<&str> {
        self.source_url.as_ref().map(|s| &**s)
    }

    /// Zero-copy access to the maintainer organization as an optional string slice.
    pub fn maintainer_str(&self) -> Option<&str> {
        self.maintainer.as_ref().map(|s| &**s)
    }

    /// Zero-copy access to the maintainer URL as an optional string slice.
    pub fn maintainer_url_str(&self) -> Option<&str> {
        self.maintainer_url.as_ref().map(|s| &**s)
    }

    /// Zero-copy access to the normalized source file date as an optional string slice.
    pub fn source_file_date_str(&self) -> Option<&str> {
        self.source_file_date.as_ref().map(|s| &**s)
    }

    /// Zero-copy access to the blocklist version as an optional string slice.
    pub fn version_str(&self) -> Option<&str> {
        self.version.as_ref().map(|s| &**s)
    }

    /// Zero-copy access to the update frequency as an optional string slice.
    pub fn update_frequency_str(&self) -> Option<&str> {
        self.update_frequency.as_ref().map(|s| &**s)
    }
}

/// Compact resolved metadata associated with a specific active eBPF rule ID.
///
/// This is a fully stack-sized value (no per-rule heap allocation): the owning
/// file name is intentionally *not* duplicated here, it is reachable through
/// the matching `FireholMetadata` via `metadata_id`, so only a single shared
/// `Arc<str>` is kept in the whole registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FireholRuleInfo {
    pub rule_id: u32,
    pub metadata_id: u32,
    pub category: FireholCategory,
    /// 1-based source line where this rule was defined.
    pub line: u32,
}

/// Resolved per-rule state kept in the registry.
///
/// `block` is shared (`Arc`) across every rule whose IP/CIDR target is the same,
/// so the `Vec`s holding its file names / categories are allocated exactly once.
/// The `rule_id` is intentionally *not* stored here: it is the HashMap key, so a
/// per-rule copy would be pure redundancy (a few tens of MB with millions of rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleBlockEntry {
    pub metadata_id: u32,
    pub category: FireholCategory,
    /// 1-based source line of this rule inside its owning file.
    pub line: u32,
    /// Shared per-target context, assigned by [`FireholMetadataRegistry::build_rule_block_index`].
    ///
    /// Only populated when several rules share the exact same target. For targets
    /// referenced by a single rule, it stays `None` and the context is derived
    /// lazily from the metadata (see [`FireholMetadataRegistry::resolve_rule_block`]),
    /// avoiding one heap allocation per unique target.
    pub block: Option<Arc<RuleBlockContext>>,
}

/// Stable, deduplicated set of FireHOL files and categories associated with a blocked target.
#[derive(
    Debug, Clone, Default, PartialEq, Eq,
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct RuleBlockContext {
    /// Unique file names in deterministic (insertion) order.
    pub files: Vec<Arc<str>>,
    /// 1-based source line per file, parallel to [`Self::files`].
    pub lines: Vec<u32>,
    /// Unique categories in deterministic (insertion) order.
    pub categories: Vec<FireholCategory>,
}

impl ArchivedRuleBlockContext {
    /// Return the list of file names as a zero-copy iterator over `&str`.
    pub fn files_iter(&self) -> impl ExactSizeIterator<Item = &str> {
        self.files.iter().map(|f| &**f)
    }

    /// Return categories as an iterator of native `FireholCategory`.
    pub fn categories_iter(&self) -> impl ExactSizeIterator<Item = FireholCategory> + '_ {
        self.categories.iter().map(|c| c.to_native())
    }
}

/// Serde helpers to (de)serialize an `Arc<str>` as a plain string.
mod arc_str_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(arc: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(arc)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Arc::from(s))
    }
}

/// Serde helpers to (de)serialize an `Option<Arc<str>>` as an optional plain string.
mod option_arc_str_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(opt: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(s) => serializer.serialize_some(s.as_ref()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Arc<str>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        Ok(s.map(Arc::from))
    }
}

/// In-memory userspace registry connecting eBPF rule IDs to full FireHOL metadata.
///
/// By default (`[`FireholMetadataRegistry::new`]`) the registry keeps everything in RAM, which is
/// the behavior exercised by the unit tests. Production can instead construct it with
/// [`FireholMetadataRegistry::with_cache`]: with a RocksDB cache the heavy, rarely-read data —
/// the verbose per-file `FireholMetadata` and the per-target file/category contexts — is persisted
/// (LZ4-compressed, Cap'n Proto) and read back lazily, while RAM retains only the dense per-rule
/// lookup vector and a small per-file hot index.
#[derive(Debug, Clone, Default)]
pub struct FireholMetadataRegistry {
    /// Optional RocksDB-backed heavy store. When `Some`, verbose metadata and the per-target
    /// IP contexts live here rather than in RAM; when `None`, the classic fully-in-RAM behavior
    /// (used by tests and small deployments) applies.
    cache: Option<Arc<CacheRocksDb>>,
    /// Per-file hot index used only when `cache` is set: `metadata_id -> (category, file_name)`.
    /// This mirrors the per-blocklist (not per-rule) quantity, so RAM stays proportional to the
    /// number of blocklists rather than the number of rules / distinct targets.
    metadata_light: HashMap<u32, (FireholCategory, Arc<str>)>,
    /// Mapping from internal metadata ID to full metadata
    pub metadata_by_id: HashMap<u32, Arc<FireholMetadata>>,
    /// Per-rule resolved state, indexed directly by rule ID (fully-in-RAM mode).
    ///
    /// Rule IDs are assigned monotonically starting at 1 (one per parsed entry), so a dense
    /// `Vec` indexed by `rule_id` is both smaller (no hashing/control-bytes overhead, no
    /// duplication of the key) and faster on the hot lookup path than the equivalent
    /// `HashMap<u32, ...>` it replaces. Slots that were never populated carry a default
    /// placeholder; [`Self::rule_count`] tracks the real number of registered rules.
    pub rules: Vec<RuleBlockEntry>,
    /// Compact per-rule store used only when a RocksDB cache is active (`cache: Some`).
    ///
    /// `(metadata_id, line)` is kept per rule (8 bytes/rule vs 24 for the fully-featured
    /// [`RuleBlockEntry`], which also embeds an `Option<Arc<RuleBlockContext>>` that is always
    /// `None` in cache mode). The per-rule `category` is *not* duplicated here: it is a
    /// per-file property already stored once in `metadata_light`, so it is re-derived from the
    /// metadata id on demand. This keeps steady-state RAM at the absolute minimum while
    /// `resolve_rule` / `resolve_rule_block` reproduce byte-identical results.
    ///
    /// Slots that were never populated carry a `(0, 0)` placeholder; [`Self::rule_count`] tracks
    /// the real number of registered rules.
    rules_cache: Vec<(u32, u32)>,
    /// Number of rules actually registered (the `rules` `Vec` may contain placeholder slots).
    pub rule_count: usize,
    /// Aggregated entry count per category
    pub category_counts: HashMap<FireholCategory, usize>,
    /// Aggregated entry count per blocklist (keyed by shared `file_name`)
    pub blocklist_counts: HashMap<Arc<str>, usize>,
    /// Reverse IP lookup index: exact IPv4 address -> shared context of owning files.
    ///
    /// Built by [`FireholMetadataRegistry::build_ip_index`] so the Ring Buffer consumer can list
    /// every FireHOL file that also covers a blocked IP, even when a *static* rule won the LPM
    /// Trie. Keyed by raw network-order octets.
    pub ip_index_v4_exact: HashMap<[u8; 4], Arc<RuleBlockContext>>,
    /// Reverse IP lookup index: exact IPv6 address -> shared context.
    pub ip_index_v6_exact: HashMap<[u8; 16], Arc<RuleBlockContext>>,
    /// Reverse IP lookup index: IPv4 CIDRs as (prefix_len, network octets, shared context).
    pub ip_index_v4_lpm: Vec<(u8, [u8; 4], Arc<RuleBlockContext>)>,
    /// Reverse IP lookup index: IPv6 CIDRs as (prefix_len, network octets, shared context).
    pub ip_index_v6_lpm: Vec<(u8, [u8; 16], Arc<RuleBlockContext>)>,
}

impl FireholMetadataRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry backed by a shared RocksDB cache.
    ///
    /// With a cache present, `register_metadata` and `build_ip_index` persist the heavy data to
    /// RocksDB (METADATA and RULE_CONTEXT column families) and the four `ip_index_*` structures
    /// stay empty in RAM. `resolve_rule_block` / `lookup_ip` read the contexts back lazily on the
    /// (infrequent) logging path.
    pub fn with_cache(cache: Arc<CacheRocksDb>) -> Self {
        Self {
            cache: Some(cache),
            rules_cache: Vec::new(),
            ..Self::default()
        }
    }

    /// Owning file name for a metadata id, from whichever store is active.
    fn file_name_for(&self, metadata_id: u32) -> Option<Arc<str>> {
        if self.cache.is_some() {
            self.metadata_light
                .get(&metadata_id)
                .map(|(_, n)| n.clone())
        } else {
            self.metadata_by_id
                .get(&metadata_id)
                .map(|m| m.file_name.clone())
        }
    }

    /// Category for a metadata id, from whichever store is active.
    pub fn category_for(&self, metadata_id: u32) -> Option<FireholCategory> {
        if self.cache.is_some() {
            self.metadata_light.get(&metadata_id).map(|(c, _)| *c)
        } else {
            self.metadata_by_id.get(&metadata_id).map(|m| m.category)
        }
    }

    /// Register a new metadata entry and return its assigned ID.
    pub fn register_metadata(&mut self, metadata: FireholMetadata) -> u32 {
        let id = metadata.id;
        if let Err(e) = self.try_register_metadata(metadata) {
            tracing::warn!("cache_rocksdb register_metadata(id={id}) failed: {e}");
        }
        id
    }

    pub(crate) fn try_register_metadata(
        &mut self,
        metadata: FireholMetadata,
    ) -> crate::error::Result<u32> {
        let id = metadata.id;
        if let Some(cache) = &self.cache {
            // Persist the full verbose metadata to RocksDB; retain only the small per-file hot
            // bits (category, file_name) in RAM so rule building / counters never touch the DB.
            cache.put_metadata(&metadata)?;
            self.metadata_light
                .insert(id, (metadata.category, metadata.file_name));
        } else {
            self.metadata_by_id.insert(id, Arc::new(metadata));
        }
        Ok(id)
    }

    /// Ensure the dense `rules` `Vec` is large enough to hold the given `rule_id`.
    fn ensure_capacity(&mut self, rule_id: u32) {
        let idx = rule_id as usize;
        if self.rules.len() <= idx {
            self.rules.resize_with(idx + 1, || RuleBlockEntry {
                metadata_id: 0,
                category: FireholCategory::Other,
                line: 0,
                block: None,
            });
        }
    }

    /// Register rule info mapped from an eBPF rule ID.
    ///
    /// The owning file name is derived from `metadata_by_id` (already registered)
    /// rather than being carried on every rule, so it is only ever stored once.
    pub fn register_rule(&mut self, rule: FireholRuleInfo) {
        let file_name = self.file_name_for(rule.metadata_id);
        *self.category_counts.entry(rule.category).or_insert(0) += 1;
        if let Some(name) = file_name {
            *self.blocklist_counts.entry(name).or_insert(0) += 1;
        }
        if self.cache.is_some() {
            // Cache mode: store only the compact (metadata_id, line); category/file are derived
            // from `metadata_light`. `block` is always None here, so keeping a full
            // `RuleBlockEntry` (24 bytes, incl. an Option<Arc>) per rule would be pure overhead.
            let idx = rule.rule_id as usize;
            if self.rules_cache.len() <= idx {
                self.rules_cache.resize(idx + 1, (0, 0));
            }
            self.rules_cache[idx] = (rule.metadata_id, rule.line);
        } else {
            self.ensure_capacity(rule.rule_id);
            self.rules[rule.rule_id as usize] = RuleBlockEntry {
                metadata_id: rule.metadata_id,
                category: rule.category,
                line: rule.line,
                block: None,
            };
        }
        self.rule_count += 1;
    }

    /// Resolve an eBPF rule ID to its active rule information.
    ///
    /// Returns an owned value so the cache-backed path can reconstruct it from the compact
    /// per-rule store (metadata id + line) without keeping a big dense array in RAM. On the
    /// fully-in-RAM path this clones the 24-byte struct (a Cheap `Arc` refcount bump when the
    /// shared block context is present); for the cache path `block` is always `None`.
    pub fn resolve_rule(&self, rule_id: u32) -> Option<RuleBlockEntry> {
        if self.cache.is_some() {
            let (metadata_id, line) = self.rules_cache.get(rule_id as usize).copied()?;
            if metadata_id == 0 {
                return None;
            }
            let category = self
                .category_for(metadata_id)
                .unwrap_or(FireholCategory::Other);
            return Some(RuleBlockEntry {
                metadata_id,
                category,
                line,
                block: None,
            });
        }
        self.rules.get(rule_id as usize).cloned()
    }

    /// Resolve an eBPF rule ID to the stable set of files/categories for the blocked target.
    ///
    /// Targets shared by a single rule don't allocate a context at build time; for them the
    /// context is built lazily (zero-copy when a shared context already exists, otherwise a
    /// small owned value derived from the rule's own metadata). This keeps the hot reload path
    /// allocation-free for the common case while preserving the full files/categories listing.
    pub fn resolve_rule_block(&self, rule_id: u32) -> Option<Cow<'_, RuleBlockContext>> {
        if self.cache.is_some() {
            // Per-target merged contexts are enumerated lazily on the logging path via
            // `lookup_ip` (RocksDB); the winning rule's own contribution is its single
            // (file, line, category) derived from the per-file hot index. This reproduces the
            // Ring Buffer consumer's final block because sibling files at the same target are
            // returned by `lookup_ip` and merged with dedup.
            let (metadata_id, line) = self.rules_cache.get(rule_id as usize).copied()?;
            if metadata_id == 0 {
                return None;
            }
            let file_name = self.file_name_for(metadata_id)?;
            let category = self
                .category_for(metadata_id)
                .unwrap_or(FireholCategory::Other);
            return Some(Cow::Owned(RuleBlockContext {
                files: vec![file_name],
                lines: vec![line],
                categories: vec![category],
            }));
        }
        let entry = self.rules.get(rule_id as usize)?;
        if let Some(block) = &entry.block {
            return Some(Cow::Borrowed(block.as_ref()));
        }
        let meta = self.metadata_by_id.get(&entry.metadata_id)?;
        Some(Cow::Owned(RuleBlockContext {
            files: vec![meta.file_name.clone()],
            lines: vec![entry.line],
            categories: vec![entry.category],
        }))
    }

    /// Build the target-based index: every rule ID whose entry shares the same IP/CIDR target
    /// maps to the same deduplicated, stably-ordered set of file names and categories.
    ///
    /// The context (and its `Vec` buffers) is allocated exactly once per distinct target and
    /// shared via `Arc`; file names are read from the (already registered) metadata, so no rule
    /// ever holds its own private copy.
    pub fn build_rule_block_index(&mut self, entries: &[FireholEntry]) {
        // In RocksDB mode the owned per-target merged contexts are not held in RAM: the single
        // context for a winning rule is derived from metadata and sibling files at the same target
        // are enumerated via `lookup_ip`, so building this shared index is unnecessary here.
        if self.cache.is_some() {
            return;
        }
        let mut by_target: HashMap<&FireholIpTarget, Vec<u32>> = HashMap::new();
        for entry in entries {
            by_target
                .entry(&entry.target)
                .or_default()
                .push(entry.rule_id);
        }

        for rule_ids in by_target.values() {
            // Skip targets referenced by a single rule: a shared context would only ever carry
            // that one rule's own file/category, which the lazy path in `resolve_rule_block`
            // already derives from metadata. Avoiding it drops ~1 heap allocation (Arc struct +
            // two Vec buffers) per unique target — the most common case with millions of rules.
            if rule_ids.len() <= 1 {
                continue;
            }
            let mut files: Vec<Arc<str>> = Vec::new();
            let mut lines: Vec<u32> = Vec::new();
            let mut categories: Vec<FireholCategory> = Vec::new();
            for rid in rule_ids {
                if let Some(entry) = self.rules.get(*rid as usize) {
                    if let Some(meta) = self.metadata_by_id.get(&entry.metadata_id) {
                        let mut dup = false;
                        for (i, f) in files.iter().enumerate() {
                            if f == &meta.file_name && lines[i] == entry.line {
                                dup = true;
                                break;
                            }
                        }
                        if !dup {
                            files.push(meta.file_name.clone());
                            lines.push(entry.line);
                        }
                    }
                    if !categories.contains(&entry.category) {
                        categories.push(entry.category);
                    }
                }
            }
            let context = Arc::new(RuleBlockContext {
                files,
                lines,
                categories,
            });
            for rid in rule_ids {
                if let Some(entry) = self.rules.get_mut(*rid as usize) {
                    // Insert the same `Arc` for every rule sharing this target: a single
                    // context allocation is shared instead of cloning it N times.
                    entry.block = Some(Arc::clone(&context));
                }
            }
        }
    }

    /// Resolve an internal metadata ID to its full metadata.
    pub fn resolve_metadata(&self, metadata_id: u32) -> Option<FireholMetadata> {
        if let Some(cache) = &self.cache {
            cache.get_metadata(metadata_id).ok().flatten()
        } else {
            self.metadata_by_id.get(&metadata_id).map(|m| (**m).clone())
        }
    }

    /// Build the reverse IP lookup index from the full set of parsed entries.
    ///
    /// For every distinct target (exact IP or CIDR) this builds a single shared
    /// [`RuleBlockContext`] listing every file/line/category that references it, then
    /// stores it in the family-appropriate structure (`ip_index_v4_exact`, `ip_index_v6_exact`,
    /// `ip_index_v4_lpm` or `ip_index_v6_lpm`). This lets a blocked IP be resolved to *all* of its
    /// owning FireHOL files regardless of which single rule the kernel LPM Trie selected.
    ///
    /// Note: holding one context per distinct target is the (intentional) RAM cost traded for
    /// the ability to attribute a block to every matching feed.
    pub fn build_ip_index(&mut self, entries: &[FireholEntry]) {
        // In RocksDB mode each distinct target's merged context is serialized into the
        // RULE_CONTEXT column family and discarded from RAM; the `ip_index_*` structures stay
        // empty and `lookup_ip` reads the contexts back lazily from RocksDB.
        if self.cache.is_some() {
            // Bound transient contexts independently of the number of targets in the feeds.
            for batch in entries.chunks(crate::firehol::parser::WORKER_BATCH_SIZE) {
                if let Err(e) = self.cache_entry_contexts(batch) {
                    tracing::warn!("cache_rocksdb build_ip_index failed: {e}");
                    break;
                }
            }
            return;
        }

        self.ip_index_v4_exact.clear();
        self.ip_index_v6_exact.clear();
        self.ip_index_v4_lpm.clear();
        self.ip_index_v6_lpm.clear();

        let mut files_by_target: HashMap<&FireholIpTarget, Vec<(Arc<str>, u32)>> = HashMap::new();
        let mut cats_by_target: HashMap<&FireholIpTarget, Vec<FireholCategory>> = HashMap::new();

        for entry in entries {
            let target = &entry.target;
            if let Some(meta) = self.metadata_by_id.get(&entry.metadata_id) {
                let files = files_by_target.entry(target).or_default();
                if !files
                    .iter()
                    .any(|(f, l)| f == &meta.file_name && *l == entry.line)
                {
                    files.push((Arc::clone(&meta.file_name), entry.line));
                }
                let cats = cats_by_target.entry(target).or_default();
                if !cats.contains(&meta.category) {
                    cats.push(meta.category);
                }
            }
        }

        for (target, files) in files_by_target {
            let cats = cats_by_target.remove(target).unwrap_or_default();
            let context = Arc::new(RuleBlockContext {
                files: files.iter().map(|(f, _)| Arc::clone(f)).collect(),
                lines: files.iter().map(|(_, l)| *l).collect(),
                categories: cats,
            });
            match target {
                FireholIpTarget::ExactV4(octets) => {
                    self.ip_index_v4_exact.insert(*octets, context);
                }
                FireholIpTarget::ExactV6(octets) => {
                    self.ip_index_v6_exact.insert(*octets, context);
                }
                FireholIpTarget::CidrV4(prefix, net) => {
                    self.ip_index_v4_lpm.push((*prefix as u8, *net, context));
                }
                FireholIpTarget::CidrV6(prefix, net) => {
                    self.ip_index_v6_lpm.push((*prefix as u8, *net, context));
                }
            }
        }
    }

    /// Fill the compact hot rule table without hashing category/file names for every IP.
    pub(crate) fn register_cached_entry(&mut self, entry: &FireholEntry) {
        let index = entry.rule_id as usize;
        if self.rules_cache.len() <= index {
            self.rules_cache.resize(index + 1, (0, 0));
        }
        self.rules_cache[index] = (entry.metadata_id, entry.line);
        self.rule_count += 1;
    }

    pub(crate) fn count_cached_metadata(&mut self, id: u32, count: usize) {
        if let Some((category, file)) = self.metadata_light.get(&id) {
            *self.category_counts.entry(*category).or_default() += count;
            *self.blocklist_counts.entry(file.clone()).or_default() += count;
        }
    }

    /// Contributions are sorted by (target, import sequence) in RocksDB. Build each
    /// context once, with no point reads, read/modify/write cycles, or global RAM index.
    pub(crate) fn build_ordered_contexts(
        &self,
        writer: &mut crate::cache_rocksdb::BulkWriter<'_>,
    ) -> crate::error::Result<()> {
        use crate::error::FirewallError;
        let cache = self.cache.as_ref().expect("cached registry");
        let mut current = [0u8; 18];
        let mut current_len = 0;
        let mut context = RuleBlockContext::default();
        let mut buffer = rkyv::util::AlignedVec::with_capacity(256);
        let mut emit = |key: &[u8], context: &RuleBlockContext| {
            cache.serialize_rule_context_into(context, &mut buffer)?;
            writer.put(crate::cache_rocksdb::cf::RULE_CONTEXT, key, &buffer)
        };
        cache.visit_pairs(crate::cache_rocksdb::cf::CONTRIBUTIONS, |key, value| {
            let len = key.len().saturating_sub(8);
            if value.len() != 8
                || !matches!(
                    (key.first(), len),
                    (Some(1), 5) | (Some(2), 17) | (Some(3), 6) | (Some(4), 18)
                )
            {
                return Err(FirewallError::Cache("Invalid FireHOL contribution".into()));
            }
            let target = &key[..len];
            if &current[..current_len] != target {
                if current_len != 0 {
                    emit(&current[..current_len], &context)?;
                }
                context.files.clear();
                context.lines.clear();
                context.categories.clear();
                current[..len].copy_from_slice(target);
                current_len = len;
            }
            let metadata_id = u32::from_be_bytes(value[..4].try_into().unwrap());
            let line = u32::from_be_bytes(value[4..8].try_into().unwrap());
            let (category, file) = self
                .metadata_light
                .get(&metadata_id)
                .ok_or_else(|| FirewallError::Cache("Unknown FireHOL metadata ID".into()))?;
            if !context
                .files
                .iter()
                .zip(&context.lines)
                .any(|(f, l)| f == file && *l == line)
            {
                context.files.push(file.clone());
                context.lines.push(line);
            }
            if !context.categories.contains(category) {
                context.categories.push(*category);
            }
            Ok(())
        })?;
        if current_len != 0 {
            emit(&current[..current_len], &context)?;
        }
        Ok(())
    }

    /// Merge a bounded batch into the on-disk index, retaining no global target map.
    pub(crate) fn cache_entry_contexts(
        &self,
        entries: &[FireholEntry],
    ) -> crate::error::Result<()> {
        let cache = self.cache.as_ref().expect("cached registry");
        let mut contexts =
            HashMap::<&FireholIpTarget, RuleBlockContext>::with_capacity(entries.len());
        for entry in entries {
            let Some((category, file)) = self.metadata_light.get(&entry.metadata_id) else {
                continue;
            };
            let context = match contexts.entry(&entry.target) {
                std::collections::hash_map::Entry::Occupied(slot) => slot.into_mut(),
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let mut key_buffer = [0; 18];
                    let ctx = cache
                        .get_rule_context(target_key(slot.key(), &mut key_buffer))?
                        .unwrap_or_default();
                    slot.insert(ctx)
                }
            };
            if !context
                .files
                .iter()
                .zip(&context.lines)
                .any(|(f, l)| f == file && *l == entry.line)
            {
                context.files.push(file.clone());
                context.lines.push(entry.line);
            }
            if !context.categories.contains(category) {
                context.categories.push(*category);
            }
        }
        let mut batch = cache.batch();
        let mut buffer = rkyv::util::AlignedVec::with_capacity(256);
        let mut key_buffer = [0; 18];
        for (target, context) in contexts {
            let key = target_key(target, &mut key_buffer);
            cache.serialize_rule_context_into(&context, &mut buffer)?;
            cache.batch_put(
                &mut batch,
                crate::cache_rocksdb::cf::RULE_CONTEXT,
                key,
                &buffer,
            )?;
        }
        cache.apply_batch(batch)
    }

    /// Look up every distinct FireHOL context whose target contains the given IP.
    ///
    /// Returns the shared contexts for the exact IP (if any) plus every enclosing CIDR
    /// (longest-prefix scan). Callers typically merge these with the single winning rule's own
    /// context to show all feeds that cover the blocked address.
    pub fn lookup_ip(&self, ip_version: u8, octets: &[u8]) -> Vec<Arc<RuleBlockContext>> {
        match ip_version {
            4 => self.lookup_ip_v4(octets),
            6 => self.lookup_ip_v6(octets),
            _ => Vec::new(),
        }
    }

    fn lookup_ip_v4(&self, octets: &[u8]) -> Vec<Arc<RuleBlockContext>> {
        if octets.len() != 4 {
            return Vec::new();
        }
        let ip = [octets[0], octets[1], octets[2], octets[3]];
        if let Some(cache) = &self.cache {
            // Query the persisted context for the exact address, then probe each prefix length
            // (a bounded 33-key scan) to find every enclosing CIDR that covers the IP.
            let mut out = Vec::new();
            if let Ok(Some(ctx)) = cache.get_rule_context(&ctx_key_v4_exact(&ip)) {
                out.push(Arc::new(ctx));
            }
            for prefix in (0..=32u8).rev() {
                let net = mask_v4(prefix, &ip);
                if let Ok(Some(ctx)) = cache.get_rule_context(&ctx_key_v4_lpm(prefix, &net)) {
                    out.push(Arc::new(ctx));
                }
            }
            return out;
        }
        let mut out = Vec::new();
        if let Some(ctx) = self.ip_index_v4_exact.get(&ip) {
            out.push(Arc::clone(ctx));
        }
        for (prefix, net, ctx) in &self.ip_index_v4_lpm {
            if prefix_contains_v4(*prefix, net, &ip) {
                out.push(Arc::clone(ctx));
            }
        }
        out
    }

    fn lookup_ip_v6(&self, octets: &[u8]) -> Vec<Arc<RuleBlockContext>> {
        if octets.len() != 16 {
            return Vec::new();
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(octets);
        if let Some(cache) = &self.cache {
            let mut out = Vec::new();
            if let Ok(Some(ctx)) = cache.get_rule_context(&ctx_key_v6_exact(&ip)) {
                out.push(Arc::new(ctx));
            }
            for prefix in (0..=128u8).rev() {
                let net = mask_v6(prefix, &ip);
                if let Ok(Some(ctx)) = cache.get_rule_context(&ctx_key_v6_lpm(prefix, &net)) {
                    out.push(Arc::new(ctx));
                }
            }
            return out;
        }
        let mut out = Vec::new();
        if let Some(ctx) = self.ip_index_v6_exact.get(&ip) {
            out.push(Arc::clone(ctx));
        }
        for (prefix, net, ctx) in self.ip_index_v6_lpm.iter() {
            if prefix_contains_v6(*prefix, net, &ip) {
                out.push(Arc::clone(ctx));
            }
        }
        out
    }

    /// Check whether the registry has no rules mapped.
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }

    /// Total number of mapped rules in the registry.
    pub fn total_rules(&self) -> usize {
        self.rule_count
    }

    /// Total number of unique blocklists in the registry.
    pub fn total_blocklists(&self) -> usize {
        self.blocklist_counts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_parsing() {
        assert_eq!(
            FireholCategory::parse_category("abuse"),
            FireholCategory::Abuse
        );
        assert_eq!(
            FireholCategory::parse_category("attacks"),
            FireholCategory::Attacks
        );
        assert_eq!(
            FireholCategory::parse_category("attack"),
            FireholCategory::Attacks
        );
        assert_eq!(
            FireholCategory::parse_category("malware"),
            FireholCategory::Malware
        );
        assert_eq!(
            FireholCategory::parse_category("spam"),
            FireholCategory::Spam
        );
        assert_eq!(
            FireholCategory::parse_category("proxy"),
            FireholCategory::Proxy
        );
        assert_eq!(
            FireholCategory::parse_category("botnet"),
            FireholCategory::Botnet
        );
        assert_eq!(
            FireholCategory::parse_category("unroutable"),
            FireholCategory::Unroutable
        );
        assert_eq!(
            FireholCategory::parse_category("anonymizers"),
            FireholCategory::Anonymizers
        );
        assert_eq!(
            FireholCategory::parse_category("unknown_category"),
            FireholCategory::Other
        );
    }

    #[test]
    fn test_category_roundtrip_id() {
        for cat in [
            FireholCategory::Abuse,
            FireholCategory::Attacks,
            FireholCategory::Malware,
            FireholCategory::Spam,
            FireholCategory::Proxy,
            FireholCategory::Botnet,
            FireholCategory::Unroutable,
            FireholCategory::Anonymizers,
            FireholCategory::Other,
        ] {
            let id = cat.id();
            assert_eq!(FireholCategory::from_id(id), cat);
        }
    }

    #[test]
    fn test_date_normalization() {
        // Standard FireHOL date
        let raw = "Mon Sep 14 02:22:20 UTC 2026";
        let norm = normalize_firehol_date(raw).unwrap();
        assert!(norm.starts_with("2026-09-14T02:22:20"));

        // RFC3339
        let rfc = "2026-09-14T12:00:00Z";
        assert_eq!(
            normalize_firehol_date(rfc).unwrap(),
            "2026-09-14T12:00:00+00:00"
        );

        // ISO format without T
        let iso = "2026-09-14 12:00:00";
        assert_eq!(
            normalize_firehol_date(iso).unwrap(),
            "2026-09-14T12:00:00+00:00"
        );

        // Empty date
        assert_eq!(normalize_firehol_date("   "), None);
    }

    #[test]
    fn test_registry_lookups() {
        let mut reg = FireholMetadataRegistry::new();
        let meta = FireholMetadata {
            id: 42,
            category: FireholCategory::Attacks,
            source_url: Some("https://example.com/dshield".into()),
            maintainer: Some("SANS DShield".into()),
            maintainer_url: Some("https://isc.sans.edu".into()),
            source_file_date: Some("2026-09-14T00:00:00Z".into()),
            file_name: Arc::from("dshield.netset"),
            version: Some("1.0".into()),
            update_frequency: Some("1 day".into()),
        };

        reg.register_metadata(meta);
        reg.register_rule(FireholRuleInfo {
            rule_id: 101,
            metadata_id: 42,
            category: FireholCategory::Attacks,
            line: 7,
        });

        assert_eq!(reg.total_rules(), 1);
        assert_eq!(reg.total_blocklists(), 1);

        let resolved_rule = reg.resolve_rule(101).unwrap();
        assert_eq!(resolved_rule.category, FireholCategory::Attacks);
        assert_eq!(resolved_rule.metadata_id, 42);
        assert_eq!(resolved_rule.line, 7);

        let resolved_meta = reg.resolve_metadata(42).unwrap();
        assert_eq!(&*resolved_meta.file_name, "dshield.netset");
        assert_eq!(resolved_meta.maintainer.as_deref(), Some("SANS DShield"));
    }

    #[test]
    fn test_rule_block_grouping_shared_target() {
        let mut reg = FireholMetadataRegistry::new();

        // Three files, same exact IPv4 target -> three distinct rule IDs sharing one context.
        let files = [
            (
                0u32,
                "stopforumspam_180d.ipset",
                FireholCategory::Abuse,
                11u32,
            ),
            (
                10u32,
                "blocklist_net_ua.ipset",
                FireholCategory::Other,
                12u32,
            ),
            (
                20u32,
                "firehol_abusers_30d.netset",
                FireholCategory::Attacks,
                13u32,
            ),
        ];
        for (meta_id, name, cat, line) in files {
            reg.register_metadata(FireholMetadata {
                id: meta_id,
                category: cat,
                source_url: None,
                maintainer: None,
                maintainer_url: None,
                source_file_date: None,
                file_name: Arc::from(name),
                version: None,
                update_frequency: None,
            });
            reg.register_rule(FireholRuleInfo {
                rule_id: meta_id,
                metadata_id: meta_id,
                category: cat,
                line,
            });
        }

        let entries = [
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 9]), 0, 0, 11),
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 9]), 10, 10, 12),
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 9]), 20, 20, 13),
        ];
        reg.build_rule_block_index(&entries);

        // Whatever rule ID the eBPF event carries, the resolved context must expose all 3 files.
        for rid in [0u32, 10, 20] {
            let ctx = reg.resolve_rule_block(rid).expect("context for rule");
            let names: Vec<&str> = ctx.files.iter().map(|f| f.as_ref()).collect();
            assert_eq!(
                names,
                vec![
                    "stopforumspam_180d.ipset",
                    "blocklist_net_ua.ipset",
                    "firehol_abusers_30d.netset"
                ]
            );
            assert_eq!(ctx.lines, vec![11, 12, 13]);
            let cats: Vec<&str> = ctx.categories.iter().map(|c| c.as_str()).collect();
            assert_eq!(cats, vec!["abuse", "other", "attacks"]);
        }
    }

    #[test]
    fn test_rule_block_cidr_lines_point_to_matching_files() {
        // Reproduces the shared-target case: the same CIDR appears in three distinct
        // blocklists at specific physical lines. Resolution must expose exactly those
        // (file, line) pairs and must NEVER leak files that happen to sit next to the
        // target in the same input files.
        let mut reg = FireholMetadataRegistry::new();

        // File A additionally contains an exact IP right before the CIDR; that exact IP's
        // line must never be attributed to the CIDR match.
        let specs = [
            (
                1u32,
                "cidr_report_bogons.netset",
                FireholCategory::Proxy,
                46u32,
            ),
            (
                2u32,
                "firehol_level1.netset",
                FireholCategory::Attacks,
                2148u32,
            ),
            (
                3u32,
                "iblocklist_cidr_report_bogons.netset",
                FireholCategory::Proxy,
                43u32,
            ),
            (
                4u32,
                "firehol_anonymous.netset",
                FireholCategory::Anonymizers,
                45u32,
            ),
        ];
        for (meta_id, name, cat, line) in specs {
            reg.register_metadata(FireholMetadata {
                id: meta_id,
                category: cat,
                source_url: None,
                maintainer: None,
                maintainer_url: None,
                source_file_date: None,
                file_name: Arc::from(name),
                version: None,
                update_frequency: None,
            });
            reg.register_rule(FireholRuleInfo {
                rule_id: meta_id,
                metadata_id: meta_id,
                category: cat,
                line,
            });
        }

        let cidr = FireholIpTarget::CidrV4(16, [192, 168, 0, 0]);
        let exact = FireholIpTarget::ExactV4([1, 0, 133, 100]);
        let entries = [
            // Three rules share the 192.168.0.0/16 CIDR.
            FireholEntry::new(cidr.clone(), 1, 1, 46),
            FireholEntry::new(cidr, 2, 2, 2148),
            FireholEntry::new(FireholIpTarget::CidrV4(16, [192, 168, 0, 0]), 3, 3, 43),
            // An unrelated exact IP immediately around the CIDR in file A.
            FireholEntry::new(exact, 4, 4, 45),
        ];
        reg.build_rule_block_index(&entries);

        // Any rule sharing the CIDR must resolve to the three bogons files + correct lines,
        // and must NOT include firehol_anonymous.netset (which belongs to the exact IP).
        for rid in [1u32, 2, 3] {
            let ctx = reg.resolve_rule_block(rid).expect("cidr context");
            let names: Vec<&str> = ctx.files.iter().map(|f| f.as_ref()).collect();
            assert_eq!(
                names,
                vec![
                    "cidr_report_bogons.netset",
                    "firehol_level1.netset",
                    "iblocklist_cidr_report_bogons.netset"
                ],
                "CIDR match must not attribute the nearby exact-IP file"
            );
            assert_eq!(ctx.lines, vec![46, 2148, 43]);
            // The unrelated exact-IP line must never leak into the CIDR context.
            assert!(!names.contains(&"firehol_anonymous.netset"));
        }
    }

    #[test]
    fn test_rule_block_grouping_dedups_and_separates_targets() {
        let mut reg = FireholMetadataRegistry::new(); // Same file listed twice for the same target must be deduplicated, and
                                                      // distinct targets must not leak file/category context to each other.
        let meta_a = FireholMetadata {
            id: 1,
            category: FireholCategory::Spam,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("a.ipset"),
            version: None,
            update_frequency: None,
        };
        reg.register_metadata(meta_a);
        reg.register_rule(FireholRuleInfo {
            rule_id: 1,
            metadata_id: 1,
            category: FireholCategory::Spam,
            line: 5,
        });
        reg.register_rule(FireholRuleInfo {
            rule_id: 2,
            metadata_id: 1,
            category: FireholCategory::Spam,
            line: 5,
        });

        let entries = [
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 1]), 1, 1, 5),
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 1]), 2, 1, 5),
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 2]), 2, 1, 5),
        ];
        reg.build_rule_block_index(&entries);

        let ctx = reg.resolve_rule_block(1).unwrap();
        assert_eq!(ctx.files, vec![Arc::from("a.ipset")]);
        assert_eq!(ctx.lines, vec![5]);
        assert_eq!(ctx.categories, vec![FireholCategory::Spam]);

        // Different target should not carry the same file/context.
        assert!(reg.resolve_rule_block(2).is_some());
    }

    #[test]
    fn test_rule_block_index_shares_single_arc_per_target() {
        let mut reg = FireholMetadataRegistry::new();
        // Two files, same target -> two rules must share ONE shared context allocation.
        for (meta_id, name, cat) in [
            (1u32, "a.ipset", FireholCategory::Attacks),
            (2u32, "b.ipset", FireholCategory::Malware),
        ] {
            reg.register_metadata(FireholMetadata {
                id: meta_id,
                category: cat,
                source_url: None,
                maintainer: None,
                maintainer_url: None,
                source_file_date: None,
                file_name: Arc::from(name),
                version: None,
                update_frequency: None,
            });
            reg.register_rule(FireholRuleInfo {
                rule_id: meta_id,
                metadata_id: meta_id,
                category: cat,
                line: 20,
            });
        }

        let entries = [
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 7]), 1, 1, 20),
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 7]), 2, 2, 20),
        ];
        reg.build_rule_block_index(&entries);

        let c1 = reg.rules.get(1).expect("rule 1");
        let c2 = reg.rules.get(2).expect("rule 2");
        // Both rules sharing the target must point to the SAME allocation.
        assert!(Arc::ptr_eq(
            c1.block.as_ref().unwrap(),
            c2.block.as_ref().unwrap()
        ));
        let b1 = c1.block.as_ref().unwrap();
        assert_eq!(b1.files, vec![Arc::from("a.ipset"), Arc::from("b.ipset")]);
        assert_eq!(b1.lines, vec![20, 20]);
        assert_eq!(
            b1.categories,
            vec![FireholCategory::Attacks, FireholCategory::Malware]
        );
    }

    #[test]
    fn test_build_ip_index_and_lookup() {
        let mut reg = FireholMetadataRegistry::new();
        for (meta_id, name, cat) in [
            (1u32, "cidr_report_bogons.netset", FireholCategory::Proxy),
            (2u32, "abusers.ipset", FireholCategory::Abuse),
            (3u32, "exact_scan.ipset", FireholCategory::Attacks),
        ] {
            reg.register_metadata(FireholMetadata {
                id: meta_id,
                category: cat,
                source_url: None,
                maintainer: None,
                maintainer_url: None,
                source_file_date: None,
                file_name: Arc::from(name),
                version: None,
                update_frequency: None,
            });
            reg.register_rule(FireholRuleInfo {
                rule_id: meta_id,
                metadata_id: meta_id,
                category: cat,
                line: meta_id * 10,
            });
        }

        let entries = [
            // 192.168.0.0/16 listed in two files.
            FireholEntry::new(FireholIpTarget::CidrV4(16, [192, 168, 0, 0]), 1, 1, 11),
            FireholEntry::new(FireholIpTarget::CidrV4(16, [192, 168, 0, 0]), 2, 2, 21),
            // An exact IP inside that /16.
            FireholEntry::new(FireholIpTarget::ExactV4([192, 168, 1, 254]), 3, 3, 31),
        ];
        reg.build_ip_index(&entries);

        // An IP inside the /16 returns both the /16-bearing files and the exact-IP file.
        let inside = reg.lookup_ip(4, &[192, 168, 1, 254]);
        let mut names: Vec<&str> = inside
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.as_ref()))
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "abusers.ipset",
                "cidr_report_bogons.netset",
                "exact_scan.ipset"
            ]
        );

        // An IP covered only by the /16 must NOT include the exact-IP file.
        let only_cidr = reg.lookup_ip(4, &[192, 168, 42, 1]);
        let mut names2: Vec<&str> = only_cidr
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.as_ref()))
            .collect();
        names2.sort_unstable();
        assert_eq!(names2, vec!["abusers.ipset", "cidr_report_bogons.netset"]);

        // IPv6 unknown version / no match returns empty.
        assert!(reg
            .lookup_ip(6, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_empty());
    }

    #[test]
    fn test_firehol_category_formatting_and_archived() {
        use std::str::FromStr;
        let cat = FireholCategory::from_str("malware").unwrap();
        assert_eq!(cat, FireholCategory::Malware);
        assert_eq!(cat.to_string(), "malware");
        assert_eq!(cat.as_str(), "malware");

        // Rkyv archiving
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&cat).unwrap();
        let archived = unsafe { rkyv::access_unchecked::<ArchivedFireholCategory>(&bytes) };
        assert_eq!(archived.as_str(), "malware");
        assert_eq!(archived.to_native(), FireholCategory::Malware);
        let from_archived: FireholCategory = (*archived).into();
        assert_eq!(from_archived, FireholCategory::Malware);
    }

    #[test]
    fn test_date_normalization_extended() {
        assert_eq!(normalize_firehol_date(""), None);
        assert_eq!(normalize_firehol_date("   "), None);

        // Standard ISO datetime
        let iso_dt = normalize_firehol_date("2026-09-14 02:22:20").unwrap();
        assert!(iso_dt.starts_with("2026-09-14T02:22:20"));

        // Standard ISO date
        let iso_d = normalize_firehol_date("2026-09-14").unwrap();
        assert!(iso_d.starts_with("2026-09-14T00:00:00"));

        // FireHOL without UTC
        let no_utc = normalize_firehol_date("Mon Sep 14 02:22:20 2026").unwrap();
        assert!(no_utc.starts_with("2026-09-14T02:22:20"));

        // Fallback string
        let fallback = normalize_firehol_date("unparseable-date-string").unwrap();
        assert_eq!(fallback, "unparseable-date-string");
    }

    #[test]
    fn test_archived_metadata_and_rule_block_context_accessors() {
        let meta = FireholMetadata {
            id: 42,
            category: FireholCategory::Attacks,
            source_url: Some(Arc::from("https://example.com/feed")),
            maintainer: Some(Arc::from("Team")),
            maintainer_url: Some(Arc::from("https://example.com")),
            source_file_date: Some(Arc::from("2026-09-14T00:00:00Z")),
            file_name: Arc::from("attacks.ipset"),
            version: Some(Arc::from("1.0")),
            update_frequency: Some(Arc::from("daily")),
        };

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&meta).unwrap();
        let archived = unsafe { rkyv::access_unchecked::<ArchivedFireholMetadata>(&bytes) };
        assert_eq!(archived.file_name_str(), "attacks.ipset");
        assert_eq!(archived.source_url_str(), Some("https://example.com/feed"));
        assert_eq!(archived.maintainer_str(), Some("Team"));
        assert_eq!(archived.maintainer_url_str(), Some("https://example.com"));
        assert_eq!(archived.source_file_date_str(), Some("2026-09-14T00:00:00Z"));
        assert_eq!(archived.version_str(), Some("1.0"));
        assert_eq!(archived.update_frequency_str(), Some("daily"));

        let ctx = RuleBlockContext {
            files: vec![Arc::from("f1.ipset"), Arc::from("f2.ipset")],
            lines: vec![10, 20],
            categories: vec![FireholCategory::Attacks, FireholCategory::Spam],
        };
        let ctx_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ctx).unwrap();
        let archived_ctx = unsafe { rkyv::access_unchecked::<ArchivedRuleBlockContext>(&ctx_bytes) };
        let files: Vec<&str> = archived_ctx.files_iter().collect();
        assert_eq!(files, vec!["f1.ipset", "f2.ipset"]);
        let cats: Vec<FireholCategory> = archived_ctx.categories_iter().collect();
        assert_eq!(cats, vec![FireholCategory::Attacks, FireholCategory::Spam]);
    }

    #[test]
    fn test_firehol_category_variants_as_str_and_archived() {
        use std::str::FromStr;

        let categories = [
            ("abuse", FireholCategory::Abuse),
            ("attacks", FireholCategory::Attacks),
            ("malware", FireholCategory::Malware),
            ("spam", FireholCategory::Spam),
            ("proxy", FireholCategory::Proxy),
            ("botnet", FireholCategory::Botnet),
            ("unroutable", FireholCategory::Unroutable),
            ("anonymizers", FireholCategory::Anonymizers),
            ("other", FireholCategory::Other),
        ];

        for (text, cat) in categories {
            assert_eq!(cat.as_str(), text);
            assert_eq!(cat.to_string(), text);
            assert_eq!(FireholCategory::from_str(text).unwrap(), cat);

            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&cat).unwrap();
            let archived = unsafe { rkyv::access_unchecked::<ArchivedFireholCategory>(&bytes) };
            assert_eq!(archived.as_str(), text);
            assert_eq!(archived.to_native(), cat);
            let converted: FireholCategory = (*archived).into();
            assert_eq!(converted, cat);
            let from_ref: FireholCategory = archived.into();
            assert_eq!(from_ref, cat);
        }
    }

    #[test]
    fn test_prefix_contains_edges() {
        let net = [192, 168, 10, 0];
        // /0 always matches whatever the address is.
        assert!(prefix_contains_v4(0, &net, &[8, 8, 8, 8]));
        // /32 requires an exact byte-for-byte match.
        assert!(prefix_contains_v4(32, &net, &[192, 168, 10, 0]));
        assert!(!prefix_contains_v4(32, &net, &[192, 168, 10, 1]));
        // /24 covers the whole fourth octet.
        assert!(prefix_contains_v4(24, &net, &[192, 168, 10, 255]));
        assert!(!prefix_contains_v4(24, &net, &[192, 168, 11, 0]));

        let net6 = [0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // /20 matches on the first two full bytes; partial byte differs in remaining bits.
        let partial_same = [0x20, 0x01, 0xdb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let partial_diff = [0x20, 0x01, 0x5b, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(prefix_contains_v6(20, &net6, &partial_same));
        assert!(!prefix_contains_v6(20, &net6, &partial_diff));
        // /0 matches everything; /128 requires exact equality.
        assert!(prefix_contains_v6(0, &net6, &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert!(prefix_contains_v6(128, &net6, &net6));
        assert!(!prefix_contains_v6(128, &net6, &partial_same));
    }

    #[test]
    fn test_arc_str_serde_roundtrip() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Payload {
            #[serde(with = "arc_str_serde")]
            name: std::sync::Arc<str>,
            #[serde(with = "option_arc_str_serde")]
            description: Option<std::sync::Arc<str>>,
        }

        let json = r#"{"name":"attackers.ipset","description":"daily feed"}"#;
        let payload: Payload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name.as_ref(), "attackers.ipset");
        assert_eq!(payload.description.as_deref(), Some("daily feed"));

        // None serializes to null and round-trips.
        let json2 = serde_json::to_string(&Payload {
            name: std::sync::Arc::from("x.ipset"),
            description: None,
        })
        .unwrap();
        assert!(json2.contains("\"description\":null"));
        let back: Payload = serde_json::from_str(&json2).unwrap();
        assert_eq!(back.description, None);

        let payload = Payload {
            name: std::sync::Arc::from("attackers.ipset"),
            description: Some(std::sync::Arc::from("daily feed")),
        };
        assert_eq!(payload, serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap());
    }

    #[test]
    fn test_cache_mode_compact_rule_registration_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Arc::new(CacheRocksDb::open(tmp.path()).unwrap());
        let mut reg = FireholMetadataRegistry::with_cache(cache);

        reg.register_metadata(FireholMetadata {
            id: 10,
            category: FireholCategory::Proxy,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("proxies.ipset"),
            version: None,
            update_frequency: None,
        });
        // Cache-mode register_rule must resize the compact rules_cache vector.
        reg.register_rule(FireholRuleInfo {
            rule_id: 3,
            metadata_id: 10,
            category: FireholCategory::Proxy,
            line: 9,
        });
        let rule = reg.resolve_rule(3).expect("cache-mode rule");
        assert_eq!(rule.metadata_id, 10);
        assert_eq!(rule.category, FireholCategory::Proxy);
        assert_eq!(rule.line, 9);

        // build_rule_block_index is a no-op when a cache is active.
        reg.build_rule_block_index(&[]);

        // A placeholder entry with metadata_id 0 resolves to None.
        reg.register_cached_entry(&FireholEntry::new(
            FireholIpTarget::ExactV4([10, 0, 0, 9]),
            4,
            0,
            0,
        ));
        assert!(reg.resolve_rule_block(4).is_none());
    }

    #[test]
    fn test_rule_block_grouping_multi_line_multi_category() {
        let mut reg = FireholMetadataRegistry::new();
        reg.register_metadata(FireholMetadata {
            id: 1,
            category: FireholCategory::Spam,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("spam.ipset"),
            version: None,
            update_frequency: None,
        });
        reg.register_metadata(FireholMetadata {
            id: 2,
            category: FireholCategory::Malware,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("malware.ipset"),
            version: None,
            update_frequency: None,
        });
        for (rule_id, meta_id, line) in [(1u32, 1u32, 5u32), (2, 1, 7), (3, 2, 9)] {
            reg.register_rule(FireholRuleInfo {
                rule_id,
                metadata_id: meta_id,
                category: if meta_id == 1 {
                    FireholCategory::Spam
                } else {
                    FireholCategory::Malware
                },
                line,
            });
        }

        let entries = [
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 7]), 1, 1, 5),
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 7]), 2, 1, 7),
            FireholEntry::new(FireholIpTarget::ExactV4([203, 0, 113, 7]), 3, 2, 9),
        ];
        reg.build_rule_block_index(&entries);

        let ctx = reg.resolve_rule_block(3).unwrap();
        assert_eq!(
            ctx.files,
            vec![Arc::from("spam.ipset"), Arc::from("spam.ipset"), Arc::from("malware.ipset")]
        );
        assert_eq!(ctx.lines, vec![5, 7, 9]);
        assert_eq!(
            ctx.categories,
            vec![FireholCategory::Spam, FireholCategory::Malware]
        );
    }

    #[test]
    fn test_firehol_registry_ipv6_and_helpers() {
        let mut reg = FireholMetadataRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.total_rules(), 0);
        assert_eq!(reg.total_blocklists(), 0);

        let meta_id = reg.register_metadata(FireholMetadata {
            id: 1,
            category: FireholCategory::Botnet,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("botnets_v6.netset"),
            version: None,
            update_frequency: None,
        });
        reg.register_rule(FireholRuleInfo {
            rule_id: 1,
            metadata_id: meta_id,
            category: FireholCategory::Botnet,
            line: 5,
        });

        assert!(!reg.is_empty());
        assert_eq!(reg.total_rules(), 1);
        assert_eq!(reg.total_blocklists(), 1);

        let v6_net = [0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v6_exact = [0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let entries = [
            FireholEntry::new(FireholIpTarget::CidrV6(32, v6_net), 1, 1, 5),
            FireholEntry::new(FireholIpTarget::ExactV6(v6_exact), 2, 1, 6),
        ];
        reg.build_ip_index(&entries);

        let res = reg.lookup_ip(6, &v6_exact);
        assert!(!res.is_empty());
        let res_other = reg.lookup_ip(6, &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(res_other.is_empty());

        let rule_opt = reg.resolve_rule(1);
        assert!(rule_opt.is_some());
        let block_opt = reg.resolve_rule_block(1);
        assert!(block_opt.is_some());
        let meta_resolved = reg.resolve_metadata(1);
        assert!(meta_resolved.is_some());
    }

    #[test]
    fn test_firehol_registry_with_rocksdb_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Arc::new(CacheRocksDb::open(tmp.path()).unwrap());
        let mut reg = FireholMetadataRegistry::with_cache(cache);

        let meta = FireholMetadata {
            id: 10,
            category: FireholCategory::Abuse,
            source_url: Some(Arc::from("https://example.com/abuse")),
            maintainer: Some(Arc::from("Maintainer")),
            maintainer_url: None,
            source_file_date: None,
            file_name: Arc::from("abuse.ipset"),
            version: None,
            update_frequency: None,
        };

        reg.register_metadata(meta);
        reg.count_cached_metadata(10, 5);

        let entry = FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 1]), 1, 10, 12);
        reg.register_cached_entry(&entry);

        let resolved_meta = reg.resolve_metadata(10);
        assert!(resolved_meta.is_some());
        assert_eq!(resolved_meta.unwrap().file_name.as_ref(), "abuse.ipset");

        let resolved_rule = reg.resolve_rule(1);
        assert!(resolved_rule.is_some());
        assert_eq!(resolved_rule.unwrap().category, FireholCategory::Abuse);

        let block = reg.resolve_rule_block(1);
        assert!(block.is_some());

        // Build ip index with cache
        reg.build_ip_index(&[entry]);
        let looked_up = reg.lookup_ip(4, &[10, 0, 0, 1]);
        assert!(!looked_up.is_empty());
    }
}
