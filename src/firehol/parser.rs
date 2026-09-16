//! High-performance parallel parser for FireHOL `.ipset` and `.netset` blocklists.
//!
//! Features:
//! - Auto-discovery of all `.ipset` and `.netset` files
//! - Descending file size sorting for optimal CPU load distribution
//! - Dynamic work stealing via a shared atomic file index
//! - One worker per available core, bounded by file count
//! - Zero-copy string splitting and streaming line processing
//! - Extraction of FireHOL comment metadata and RFC3339 date normalization
//! - Mid-file metadata change detection
//! - Exact single-IP vs CIDR subnet classification (`/32` and `/128` routed to exact HashMaps)
//! - Strict validation: any invalid IP or CIDR immediately fails the entire import
//! - Recycled 32,768-entry blocks and one bounded bulk writer (up to 300 MiB)
//! - Aggregation of blocklist and threat category statistics

use crate::cache_rocksdb::{BulkWriter, CacheRocksDb, MAX_IMPORT_BATCH_BYTES};
use crate::console::*;
use crate::firehol::{
    entry::{FireholEntry, FireholIpTarget},
    metadata::{
        normalize_firehol_date, FireholCategory, FireholMetadata, FireholMetadataRegistry,
        FireholRuleInfo,
    },
    metrics::FireholMetrics,
};
use ipnet::IpNet;
use std::{
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

/// Batch size for worker-local entry accumulation before transferring to shared state.
pub const WORKER_BATCH_SIZE: usize = 32_768;

/// Errors that can occur during FireHOL blocklist parsing.
#[derive(thiserror::Error, Debug)]
pub enum FireholParseError {
    #[error("FireHOL cache failed: {0}")]
    Cache(#[from] crate::error::FirewallError),
    #[error("I/O error reading blocklist file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid IP or CIDR entry in '{path}:{line}': '{entry}'")]
    InvalidEntry {
        path: PathBuf,
        line: usize,
        entry: String,
    },

    #[error("Empty or invalid blocklist directory at '{0}'")]
    InvalidDirectory(PathBuf),

    #[error("Worker thread failed during parallel parsing: {0}")]
    WorkerPanic(String),
}

/// Consolidated results of parsing all FireHOL blocklists.
#[derive(Debug, Clone, Default)]
pub struct FireholDataSet {
    /// All parsed IP and CIDR entries
    pub entries: Vec<FireholEntry>,
    /// Temporary disk spool used by the production import pipeline.
    pub stored_entries: Option<Arc<CacheRocksDb>>,
    /// Metadata registry mapping rule IDs to categories and blocklist origins
    pub registry: FireholMetadataRegistry,
    /// Total number of blocklist files processed
    pub total_files: usize,
    /// Total bytes read across all files
    pub total_bytes: u64,
    pub timing: FireholImportTiming,
    /// Total exact IPv4 addresses (routed to HashMap)
    pub exact_v4_count: usize,
    /// Total exact IPv6 addresses (routed to HashMap)
    pub exact_v6_count: usize,
    /// Total IPv4 CIDR subnets (routed to LPM Trie)
    pub lpm_v4_count: usize,
    /// Total IPv6 CIDR subnets (routed to LPM Trie)
    pub lpm_v6_count: usize,
}

impl FireholDataSet {
    pub fn is_empty(&self) -> bool {
        self.total_entries() == 0
    }

    pub fn total_entries(&self) -> usize {
        if self.stored_entries.is_some() {
            self.total_hashmap_entries() + self.total_lpm_entries()
        } else {
            self.entries.len()
        }
    }

    pub(crate) fn visit_entries(
        &self,
        mut visitor: impl FnMut(&FireholEntry) -> crate::error::Result<()>,
    ) -> crate::error::Result<()> {
        if let Some(cache) = &self.stored_entries {
            cache.visit_values(crate::cache_rocksdb::cf::ENTRIES, |bytes| {
                if bytes.is_empty() || bytes.len() % 30 != 0 {
                    return Err(crate::error::FirewallError::Cache(
                        "Invalid FireHOL spool block".into(),
                    ));
                }
                for encoded in bytes.as_chunks::<30>().0 {
                    visitor(&FireholEntry::decode(encoded)?)?;
                }
                Ok(())
            })?;
        } else {
            for entry in &self.entries {
                visitor(entry)?;
            }
        }
        Ok(())
    }

    pub fn total_hashmap_entries(&self) -> usize {
        self.exact_v4_count + self.exact_v6_count
    }

    pub fn total_lpm_entries(&self) -> usize {
        self.lpm_v4_count + self.lpm_v6_count
    }
}

/// Metadata builder tracking the active FireHOL metadata state within a file.
#[derive(Debug, Clone)]
struct ActiveFileMetadata {
    file_name: Arc<str>,
    category: FireholCategory,
    source_url: Option<Arc<str>>,
    maintainer: Option<Arc<str>>,
    maintainer_url: Option<Arc<str>>,
    source_file_date: Option<Arc<str>>,
    version: Option<Arc<str>>,
    update_frequency: Option<Arc<str>>,
    current_metadata_id: u32,
}

impl ActiveFileMetadata {
    fn new(file_name: Arc<str>, initial_id: u32) -> Self {
        Self {
            file_name,
            category: FireholCategory::Other,
            source_url: None,
            maintainer: None,
            maintainer_url: None,
            source_file_date: None,
            version: None,
            update_frequency: None,
            current_metadata_id: initial_id,
        }
    }

    fn to_metadata(&self) -> FireholMetadata {
        FireholMetadata {
            id: self.current_metadata_id,
            category: self.category,
            source_url: self.source_url.clone(),
            maintainer: self.maintainer.clone(),
            maintainer_url: self.maintainer_url.clone(),
            source_file_date: self.source_file_date.clone(),
            file_name: self.file_name.clone(),
            version: self.version.clone(),
            update_frequency: self.update_frequency.clone(),
        }
    }
}

/// Stage times are worker-seconds for read/parse/wait and coordinator-seconds for
/// transformation/writes. Concurrent stages overlap and must not be added to total time.
#[derive(Debug, Clone, Default)]
pub struct FireholImportTiming {
    pub read_seconds: f64,
    pub parse_seconds: f64,
    pub queue_wait_seconds: f64,
    pub transform_seconds: f64,
    pub rocksdb_write_seconds: f64,
    pub rocksdb_bytes: u64,
    pub pipeline_seconds: f64,
    pub total_seconds: f64,
}

#[derive(Default)]
struct WorkerOutput {
    metadata: Vec<FireholMetadata>,
    files: usize,
    bytes: u64,
    timing: FireholImportTiming,
}

/// Read MiB chunks and lend complete UTF-8 lines directly from the read buffer.
/// Only the unfinished final line is moved; arbitrarily long lines remain supported.
fn visit_file_lines(
    path: &Path,
    mut visit: impl FnMut(&str, usize) -> Result<(), FireholParseError>,
) -> Result<(u64, f64, f64), FireholParseError> {
    let io_error = |source| FireholParseError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = File::open(path).map_err(io_error)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let (mut used, mut line_number, mut bytes) = (0, 0, 0);
    let (mut read_seconds, mut parse_seconds) = (0.0, 0.0);
    loop {
        if used == buffer.len() {
            buffer.resize(buffer.len() * 2, 0);
        }
        let start = Instant::now();
        let read = match file.read(&mut buffer[used..]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(io_error)?,
        };
        read_seconds += start.elapsed().as_secs_f64();
        bytes += read as u64;
        used += read;
        let end = if read == 0 {
            used
        } else {
            buffer[..used]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1)
        };
        let start = Instant::now();
        let text = std::str::from_utf8(&buffer[..end])
            .map_err(|e| io_error(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        for line in text.split_terminator('\n') {
            line_number += 1;
            visit(line, line_number)?;
        }
        parse_seconds += start.elapsed().as_secs_f64();
        buffer.copy_within(end..used, 0);
        used -= end;
        if read == 0 {
            break;
        }
    }
    Ok((bytes, read_seconds, parse_seconds))
}

/// High-performance parallel parser component.
/// Punch out a single IPv4 address from an IPv4 CIDR subnet, returning a minimal set of disjoint subnets.
pub fn exclude_v4_from_cidr(
    net: ipnet::Ipv4Net,
    target_ip: std::net::Ipv4Addr,
) -> Vec<ipnet::Ipv4Net> {
    if !net.contains(&target_ip) {
        return vec![net];
    }
    let mut result = Vec::with_capacity(32);
    let mut current = net;

    while current.prefix_len() < 32 {
        let p = current.prefix_len();
        let base = u32::from(current.network());
        let half0_net = std::net::Ipv4Addr::from(base);
        let half1_net = std::net::Ipv4Addr::from(base | (1 << (31 - p)));

        let half0 = ipnet::Ipv4Net::new(half0_net, p + 1).unwrap();
        let half1 = ipnet::Ipv4Net::new(half1_net, p + 1).unwrap();

        if half0.contains(&target_ip) {
            result.push(half1);
            current = half0;
        } else {
            result.push(half0);
            current = half1;
        }
    }
    result
}

/// Punch out a single IPv6 address from an IPv6 CIDR subnet, returning a minimal set of disjoint subnets.
pub fn exclude_v6_from_cidr(
    net: ipnet::Ipv6Net,
    target_ip: std::net::Ipv6Addr,
) -> Vec<ipnet::Ipv6Net> {
    if !net.contains(&target_ip) {
        return vec![net];
    }
    let mut result = Vec::with_capacity(128);
    let mut current = net;

    while current.prefix_len() < 128 {
        let p = current.prefix_len();
        let base = u128::from(current.network());
        let half0_net = std::net::Ipv6Addr::from(base);
        let half1_net = std::net::Ipv6Addr::from(base | (1u128 << (127 - p)));

        let half0 = ipnet::Ipv6Net::new(half0_net, p + 1).unwrap();
        let half1 = ipnet::Ipv6Net::new(half1_net, p + 1).unwrap();

        if half0.contains(&target_ip) {
            result.push(half1);
            current = half0;
        } else {
            result.push(half0);
            current = half1;
        }
    }
    result
}

/// Parse comma-separated list of IP addresses (IPv4 and IPv6) with trimming.
pub fn parse_ignore_ips(raw: &str) -> Vec<IpAddr> {
    raw.split(",")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(e) => {
                warn!("⚠️ Invalid IP \x27{}\x27 in FIREHOL_IGNORE_IP: {}", s, e);
                None
            }
        })
        .collect()
}

/// Parse directly to the binary map target, preserving the existing grammar:
/// std rejects zero-padded standalone IPv4, whereas ipnet accepts it in CIDRs.
fn parse_ipv4_target(bytes: &[u8]) -> Option<FireholIpTarget> {
    let mut octets = [0u8; 4];
    let mut offset = 0;
    let mut padded = false;
    for (index, octet) in octets.iter_mut().enumerate() {
        let start = offset;
        let mut value = 0u16;
        while let Some(digit @ b'0'..=b'9') = bytes.get(offset) {
            value = value * 10 + (digit - b'0') as u16;
            offset += 1;
            if offset - start > 3 || value > 255 {
                return None;
            }
        }
        if offset == start {
            return None;
        }
        padded |= offset - start > 1 && bytes[start] == b'0';
        *octet = value as u8;
        if index != 3 {
            if bytes.get(offset) != Some(&b'.') {
                return None;
            }
            offset += 1;
        }
    }
    if offset == bytes.len() {
        return (!padded).then_some(FireholIpTarget::ExactV4(octets));
    }
    if bytes.get(offset) != Some(&b'/') {
        return None;
    }
    let suffix = &bytes[offset + 1..];
    if suffix.is_empty() || suffix.len() > 2 {
        return None;
    }
    let mut prefix = 0u32;
    for digit in suffix {
        if !digit.is_ascii_digit() {
            return None;
        }
        prefix = prefix * 10 + (digit - b'0') as u32;
    }
    match prefix {
        32 => Some(FireholIpTarget::ExactV4(octets)),
        0..=31 => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            Some(FireholIpTarget::CidrV4(
                prefix,
                (u32::from_be_bytes(octets) & mask).to_be_bytes(),
            ))
        }
        _ => None,
    }
}

pub struct FireholParser;

impl FireholParser {
    /// Discover, sort, and parse all FireHOL files in parallel without ignore filters.
    pub fn parse_directory<P: AsRef<Path>>(
        dir_path: P,
        metrics: Option<&FireholMetrics>,
    ) -> Result<FireholDataSet, FireholParseError> {
        Self::parse_directory_with_ignore(dir_path, &[], metrics)
    }

    /// Like [`Self::parse_directory`] but backs the registry with a RocksDB cache so the heavy
    /// per-target and verbose metadata are persisted rather than resident in RAM.
    pub fn parse_directory_cached<P: AsRef<Path>>(
        dir_path: P,
        metrics: Option<&FireholMetrics>,
        cache: Option<Arc<CacheRocksDb>>,
    ) -> Result<FireholDataSet, FireholParseError> {
        Self::parse_directory_with_ignore_cached(dir_path, &[], metrics, cache)
    }

    /// Discover, sort, and parse all FireHOL files in parallel while excluding any IPs in `ignore_ips`.
    pub fn parse_directory_with_ignore<P: AsRef<Path>>(
        dir_path: P,
        ignore_ips: &[IpAddr],
        metrics: Option<&FireholMetrics>,
    ) -> Result<FireholDataSet, FireholParseError> {
        Self::parse_directory_with_ignore_cached(dir_path, ignore_ips, metrics, None)
    }

    /// Like [`Self::parse_directory_with_ignore`] but backs the registry with a RocksDB cache.
    pub fn parse_directory_with_ignore_cached<P: AsRef<Path>>(
        dir_path: P,
        ignore_ips: &[IpAddr],
        metrics: Option<&FireholMetrics>,
        cache: Option<Arc<CacheRocksDb>>,
    ) -> Result<FireholDataSet, FireholParseError> {
        Self::parse_directory_impl(dir_path, ignore_ips, metrics, cache, false)
    }

    pub(crate) fn parse_directory_spooled<P: AsRef<Path>>(
        dir_path: P,
        ignore_ips: &[IpAddr],
        metrics: Option<&FireholMetrics>,
        cache: Option<Arc<CacheRocksDb>>,
    ) -> Result<FireholDataSet, FireholParseError> {
        Self::parse_directory_impl(dir_path, ignore_ips, metrics, cache, true)
    }

    fn parse_directory_impl<P: AsRef<Path>>(
        dir_path: P,
        ignore_ips: &[IpAddr],
        metrics: Option<&FireholMetrics>,
        cache: Option<Arc<CacheRocksDb>>,
        spool: bool,
    ) -> Result<FireholDataSet, FireholParseError> {
        let start_time = Instant::now();
        // A failed/replaced import must never overwrite a registry still used by readers.
        let cache = cache
            .map(|c| c.import_generation().map(Arc::new))
            .transpose()?;
        let dir = dir_path.as_ref();
        if !dir.is_dir() {
            return Err(FireholParseError::InvalidDirectory(dir.to_path_buf()));
        }

        // 1. Discover all .ipset and .netset files
        let mut files = Self::discover_files(dir)?;
        if files.is_empty() {
            warn!(
                "{}",
                yellow_bold(format!("⚠️ No .ipset or .netset files found in {:?}", dir))
            );
            return Ok(FireholDataSet::default());
        }

        // 2. Sort files by size descending (largest files first for optimal worker load balancing)
        files.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));

        let total_file_size: u64 = files.iter().map(|(_, sz)| *sz).sum();
        let file_count = files.len();

        let total_mb = total_file_size as f64 / 1_048_576.0;
        info!(
            "{}",
            cyan_bold(format!(
                "📂 Discovered {} FireHOL files ({} MB total). Starting parallel parsing...",
                bold_num(file_count),
                bold(format_float_with_spaces(total_mb, 2))
            ))
        );

        // 3. Worker configuration
        let num_cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let num_workers = num_cpus.min(file_count).max(1);
        let file_index = AtomicUsize::new(0);
        let abort = AtomicBool::new(false);
        let next_metadata_id = AtomicU32::new(1);
        // One budget for the entire import, never 300 MiB per worker.
        let batch_limit = (total_file_size.saturating_mul(8) as usize).min(MAX_IMPORT_BATCH_BYTES);
        let mut writer = cache.as_ref().map(|c| BulkWriter::new(c, batch_limit));
        let mut all_entries = Vec::new();
        let mut all_metadata = Vec::new();
        let mut total_files_processed = 0;
        let mut total_bytes_read = 0;
        let mut timing = FireholImportTiming::default();
        let pipeline_start = Instant::now();

        thread::scope(|scope| -> Result<(), FireholParseError> {
            let (tx, rx) = mpsc::sync_channel::<(usize, Vec<FireholEntry>)>(num_workers);
            let mut handles = Vec::new();
            let mut recycle = Vec::new();
            for worker_id in 0..num_workers {
                let (reuse_tx, reuse_rx) = mpsc::sync_channel(2);
                recycle.push(reuse_tx);
                let tx = tx.clone();
                let files = &files;
                let file_index = &file_index;
                let abort = &abort;
                let next_metadata_id = &next_metadata_id;
                handles.push(
                    scope.spawn(move || -> Result<WorkerOutput, FireholParseError> {
                        let mut result = WorkerOutput::default();
                        let mut entries = Vec::with_capacity(WORKER_BATCH_SIZE);
                        let wait_seconds = std::cell::Cell::new(0.0);
                        let mut flush = |entries: &mut Vec<FireholEntry>| {
                            if entries.is_empty() {
                                return Ok(());
                            }
                            let start = Instant::now();
                            let full = std::mem::take(entries);
                            tx.send((worker_id, full)).map_err(|_| {
                                FireholParseError::WorkerPanic("import writer stopped".into())
                            })?;
                            *entries = reuse_rx
                                .try_recv()
                                .unwrap_or_else(|_| Vec::with_capacity(WORKER_BATCH_SIZE));
                            wait_seconds.set(wait_seconds.get() + start.elapsed().as_secs_f64());
                            Ok(())
                        };
                        loop {
                            if abort.load(Ordering::Relaxed) {
                                break;
                            }
                            let index = file_index.fetch_add(1, Ordering::Relaxed);
                            let Some((path, _)) = files.get(index) else {
                                break;
                            };
                            match Self::parse_single_file(
                                path,
                                ignore_ips,
                                next_metadata_id,
                                &mut entries,
                                &mut result.metadata,
                                &mut flush,
                            ) {
                                Ok((bytes, read, parse)) => {
                                    result.files += 1;
                                    result.bytes += bytes;
                                    result.timing.read_seconds += read;
                                    result.timing.parse_seconds += parse;
                                }
                                Err(e) => {
                                    abort.store(true, Ordering::Relaxed);
                                    return Err(e);
                                }
                            }
                        }
                        let parsing_wait = wait_seconds.get();
                        flush(&mut entries)?;
                        result.timing.parse_seconds =
                            (result.timing.parse_seconds - parsing_wait).max(0.0);
                        result.timing.queue_wait_seconds = wait_seconds.get();
                        Ok(result)
                    }),
                );
            }
            drop(tx);
            let mut sequence = 0u64;
            let mut encoded = Vec::with_capacity(WORKER_BATCH_SIZE * 30);
            let consume = (|| -> Result<(), FireholParseError> {
                while let Ok((worker, mut entries)) = rx.recv() {
                    let start = Instant::now();
                    // IDs are assigned once in publication order: no contended atomic per IP.
                    for (offset, entry) in entries.iter_mut().enumerate() {
                        entry.rule_id =
                            u32::try_from(sequence + offset as u64 + 1).map_err(|_| {
                                FireholParseError::WorkerPanic("FireHOL rule ID overflow".into())
                            })?;
                    }
                    let prior_write = writer.as_ref().map_or(0.0, |w| w.write_seconds);
                    if let Some(writer) = &mut writer {
                        writer.entries(&entries, sequence, spool, &mut encoded)?;
                    }
                    sequence += entries.len() as u64;
                    if !spool || cache.is_none() {
                        all_entries.append(&mut entries);
                    }
                    entries.clear();
                    let _ = recycle[worker].try_send(entries);
                    timing.transform_seconds += start.elapsed().as_secs_f64()
                        - (writer.as_ref().map_or(0.0, |w| w.write_seconds) - prior_write);
                }
                if let Some(writer) = &mut writer {
                    writer.commit()?;
                }
                Ok(())
            })();
            if consume.is_err() {
                abort.store(true, Ordering::Relaxed);
            }
            drop(rx); // Unblock senders before joining, including the writer-error path.
            let mut failure = consume.err();
            for handle in handles {
                match handle.join() {
                    Ok(Ok(worker)) => {
                        all_metadata.extend(worker.metadata);
                        total_files_processed += worker.files;
                        total_bytes_read += worker.bytes;
                        timing.read_seconds += worker.timing.read_seconds;
                        timing.parse_seconds += worker.timing.parse_seconds;
                        timing.queue_wait_seconds += worker.timing.queue_wait_seconds;
                    }
                    Ok(Err(e)) => {
                        if failure.is_none() {
                            failure = Some(e);
                        }
                    }
                    Err(e) => {
                        if failure.is_none() {
                            failure = Some(FireholParseError::WorkerPanic(format!("{e:?}")));
                        }
                    }
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            Ok(())
        })
            .inspect_err(|_| {
                if let Some(m) = metrics {
                    m.invalid_entries_total.inc();
                }
            })?;
        timing.pipeline_seconds = pipeline_start.elapsed().as_secs_f64();
        info!(
            "FireHOL read/parse/spool pipeline finished in {:.3}s; building ordered contexts",
            timing.pipeline_seconds
        );

        // 6. Build consolidated registry and counters
        let mut registry = match cache.clone() {
            Some(cache) => FireholMetadataRegistry::with_cache(cache),
            None => FireholMetadataRegistry::new(),
        };
        for meta in all_metadata {
            registry.try_register_metadata(meta)?;
        }
        let mut dataset = FireholDataSet {
            entries: all_entries,
            stored_entries: if spool { cache.clone() } else { None },
            total_files: total_files_processed,
            total_bytes: total_bytes_read,
            ..FireholDataSet::default()
        };
        let mut counts = [0usize; 4];
        let transform_start = Instant::now();
        let mut metadata_counts = vec![0usize; next_metadata_id.load(Ordering::Relaxed) as usize];
        dataset.visit_entries(|entry| {
            if cache.is_some() {
                registry.register_cached_entry(entry);
                metadata_counts[entry.metadata_id as usize] += 1;
            } else {
                registry.register_rule(FireholRuleInfo {
                    rule_id: entry.rule_id,
                    metadata_id: entry.metadata_id,
                    line: entry.line,
                    category: registry
                        .category_for(entry.metadata_id)
                        .unwrap_or(FireholCategory::Other),
                });
            }
            counts[match entry.target {
                FireholIpTarget::ExactV4(_) => 0,
                FireholIpTarget::ExactV6(_) => 1,
                FireholIpTarget::CidrV4(_, _) => 2,
                FireholIpTarget::CidrV6(_, _) => 3,
            }] += 1;
            Ok(())
        })?;
        for (id, count) in metadata_counts.into_iter().enumerate() {
            if count > 0 {
                registry.count_cached_metadata(id as u32, count);
            }
        }
        let previous_write = writer.as_ref().map_or(0.0, |w| w.write_seconds);
        if let Some(writer) = &mut writer {
            registry.build_ordered_contexts(writer)?;
            writer.commit()?;
        } else {
            registry.build_rule_block_index(&dataset.entries);
            registry.build_ip_index(&dataset.entries);
        }
        timing.transform_seconds += transform_start.elapsed().as_secs_f64()
            - (writer.as_ref().map_or(0.0, |w| w.write_seconds) - previous_write);
        if let Some(writer) = &writer {
            timing.rocksdb_write_seconds = writer.write_seconds;
            timing.rocksdb_bytes = writer.written_bytes;
        }
        drop(writer);
        if let Some(cache) = &cache {
            let start = Instant::now();
            cache.clear_contributions()?;
            cache.flush_import()?;
            timing.rocksdb_write_seconds += start.elapsed().as_secs_f64();
        }
        let [exact_v4_count, exact_v6_count, lpm_v4_count, lpm_v6_count] = counts;
        let total_entries: usize = counts.iter().sum();
        let parse_duration = start_time.elapsed().as_secs_f64();
        timing.total_seconds = parse_duration;

        let throughput = total_file_size as f64 / parse_duration.max(f64::EPSILON);
        let entries_per_second = total_entries as f64 / parse_duration.max(f64::EPSILON);
        let db_throughput =
            timing.rocksdb_bytes as f64 / timing.rocksdb_write_seconds.max(f64::EPSILON);
        let input_mib = total_file_size as f64 / 1_048_576.0;
        let batch_mib = batch_limit.max(1024 * 1024) as f64 / 1_048_576.0;
        let fs = |v: f64, d: usize| bold(format_float_with_spaces(v, d)).to_string();
        let parse_mb_s = throughput / 1_000_000.0;
        let db_mb_s = db_throughput / 1_000_000.0;
        let rocksdb_mb = timing.rocksdb_bytes as f64 / 1_000_000.0;
        let entries_per_sec = bold_num(entries_per_second.round() as u64).to_string();
        info!(
            "{}",
            format!(
                "\n{} {}\n\
                 {} Files            : {}\n\
                 {} Entries          : {}\n\
                 {} Input size       : {} MiB ({} bytes)\n\
                 {} Read time        : {} s (summed workers)\n\
                 {} Parse time       : {} s (summed workers, excl. queue wait)\n\
                 {} Queue wait time  : {} s (summed workers)\n\
                 {} Pipeline time    : {} s (wall)\n\
                 {} Transform time   : {} s (coordinator, incl. ordered scans)\n\
                 {} RocksDB write    : {} s (writes + final flush)\n\
                 {} Total time       : {} s\n\
                 {} Parse throughput : {} MB/s\n\
                 {} Import speed     : {} entries/s\n\
                 {} RocksDB thp      : {} MB/s (logical batch bytes)\n\
                 {} RocksDB size     : {} MB\n\
                 {} Workers          : {}\n\
                 {} Batch budget     : {} MiB",
                cyan_bold("📊"),
                blue_bold("FireHOL import performance"),
                blue("🗂️"),
                bold_num(total_files_processed),
                green("🛡️"),
                bold_num(total_entries),
                magenta("💾"),
                fs(input_mib, 2),
                bold_num(total_file_size),
                cyan("⏱️"),
                fs(timing.read_seconds, 3),
                cyan("⏱️"),
                fs(timing.parse_seconds, 3),
                yellow("⏳"),
                fs(timing.queue_wait_seconds, 3),
                cyan("🔀"),
                fs(timing.pipeline_seconds, 3),
                magenta("⚙️"),
                fs(timing.transform_seconds, 3),
                blue("🗄️"),
                fs(timing.rocksdb_write_seconds, 3),
                green("📅"),
                fs(timing.total_seconds, 3),
                green("🚀"),
                fs(parse_mb_s, 2),
                cyan("⚡"),
                entries_per_sec,
                blue("🗄️"),
                fs(db_mb_s, 2),
                blue("🗄️"),
                fs(rocksdb_mb, 2),
                yellow("🧵"),
                bold_num(num_workers),
                magenta("📦"),
                bold(format_float_with_spaces(batch_mib, 1))
            )
        );

        // 7. Update Prometheus metrics
        if let Some(m) = metrics {
            m.parse_duration_seconds.observe(parse_duration);
            for (stage, seconds) in [
                ("read", timing.read_seconds),
                ("parse", timing.parse_seconds),
                ("queue_wait", timing.queue_wait_seconds),
                ("transform", timing.transform_seconds),
                ("rocksdb_write", timing.rocksdb_write_seconds),
                ("pipeline", timing.pipeline_seconds),
                ("total", timing.total_seconds),
            ] {
                m.import_stage_seconds
                    .with_label_values(&[stage])
                    .set(seconds);
            }
            m.import_throughput_bytes_per_second
                .with_label_values(&["parsing"])
                .set(throughput);
            m.import_throughput_bytes_per_second
                .with_label_values(&["rocksdb"])
                .set(db_throughput);
            m.import_entries_per_second.set(entries_per_second);
            m.import_written_bytes.set(timing.rocksdb_bytes as i64);
            m.import_files.set(total_files_processed as i64);
            m.blocklists_total.set(registry.total_blocklists() as i64);
            m.total_entries.set(total_entries as i64);
            m.ipv4_total.set((exact_v4_count + lpm_v4_count) as i64);
            m.ipv6_total.set((exact_v6_count + lpm_v6_count) as i64);
            m.exact_total.set((exact_v4_count + exact_v6_count) as i64);
            m.cidr_total.set((lpm_v4_count + lpm_v6_count) as i64);
            m.hashmap_entries
                .set((exact_v4_count + exact_v6_count) as i64);
            m.lpm_entries.set((lpm_v4_count + lpm_v6_count) as i64);
            m.loaded_bytes_total.set(total_file_size as i64);

            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            m.last_compile_timestamp.set(now_unix);

            for (cat, count) in &registry.category_counts {
                m.entries_by_category
                    .with_label_values(&[cat.as_str(), "ipv4", "exact"])
                    .set(*count as i64);
            }
            for (bl, count) in &registry.blocklist_counts {
                m.entries_by_blocklist
                    .with_label_values(&[bl.as_ref()])
                    .set(*count as i64);
            }
        }

        info!(
            "{}",
            green_bold(format!(
                "⚡ FireHOL parallel parse complete in {:.3}s: {} entries ({} exact IPv4 🎯, {} exact IPv6 🎯, {} LPM IPv4 🌲, {} LPM IPv6 🌲) across {} blocklists",
                bold(format!("{:.3}", parse_duration)),
                bold_num(total_entries),
                bold_num(exact_v4_count),
                bold_num(exact_v6_count),
                bold_num(lpm_v4_count),
                bold_num(lpm_v6_count),
                bold_num(registry.total_blocklists())
            ))
        );

        dataset.timing = timing;
        dataset.registry = registry;
        dataset.exact_v4_count = exact_v4_count;
        dataset.exact_v6_count = exact_v6_count;
        dataset.lpm_v4_count = lpm_v4_count;
        dataset.lpm_v6_count = lpm_v6_count;
        Ok(dataset)
    }

    /// Discover all `.ipset` and `.netset` files in the given directory.
    fn discover_files(dir: &Path) -> Result<Vec<(PathBuf, u64)>, FireholParseError> {
        let mut files = Vec::new();
        let entries = std::fs::read_dir(dir).map_err(|e| FireholParseError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| FireholParseError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if ext == "ipset" || ext == "netset" {
                        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        files.push((path, size));
                    }
                }
            }
        }

        Ok(files)
    }

    /// Parse a single `.ipset` or `.netset` file line-by-line.
    fn parse_single_file(
        path: &Path,
        ignore_ips: &[IpAddr],
        next_metadata_id: &AtomicU32,
        entries_out: &mut Vec<FireholEntry>,
        metadata_out: &mut Vec<FireholMetadata>,
        flush: &mut impl FnMut(&mut Vec<FireholEntry>) -> Result<(), FireholParseError>,
    ) -> Result<(u64, f64, f64), FireholParseError> {
        let file_name = Arc::<str>::from(
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown"),
        );

        let mut current_meta = ActiveFileMetadata::new(
            file_name.clone(),
            next_metadata_id.fetch_add(1, Ordering::Relaxed),
        );

        let mut has_emitted_current_metadata = false;

        let timing = visit_file_lines(path, |line, line_num| {
            let trimmed = line.trim();

            // 1. Skip empty lines
            if trimmed.is_empty() {
                return Ok(());
            }

            // 2. Parse FireHOL Comment / Metadata
            if let Some(stripped) = trimmed.strip_prefix('#') {
                let comment_body = stripped.trim();
                if let Some((k, v)) = comment_body.split_once(':') {
                    let key = k.trim().to_lowercase();
                    let val = v.trim();

                    match key.as_str() {
                        "category" => {
                            let new_cat = FireholCategory::parse_category(val);
                            if new_cat != current_meta.category && has_emitted_current_metadata {
                                // Mid-file metadata change: allocate new metadata entry
                                current_meta.current_metadata_id =
                                    next_metadata_id.fetch_add(1, Ordering::Relaxed);
                                has_emitted_current_metadata = false;
                            }
                            current_meta.category = new_cat;
                        }
                        "maintainer" => {
                            current_meta.maintainer = Some(Arc::from(val));
                        }
                        "maintainer url" => {
                            current_meta.maintainer_url = Some(Arc::from(val));
                        }
                        "list source url" => {
                            current_meta.source_url = Some(Arc::from(val));
                        }
                        "source file date" => {
                            current_meta.source_file_date =
                                normalize_firehol_date(val).map(Arc::from);
                        }
                        "version" => {
                            current_meta.version = Some(Arc::from(val));
                        }
                        "update frequency" => {
                            current_meta.update_frequency = Some(Arc::from(val));
                        }
                        _ => {}
                    }
                }
                return Ok(());
            }

            // 3. Strip any inline comment
            let ip_part = if let Some((before_hash, _)) = trimmed.split_once('#') {
                before_hash.trim()
            } else {
                trimmed
            };

            if ip_part.is_empty() {
                return Ok(());
            }

            // 4. Ensure metadata is registered before storing first entry for it
            if !has_emitted_current_metadata {
                metadata_out.push(current_meta.to_metadata());
                has_emitted_current_metadata = true;
            }

            // 5. Parse IP or CIDR strictly, filtering ignored IPs and adapting CIDR subnets
            let invalid = || FireholParseError::InvalidEntry {
                path: path.to_path_buf(),
                line: line_num,
                entry: ip_part.to_string(),
            };
            let single = Self::parse_ip_or_cidr(ip_part).ok_or_else(invalid)?;
            let expanded;
            let targets = if ignore_ips.iter().any(|ip| single.contains_ip(ip)) {
                // Only matching exclusions need expansion/allocation and warning logs.
                expanded = Self::parse_ip_or_cidr_with_ignore(
                    ip_part,
                    ignore_ips,
                    &current_meta.file_name,
                    current_meta.category,
                )
                    .ok_or_else(invalid)?;
                expanded.as_slice()
            } else {
                std::slice::from_ref(&single)
            };

            for target in targets {
                entries_out.push(FireholEntry::new(
                    target.clone(),
                    0,
                    current_meta.current_metadata_id,
                    line_num as u32,
                ));
                if entries_out.len() >= WORKER_BATCH_SIZE {
                    flush(entries_out)?;
                }
            }
            Ok(())
        })?;

        // In case a file contained only comments and no IPs, emit its metadata
        if !has_emitted_current_metadata {
            metadata_out.push(current_meta.to_metadata());
        }

        Ok(timing)
    }

    /// Strictly parse an IP or CIDR string.
    pub fn parse_ip_or_cidr(token: &str) -> Option<FireholIpTarget> {
        if !token.as_bytes().contains(&b':') {
            return parse_ipv4_target(token.as_bytes());
        }
        if token.as_bytes().contains(&b'/') {
            let net = ipnet::Ipv6Net::from_str(token).ok()?;
            if net.prefix_len() == 128 {
                Some(FireholIpTarget::ExactV6(net.addr().octets()))
            } else {
                Some(FireholIpTarget::CidrV6(
                    net.prefix_len() as u32,
                    net.network().octets(),
                ))
            }
        } else {
            Some(FireholIpTarget::ExactV6(
                token.parse::<std::net::Ipv6Addr>().ok()?.octets(),
            ))
        }
    }

    /// Strictly parse an IP or CIDR string, ignoring matching IPs and adapting CIDRs into disjoint subnets.
    pub fn parse_ip_or_cidr_with_ignore(
        token: &str,
        ignore_ips: &[IpAddr],
        file_name: &str,
        category: FireholCategory,
    ) -> Option<Vec<FireholIpTarget>> {
        if token.contains('/') {
            // CIDR network notation
            match IpNet::from_str(token) {
                Ok(IpNet::V4(net)) => {
                    let p = net.prefix_len();
                    if p > 32 {
                        return None;
                    }
                    if p == 32 {
                        let addr = IpAddr::V4(net.addr());
                        if ignore_ips.contains(&addr) {
                            warn!(
                                "⚠️ Ignored IP \x27{}\x27 in FireHOL file \x27{}\x27 (category: {})",
                                addr, file_name, category
                            );
                            return Some(Vec::new());
                        }
                        return Some(vec![FireholIpTarget::ExactV4(net.addr().octets())]);
                    }

                    // Check if any ignored IPv4 falls within this CIDR
                    let mut matched_any = false;
                    let mut subnets = vec![net];
                    for ignored in ignore_ips {
                        if let IpAddr::V4(v4) = ignored {
                            if net.contains(v4) {
                                warn!(
                                    "⚠️ Ignored IP \x27{}\x27 excluded from CIDR \x27{}\x27 in FireHOL file \x27{}\x27 (category: {})",
                                    v4, token, file_name, category
                                );
                                matched_any = true;
                                let mut next = Vec::new();
                                for sub in subnets {
                                    next.extend(exclude_v4_from_cidr(sub, *v4));
                                }
                                subnets = next;
                            }
                        }
                    }

                    if !matched_any {
                        Some(vec![FireholIpTarget::CidrV4(
                            p as u32,
                            net.network().octets(),
                        )])
                    } else {
                        let targets = subnets
                            .into_iter()
                            .map(|sub| {
                                if sub.prefix_len() == 32 {
                                    FireholIpTarget::ExactV4(sub.addr().octets())
                                } else {
                                    FireholIpTarget::CidrV4(
                                        sub.prefix_len() as u32,
                                        sub.network().octets(),
                                    )
                                }
                            })
                            .collect();
                        Some(targets)
                    }
                }
                Ok(IpNet::V6(net)) => {
                    let p = net.prefix_len();
                    if p > 128 {
                        return None;
                    }
                    if p == 128 {
                        let addr = IpAddr::V6(net.addr());
                        if ignore_ips.contains(&addr) {
                            warn!(
                                "⚠️ Ignored IP \x27{}\x27 in FireHOL file \x27{}\x27 (category: {})",
                                addr, file_name, category
                            );
                            return Some(Vec::new());
                        }
                        return Some(vec![FireholIpTarget::ExactV6(net.addr().octets())]);
                    }

                    // Check if any ignored IPv6 falls within this CIDR
                    let mut matched_any = false;
                    let mut subnets = vec![net];
                    for ignored in ignore_ips {
                        if let IpAddr::V6(v6) = ignored {
                            if net.contains(v6) {
                                warn!(
                                    "⚠️ Ignored IP \x27{}\x27 excluded from CIDR \x27{}\x27 in FireHOL file \x27{}\x27 (category: {})",
                                    v6, token, file_name, category
                                );
                                matched_any = true;
                                let mut next = Vec::new();
                                for sub in subnets {
                                    next.extend(exclude_v6_from_cidr(sub, *v6));
                                }
                                subnets = next;
                            }
                        }
                    }

                    if !matched_any {
                        Some(vec![FireholIpTarget::CidrV6(
                            p as u32,
                            net.network().octets(),
                        )])
                    } else {
                        let targets = subnets
                            .into_iter()
                            .map(|sub| {
                                if sub.prefix_len() == 128 {
                                    FireholIpTarget::ExactV6(sub.addr().octets())
                                } else {
                                    FireholIpTarget::CidrV6(
                                        sub.prefix_len() as u32,
                                        sub.network().octets(),
                                    )
                                }
                            })
                            .collect();
                        Some(targets)
                    }
                }
                Err(_) => None,
            }
        } else {
            // Standalone IP notation
            match IpAddr::from_str(token) {
                Ok(addr) => {
                    if ignore_ips.contains(&addr) {
                        warn!(
                            "⚠️ Ignored IP \x27{}\x27 in FireHOL file \x27{}\x27 (category: {})",
                            addr, file_name, category
                        );
                        Some(Vec::new())
                    } else {
                        match addr {
                            IpAddr::V4(v4) => Some(vec![FireholIpTarget::ExactV4(v4.octets())]),
                            IpAddr::V6(v6) => Some(vec![FireholIpTarget::ExactV6(v6.octets())]),
                        }
                    }
                }
                Err(_) => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_parse_ip_or_cidr() {
        // Exact IPv4
        assert_eq!(
            FireholParser::parse_ip_or_cidr("192.0.2.1"),
            Some(FireholIpTarget::ExactV4([192, 0, 2, 1]))
        );

        // IPv4 /32 routed to ExactV4
        assert_eq!(
            FireholParser::parse_ip_or_cidr("192.0.2.1/32"),
            Some(FireholIpTarget::ExactV4([192, 0, 2, 1]))
        );

        // IPv4 CIDR
        assert_eq!(
            FireholParser::parse_ip_or_cidr("198.51.100.0/24"),
            Some(FireholIpTarget::CidrV4(24, [198, 51, 100, 0]))
        );

        // Exact IPv6
        let v6_addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            FireholParser::parse_ip_or_cidr("2001:db8::1"),
            Some(FireholIpTarget::ExactV6(v6_addr.octets()))
        );

        // IPv6 /128 routed to ExactV6
        assert_eq!(
            FireholParser::parse_ip_or_cidr("2001:db8::1/128"),
            Some(FireholIpTarget::ExactV6(v6_addr.octets()))
        );

        // IPv6 CIDR
        let v6_net: std::net::Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(
            FireholParser::parse_ip_or_cidr("2001:db8::/32"),
            Some(FireholIpTarget::CidrV6(32, v6_net.octets()))
        );

        // Invalid IPs
        assert_eq!(FireholParser::parse_ip_or_cidr("999.999.999.999"), None);
        assert_eq!(FireholParser::parse_ip_or_cidr("192.168.1.1/33"), None);
        assert_eq!(FireholParser::parse_ip_or_cidr("not_an_ip"), None);
    }

    #[test]
    fn test_parse_directory_valid() {
        let dir = tempdir().unwrap();

        let file1_path = dir.path().join("dshield.netset");
        let mut f1 = File::create(&file1_path).unwrap();
        writeln!(f1, "# Maintainer: SANS DShield").unwrap();
        writeln!(f1, "# Category: attacks").unwrap();
        writeln!(f1, "# Source File Date: Mon Sep 14 02:22:20 UTC 2026").unwrap();
        writeln!(f1, "192.0.2.1").unwrap();
        writeln!(f1, "198.51.100.0/24").unwrap();
        writeln!(f1, "203.0.113.5/32").unwrap(); // /32 becomes exact!

        let file2_path = dir.path().join("feodo.ipset");
        let mut f2 = File::create(&file2_path).unwrap();
        writeln!(f2, "# Maintainer: Feodo Tracker").unwrap();
        writeln!(f2, "# Category: botnet").unwrap();
        writeln!(f2, "192.0.2.100").unwrap();
        writeln!(f2, "2001:db8::1").unwrap();

        let dataset = FireholParser::parse_directory(dir.path(), None).unwrap();

        assert_eq!(dataset.total_files, 2);
        assert_eq!(dataset.total_entries(), 5);
        // Exact entries: 192.0.2.1, 203.0.113.5/32, 192.0.2.100, 2001:db8::1
        assert_eq!(dataset.exact_v4_count, 3);
        assert_eq!(dataset.exact_v6_count, 1);
        // LPM entries: 198.51.100.0/24
        assert_eq!(dataset.lpm_v4_count, 1);
        assert_eq!(dataset.lpm_v6_count, 0);

        assert_eq!(dataset.registry.total_blocklists(), 2);
    }

    #[test]
    fn test_entry_line_numbers_match_physical_lines() {
        let dir = tempdir().unwrap();

        // Physical line numbering must be preserved even in the presence of
        // comment / blank / inline-comment lines.
        let file_path = dir.path().join("linecheck.netset");
        let mut f = File::create(&file_path).unwrap();
        writeln!(f, "# Category: attacks").unwrap(); // line 1
        writeln!(f).unwrap(); // line 2 (blank)
        writeln!(f, "192.0.2.1").unwrap(); // line 3
        writeln!(f, "# Maintainer: x").unwrap(); // line 4
        writeln!(f, "192.0.2.2").unwrap(); // line 5
        writeln!(f, "192.0.2.3 # inline comment").unwrap(); // line 6
        writeln!(f, "198.51.100.0/24").unwrap(); // line 7

        let dataset = FireholParser::parse_directory(dir.path(), None).unwrap();

        let mut got: Vec<(String, u32)> = dataset
            .entries
            .iter()
            .map(|e| (e.target.to_string_repr(), e.line))
            .collect();
        got.sort();

        assert_eq!(
            got,
            vec![
                ("192.0.2.1".to_string(), 3),
                ("192.0.2.2".to_string(), 5),
                ("192.0.2.3".to_string(), 6),
                ("198.51.100.0/24".to_string(), 7),
            ]
        );
    }

    #[test]
    fn test_strict_parsing_aborts_on_invalid_line() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("malformed.ipset");
        let mut f = File::create(&file_path).unwrap();
        writeln!(f, "# Category: malware").unwrap();
        writeln!(f, "192.0.2.1").unwrap();
        writeln!(f, "corrupted_ip_address_line").unwrap();
        writeln!(f, "192.0.2.2").unwrap();

        let result = FireholParser::parse_directory(dir.path(), None);
        assert!(result.is_err());
        match result.unwrap_err() {
            FireholParseError::InvalidEntry { line, entry, .. } => {
                assert_eq!(line, 3);
                assert_eq!(entry, "corrupted_ip_address_line");
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_mid_file_category_change() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("mixed.ipset");
        let mut f = File::create(&file_path).unwrap();
        writeln!(f, "# Category: spam").unwrap();
        writeln!(f, "192.0.2.1").unwrap();
        writeln!(f, "# Category: botnet").unwrap();
        writeln!(f, "192.0.2.2").unwrap();

        let dataset = FireholParser::parse_directory(dir.path(), None).unwrap();
        assert_eq!(dataset.total_entries(), 2);

        // Find rules and verify different categories
        let r1 = dataset
            .registry
            .resolve_rule(dataset.entries[0].rule_id)
            .unwrap();
        let r2 = dataset
            .registry
            .resolve_rule(dataset.entries[1].rule_id)
            .unwrap();
        assert_eq!(r1.category, FireholCategory::Spam);
        assert_eq!(r2.category, FireholCategory::Botnet);
    }
    #[test]
    fn test_parse_ignore_ips_various_inputs() {
        // 1. Single IPv4
        let res = parse_ignore_ips("192.168.1.1");
        assert_eq!(res, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);

        // 2. Single IPv6
        let res = parse_ignore_ips("2001:db8::1");
        assert_eq!(res, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);

        // 3. Comma-separated list with mixed IPv4 and IPv6
        let res = parse_ignore_ips("192.168.1.1,10.0.0.1,2001:db8::1");
        assert_eq!(
            res,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ]
        );

        // 4. Spaces and trimming around tokens
        let res = parse_ignore_ips("   172.28.0.3  ,   10.10.10.10   ,    fd00::1   ");
        assert_eq!(
            res,
            vec![
                "172.28.0.3".parse::<IpAddr>().unwrap(),
                "10.10.10.10".parse::<IpAddr>().unwrap(),
                "fd00::1".parse::<IpAddr>().unwrap(),
            ]
        );

        // 5. Empty elements and trailing/leading commas
        let res = parse_ignore_ips(", , 172.28.0.3 ,,, 1.1.1.1, ");
        assert_eq!(
            res,
            vec![
                "172.28.0.3".parse::<IpAddr>().unwrap(),
                "1.1.1.1".parse::<IpAddr>().unwrap(),
            ]
        );

        // 6. Invalid tokens ignored gracefully
        let res = parse_ignore_ips("192.168.1.1, invalid_ip, 2001:db8::2");
        assert_eq!(
            res,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2001:db8::2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_exclude_v4_from_cidr_punchout() {
        // A. IP not in subnet -> unchanged
        let net: ipnet::Ipv4Net = "192.168.1.0/24".parse().unwrap();
        let unrelated: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
        let subs = exclude_v4_from_cidr(net, unrelated);
        assert_eq!(subs, vec![net]);

        // B. /32 containing target IP -> empty
        let net32: ipnet::Ipv4Net = "192.168.1.5/32".parse().unwrap();
        let target: std::net::Ipv4Addr = "192.168.1.5".parse().unwrap();
        let subs = exclude_v4_from_cidr(net32, target);
        assert!(subs.is_empty());

        // C. /30 network containing target IP
        // 192.168.1.0/30 contains .0, .1, .2, .3.
        // Punching out .2 must leave .0, .1 (192.168.1.0/31) and .3 (192.168.1.3/32)
        let net30: ipnet::Ipv4Net = "192.168.1.0/30".parse().unwrap();
        let target: std::net::Ipv4Addr = "192.168.1.2".parse().unwrap();
        let subs = exclude_v4_from_cidr(net30, target);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], "192.168.1.0/31".parse::<ipnet::Ipv4Net>().unwrap());
        assert_eq!(subs[1], "192.168.1.3/32".parse::<ipnet::Ipv4Net>().unwrap());

        for sub in &subs {
            assert!(!sub.contains(&target));
        }

        // D. /12 network containing Prometheus IP 172.28.0.3
        let net12: ipnet::Ipv4Net = "172.16.0.0/12".parse().unwrap();
        let target_prom: std::net::Ipv4Addr = "172.28.0.3".parse().unwrap();
        let subs12 = exclude_v4_from_cidr(net12, target_prom);
        assert_eq!(subs12.len(), 20);
        for sub in &subs12 {
            assert!(!sub.contains(&target_prom));
        }
    }

    #[test]
    fn test_exclude_v6_from_cidr_punchout() {
        // A. IP not in subnet -> unchanged
        let net: ipnet::Ipv6Net = "2001:db8::/32".parse().unwrap();
        let unrelated: std::net::Ipv6Addr = "2001:cafe::1".parse().unwrap();
        let subs = exclude_v6_from_cidr(net, unrelated);
        assert_eq!(subs, vec![net]);

        // B. /128 containing target IP -> empty
        let net128: ipnet::Ipv6Net = "2001:db8::5/128".parse().unwrap();
        let target: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
        let subs = exclude_v6_from_cidr(net128, target);
        assert!(subs.is_empty());

        // C. /120 network containing target IP
        let net120: ipnet::Ipv6Net = "2001:db8::/120".parse().unwrap();
        let target: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
        let subs120 = exclude_v6_from_cidr(net120, target);
        assert_eq!(subs120.len(), 8);
        for sub in &subs120 {
            assert!(!sub.contains(&target));
        }
    }

    #[test]
    fn test_parse_ip_or_cidr_with_ignore_exact_and_cidr() {
        let ignore_v4 = "172.28.0.3".parse::<IpAddr>().unwrap();
        let ignore_v6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        let ignore_list = vec![ignore_v4, ignore_v6];

        // 1. Exact IPv4 matching ignore list -> returns empty
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "172.28.0.3",
            &ignore_list,
            "test.ipset",
            FireholCategory::Attacks,
        );
        assert_eq!(res, Some(Vec::new()));

        // 2. Exact IPv4 /32 matching ignore list -> returns empty
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "172.28.0.3/32",
            &ignore_list,
            "test.netset",
            FireholCategory::Attacks,
        );
        assert_eq!(res, Some(Vec::new()));

        // 3. Exact IPv6 matching ignore list -> returns empty
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "2001:db8::1",
            &ignore_list,
            "test.ipset",
            FireholCategory::Malware,
        );
        assert_eq!(res, Some(Vec::new()));

        // 4. Exact IPv6 /128 matching ignore list -> returns empty
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "2001:db8::1/128",
            &ignore_list,
            "test.netset",
            FireholCategory::Malware,
        );
        assert_eq!(res, Some(Vec::new()));

        // 5. Non-ignored exact IPv4 -> kept
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "192.168.1.1",
            &ignore_list,
            "test.ipset",
            FireholCategory::Attacks,
        );
        assert_eq!(res, Some(vec![FireholIpTarget::ExactV4([192, 168, 1, 1])]));

        // 6. CIDR containing ignored IPv4 -> decomposed
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "172.28.0.0/30",
            &ignore_list,
            "test.netset",
            FireholCategory::Botnet,
        );
        let targets = res.expect("Should parse");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], FireholIpTarget::CidrV4(31, [172, 28, 0, 0]));
        assert_eq!(targets[1], FireholIpTarget::ExactV4([172, 28, 0, 2]));

        // 7. CIDR containing ignored IPv6 -> decomposed
        let res = FireholParser::parse_ip_or_cidr_with_ignore(
            "2001:db8::/126",
            &ignore_list,
            "test.netset",
            FireholCategory::Malware,
        );
        let targets_v6 = res.expect("Should parse");
        assert_eq!(targets_v6.len(), 2);
    }

    #[test]
    fn test_parse_directory_with_ignore_prometheus_e2e() {
        let dir = tempdir().unwrap();

        let file1_path = dir.path().join("firehol_level1.netset");
        let mut f1 = File::create(&file1_path).unwrap();
        writeln!(f1, "# Maintainer: FireHOL").unwrap();
        writeln!(f1, "# Category: attacks").unwrap();
        writeln!(f1, "172.16.0.0/12").unwrap();
        writeln!(f1, "192.0.2.1").unwrap();

        let file2_path = dir.path().join("bogon.ipset");
        let mut f2 = File::create(&file2_path).unwrap();
        writeln!(f2, "# Maintainer: Bogons").unwrap();
        writeln!(f2, "# Category: other").unwrap();
        writeln!(f2, "172.28.0.3").unwrap();
        writeln!(f2, "10.0.0.1").unwrap();

        let ignore_ips = parse_ignore_ips(" 172.28.0.3 ");
        let dataset =
            FireholParser::parse_directory_with_ignore(dir.path(), &ignore_ips, None).unwrap();

        let prom_v4 = [172, 28, 0, 3];
        for entry in &dataset.entries {
            match entry.target {
                FireholIpTarget::ExactV4(octets) => {
                    assert_ne!(octets, prom_v4, "Prometheus IP must NOT be in exact map!");
                }
                FireholIpTarget::CidrV4(prefix, octets) => {
                    let net = ipnet::Ipv4Net::new(std::net::Ipv4Addr::from(octets), prefix as u8)
                        .unwrap();
                    assert!(
                        !net.contains(&std::net::Ipv4Addr::from(prom_v4)),
                        "Prometheus IP must NOT be in any CIDR subnet: {}/{}",
                        net.network(),
                        prefix
                    );
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::firehol::sync::FireholSyncManager;
    use std::io::Write;

    #[test]
    fn fast_address_parser_matches_reference_grammar() {
        fn check(token: &str) {
            let reference =
                FireholParser::parse_ip_or_cidr_with_ignore(token, &[], "", FireholCategory::Other)
                    .and_then(|v| v.into_iter().next());
            assert_eq!(
                FireholParser::parse_ip_or_cidr(token),
                reference,
                "{token:?}"
            );
        }
        for octet in 0..=255 {
            check(&format!("{octet}.2.3.4"));
            for prefix in 0..=33 {
                check(&format!("{octet}.2.255.129/{prefix}"));
                check(&format!("{octet:03}.002.3.4/{prefix:02}"));
            }
        }
        for prefix in 0..=129 {
            for ip in [
                "2001:db8::abcd",
                "::",
                "::ffff:192.0.2.1",
                "::ffff:192.000.002.001",
            ] {
                check(&format!("{ip}/{prefix}"));
                check(&format!("{ip}/{prefix:03}"));
                check(ip);
            }
        }
        for token in [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.2.3",
            "1234.1.2.3",
            "01.2.3.4",
            "1.2.3.4/",
            "1.2.3.4/+1",
            "1.2.3.4/001",
            "1.2.3.4/33",
            "1.2.3.4/1/2",
            " 1.2.3.4",
            "1.2.3.4 ",
            "1.2.3.4/1\n",
            "１.2.3.4",
            "::1%eth0",
            "2001:::1",
            "a.b.c.d",
        ] {
            check(token);
        }
    }

    #[test]
    fn chunk_reader_preserves_long_lines_utf8_crlf_and_final_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boundary.ipset");
        let prefix = format!(
            "#{}\n# Category: malware\r\n192.0.2.1\r\n\n2001:db8::1",
            "é".repeat(1024 * 1024)
        );
        std::fs::write(&path, &prefix).unwrap();
        let mut lines = Vec::new();
        let (bytes, _, _) = visit_file_lines(&path, |line, number| {
            lines.push((number, line.to_string()));
            Ok(())
        })
            .unwrap();
        assert_eq!(bytes as usize, prefix.len());
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[2], (3, "192.0.2.1\r".into()));
        assert_eq!(lines[4], (5, "2001:db8::1".into()));
        let data = FireholParser::parse_directory(dir.path(), None).unwrap();
        assert_eq!(
            data.entries.iter().map(|e| e.line).collect::<Vec<_>>(),
            [3, 5]
        );
        std::fs::write(&path, b"192.0.2.1\n\xff").unwrap();
        assert!(matches!(
            FireholParser::parse_directory(dir.path(), None),
            Err(FireholParseError::Io { .. })
        ));
    }

    #[test]
    fn spooled_import_matches_memory_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = File::create(dir.path().join("feed.netset")).unwrap();
        writeln!(file, "# Category: malware").unwrap();
        for i in 0..(WORKER_BATCH_SIZE * 2 + 7) {
            writeln!(
                file,
                "10.{}.{}.{}/32",
                (i >> 16) & 255,
                (i >> 8) & 255,
                i & 255
            )
                .unwrap();
        }
        writeln!(
            file,
            "# Category: abuse\n10.0.0.1\n2001:db8::/126\n192.0.2.0/24"
        )
            .unwrap();
        drop(file);
        let cache = Arc::new(CacheRocksDb::open(dir.path().join("cache")).unwrap());
        let ignored = ["192.0.2.5".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let memory =
            FireholParser::parse_directory_with_ignore(dir.path(), &ignored, None).unwrap();
        let disk = FireholParser::parse_directory_spooled(dir.path(), &ignored, None, Some(cache))
            .unwrap();
        assert!(disk.entries.is_empty());
        assert!(disk.stored_entries.is_some());
        assert_eq!(disk.total_entries(), memory.total_entries());
        assert_eq!(
            disk.registry.category_counts,
            memory.registry.category_counts
        );
        let (expected, expected_report) = FireholSyncManager::prepare_rules(&memory);
        let (actual, actual_report) = FireholSyncManager::try_prepare_rules(&disk).unwrap();
        assert_eq!(actual_report, expected_report);
        assert_eq!(actual.exact_v4, expected.exact_v4);
        assert_eq!(actual.exact_v6, expected.exact_v6);
        assert_eq!(actual.lpm_v4, expected.lpm_v4);
        assert_eq!(actual.lpm_v6, expected.lpm_v6);
        for ip in [[10, 0, 0, 1], [192, 0, 2, 6], [192, 0, 2, 5]] {
            assert_eq!(
                disk.registry.lookup_ip(4, &ip),
                memory.registry.lookup_ip(4, &ip)
            );
        }
        assert_eq!(
            disk.registry.lookup_ip(
                6,
                &"2001:db8::2"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            ),
            memory.registry.lookup_ip(
                6,
                &"2001:db8::2"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            )
        );
        disk.stored_entries
            .as_ref()
            .unwrap()
            .put(
                crate::cache_rocksdb::cf::ENTRIES,
                &(u64::MAX - 1).to_be_bytes(),
                b"corrupt",
            )
            .unwrap();
        assert!(FireholSyncManager::try_prepare_rules(&disk).is_err());
        disk.stored_entries
            .as_ref()
            .unwrap()
            .clear_entries()
            .unwrap();
        assert!(disk
            .stored_entries
            .as_ref()
            .unwrap()
            .iter(crate::cache_rocksdb::cf::ENTRIES)
            .unwrap()
            .next()
            .is_none());
        assert!(!disk.registry.lookup_ip(4, &[10, 0, 0, 1]).is_empty());
    }

    #[test]
    fn cache_generations_preserve_active_readers_and_reject_partial_imports() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");
        let cache = Arc::new(CacheRocksDb::open(&root).unwrap());
        let feed = dir.path().join("feed.ipset");
        std::fs::write(&feed, "# Category: malware\n192.0.2.1\n").unwrap();
        let old =
            FireholParser::parse_directory_spooled(dir.path(), &[], None, Some(cache.clone()))
                .unwrap();
        std::fs::write(&feed, "# Category: abuse\n192.0.2.2\n").unwrap();
        let new =
            FireholParser::parse_directory_spooled(dir.path(), &[], None, Some(cache.clone()))
                .unwrap();
        assert!(new.registry.lookup_ip(4, &[192, 0, 2, 1]).is_empty());
        assert!(!old.registry.lookup_ip(4, &[192, 0, 2, 1]).is_empty());
        std::fs::write(
            &feed,
            format!("{}invalid\n", "192.0.2.3\n".repeat(WORKER_BATCH_SIZE + 1)),
        )
            .unwrap();
        assert!(
            FireholParser::parse_directory_spooled(dir.path(), &[], None, Some(cache)).is_err()
        );
        assert!(!new.registry.lookup_ip(4, &[192, 0, 2, 2]).is_empty());
        drop(old);
        drop(new);
        assert!(!std::fs::read_dir(root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("import-")));
    }
}

#[cfg(test)]
mod memory_profile {
    use super::*;
    #[test]
    #[ignore = "manual memory/performance measurement"]
    fn import_memory_profile() {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .try_init();
        let dir = std::env::var("FIREHOL_PROFILE_DIR").expect("set FIREHOL_PROFILE_DIR");
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(CacheRocksDb::open(temp.path().join("cache")).unwrap());
        let data = FireholParser::parse_directory_spooled(&dir, &[], None, Some(cache)).unwrap();
        let (rules, report) = crate::firehol::sync::FireholSyncManager::prepare_rules(&data);
        eprintln!(
            "entries={} prepared={}",
            data.total_entries(),
            report.total_rules()
        );
        std::hint::black_box(rules);
    }
}
