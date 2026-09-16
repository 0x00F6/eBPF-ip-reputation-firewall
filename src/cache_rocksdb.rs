//! A self-contained on-disk cache wrapper (RocksDB) for the heavy rule metadata
//! that does not need to stay resident in RAM.
//!
//! The firewall keeps only the data required for the critical / very frequent
//! code paths in memory (the dense per-rule lookup vector). Everything verbose —
//! per-file metadata (`category`, `rule`, `protocol`, IP target, `fileName`,
//! maintainer URLs, update frequency, …) and the per-target file/category
//! contexts — is persisted here, **compressed with LZ4 by RocksDB**, serialized
//! with **Cap'n Proto**, and read back lazily on the (infrequent) logging path.
//!
//! [`CacheRocksDb`] is responsible for:
//! * low-level reads/writes and batched writes into RocksDB;
//! * Cap'n Proto (de)serialization of [`FireholMetadata`] / [`RuleBlockContext`];
//! * LZ4 compression (configured once per column family);
//! * compact, fixed-width key encoding on the stack for all target kinds;
//! * zero-copy / low-allocation reads (`get_pinned` pins the value in the block
//!   cache and avoids a copy of the raw value; rkyv parses the message zero-copy
//!   from the pinned slice).

use crate::error::{FirewallError, Result};
use crate::firehol::metadata::{
    ArchivedFireholMetadata, ArchivedRuleBlockContext, FireholMetadata, RuleBlockContext,
};
use rkyv::util::AlignedVec;
use rocksdb::{
    BlockBasedOptions, ColumnFamily, ColumnFamilyDescriptor, DBCompressionType, DBPinnableSlice,
    IteratorMode, Options, ReadOptions, WriteBatch, WriteOptions, DB,
};
use std::path::{Path, PathBuf};
/// Column families used by the firewall cache.
pub mod cf {
    /// Import sequence (u64 BE) -> fixed-width FireHOL entry.
    pub const CONTRIBUTIONS: &str = "contributions";
    pub const ENTRIES: &str = "entries";
    /// Metadata ID (u32 BE) -> verbose Cap'n Proto metadata.
    pub const METADATA: &str = "meta";
    /// Per-target file/category context. Keyed by the IP/CIDR target.
    pub const RULE_CONTEXT: &str = "rule_ctx";
}

/// Key encoding tags (single leading byte) so the four target kinds never collide.
mod tag {
    pub const V4_EXACT: u8 = 0x01;
    pub const V6_EXACT: u8 = 0x02;
    pub const V4_LPM: u8 = 0x03;
    pub const V6_LPM: u8 = 0x04;
}

/// Creates a compact big-endian key for a metadata id.
///
/// Inlined into the caller (stack, zero heap allocation).
#[inline]
pub fn metadata_key(id: u32) -> [u8; 4] {
    id.to_be_bytes()
}

/// Returns a compact key for an exact IPv4 context.
#[inline]
pub fn ctx_key_v4_exact(octets: &[u8; 4]) -> [u8; 5] {
    let mut k = [0u8; 5];
    k[0] = tag::V4_EXACT;
    k[1..].copy_from_slice(octets);
    k
}

/// Returns a compact key for an exact IPv6 context.
pub fn ctx_key_v6_exact(octets: &[u8; 16]) -> [u8; 17] {
    let mut k = [0u8; 17];
    k[0] = tag::V6_EXACT;
    k[1..].copy_from_slice(octets);
    k
}

/// Returns a compact key for an IPv4 CIDR context.
pub fn ctx_key_v4_lpm(prefix: u8, net: &[u8; 4]) -> [u8; 6] {
    let mut k = [0u8; 6];
    k[0] = tag::V4_LPM;
    k[1] = prefix;
    k[2..].copy_from_slice(net);
    k
}

/// Returns a compact key for an IPv6 CIDR context.
pub fn ctx_key_v6_lpm(prefix: u8, net: &[u8; 16]) -> [u8; 18] {
    let mut k = [0u8; 18];
    k[0] = tag::V6_LPM;
    k[1] = prefix;
    k[2..].copy_from_slice(net);
    k
}

/// Encapsulates a RocksDB instance configured for a low RAM footprint (LZ4
/// compression + a bounded block cache) and exposes reads, writes, deletes,
/// batched writes, and Cap'n Proto (de)serialization of the heavy payloads.
#[derive(Debug)]
pub struct CacheRocksDb {
    db: DB,
    // Fields drop in declaration order: close RocksDB before removing temporary files.
    temporary: Option<TemporaryCache>,
}

#[derive(Debug)]
struct TemporaryCache(PathBuf);
impl Drop for TemporaryCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl CacheRocksDb {
    /// Isolated import generation; remains alive while its registry or dataset is in use.
    pub fn import_generation(&self) -> Result<Self> {
        let path = self
            .db
            .path()
            .join(format!("import-{}", uuid::Uuid::new_v4()));
        let mut cache = Self::open(&path)?;
        cache.temporary = Some(TemporaryCache(path));
        Ok(cache)
    }

    /// Add a raw value to a batch without allocating another owned value.
    pub fn batch_put(
        &self,
        batch: &mut WriteBatch,
        name: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        batch.put_cf(self.cf(name)?, key, value);
        Ok(())
    }

    /// Discard the temporary entry spool after map preparation.
    pub fn clear_entries(&self) -> Result<()> {
        self.db
            .delete_range_cf(self.cf(cf::ENTRIES)?, [0u8; 8], [255u8; 8])
            .map_err(|e| FirewallError::Cache(e.to_string()))
    }

    /// Open (or create) the RocksDB at `path` with LZ4 compression on every CF.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let base_opts = Self::base_options();

        // Shared block cache for all column families. 128 MiB gives hot point-lookups
        // enough room without letting RocksDB consume an unbounded amount of RAM.
        let block_cache = rocksdb::Cache::new_lru_cache(128 * 1024 * 1024);
        let meta_desc = ColumnFamilyDescriptor::new(cf::METADATA, Self::cf_options(&block_cache));
        let ctx_desc =
            ColumnFamilyDescriptor::new(cf::RULE_CONTEXT, Self::cf_options(&block_cache));

        let db = DB::open_cf_descriptors(
            &base_opts,
            path,
            [
                meta_desc,
                ctx_desc,
                ColumnFamilyDescriptor::new(cf::ENTRIES, Self::cf_options(&block_cache)),
                ColumnFamilyDescriptor::new(cf::CONTRIBUTIONS, Self::cf_options(&block_cache)),
            ],
        )
        .map_err(|e| FirewallError::Cache(format!("RocksDB open failed: {e}")))?;

        Ok(Self {
            db,
            temporary: None,
        })
    }

    /// Open a RocksDB instance with no column-family handles (single default CF).
    pub fn open_single(path: impl AsRef<Path>) -> Result<Self> {
        let db = DB::open(&Self::base_options(), path)
            .map_err(|e| FirewallError::Cache(format!("RocksDB open failed: {e}")))?;
        Ok(Self {
            db,
            temporary: None,
        })
    }

    fn base_options() -> Options {
        const MIB: usize = 1024 * 1024;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Scale RocksDB background work with the machine while keeping an upper bound
        // so compactions do not steal every CPU from the parser / firewall threads.
        let cpu_count = std::thread::available_parallelism().map_or(4, |n| n.get());
        let background_jobs = cpu_count.clamp(4, 16) as i32;
        let subcompactions = (cpu_count / 2).clamp(2, 8) as u32;
        opts.increase_parallelism(background_jobs);
        opts.set_max_background_jobs(background_jobs);
        opts.set_max_subcompactions(subcompactions);

        // Shared memtable budget across all column families. Individual CFs may use
        // several 64 MiB memtables, but RocksDB will keep the aggregate bounded.
        opts.set_db_write_buffer_size(512 * MIB);

        // Allow a reasonably large WAL during sustained imports and smooth physical
        // writes instead of generating large I/O bursts.
        opts.set_max_total_wal_size((512 * MIB) as u64);
        opts.set_bytes_per_sync((4 * MIB) as u64);
        opts.set_wal_bytes_per_sync((4 * MIB) as u64);
        opts.set_use_fsync(false);

        // Improve throughput when writes queue up from the bulk importer.
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);
        opts.set_enable_pipelined_write(true);

        // Larger sequential reads make Level compactions more efficient on SSD/NVMe.
        opts.set_compaction_readahead_size(4 * MIB);

        // Keep enough SST descriptors open and shard the table cache to reduce lock
        // contention during concurrent point lookups / compactions.
        opts.set_max_open_files(1024);
        opts.set_table_cache_num_shard_bits(6);

        opts.set_keep_log_file_num(2);
        opts
    }

    fn cf_options(cache: &rocksdb::Cache) -> Options {
        const KIB: usize = 1024;
        const MIB: usize = 1024 * KIB;
        const GIB: usize = 1024 * MIB;

        let mut opts = Options::default();

        // LZ4 is a good fit for this cache: very fast compression/decompression with
        // enough space reduction to lower disk I/O during imports and point lookups.
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(DBCompressionType::Lz4);

        // Level compaction gives predictable point-lookup performance after the large
        // sequential FireHOL import has completed.
        opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
        opts.set_level_compaction_dynamic_level_bytes(true);

        // Each CF may accumulate several memtables so a flush can run while ingestion
        // continues. The 512 MiB DB-wide budget in base_options() remains the global cap.
        opts.set_write_buffer_size(64 * MIB);
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);

        // Larger SST files reduce file-count, metadata overhead and compaction churn on
        // a database populated by large bulk imports.
        opts.set_target_file_size_base((128 * MIB) as u64);
        opts.set_max_bytes_for_level_base(GIB as u64);
        opts.set_max_compaction_bytes((2 * GIB) as u64);

        // Give L0 enough headroom for bursts from WriteBatch before throttling writers.
        // Compaction starts early enough to keep point-lookups efficient afterwards.
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(20);
        opts.set_level_zero_stop_writes_trigger(36);

        // A small in-memory whole-key Bloom filter avoids unnecessary memtable probes
        // for the point-lookups used by metadata/rule-context access.
        opts.set_memtable_prefix_bloom_ratio(0.05);
        opts.set_memtable_whole_key_filtering(true);

        let mut table = BlockBasedOptions::default();
        table.set_block_cache(cache);

        // 16 KiB data blocks reduce index overhead and work well for compressed values
        // while keeping point reads reasonably fine-grained.
        table.set_block_size(16 * KIB);

        // Full Bloom filters are well suited to exact lookups. Ten bits/key gives a low
        // false-positive rate without excessive memory overhead.
        table.set_bloom_filter(10.0, false);
        table.set_whole_key_filtering(true);
        table.set_optimize_filters_for_memory(true);

        // Put indexes and filters in the shared cache and keep L0 metadata pinned: L0 is
        // where lookup amplification is highest while imports/flushes are in progress.
        table.set_cache_index_and_filter_blocks(true);
        table.set_cache_index_and_filter_blocks_with_high_priority(true);
        table.set_pin_l0_filter_and_index_blocks_in_cache(true);

        opts.set_block_based_table_factory(&table);
        opts
    }

    /// Resolve a column family handle by name.
    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| FirewallError::Cache(format!("column family '{name}' not found")))
    }

    /// Read a raw value pinned to the block cache (zero-copy of the stored bytes).
    pub fn get_pinned(&self, cf_name: &str, key: &[u8]) -> Result<Option<DBPinnableSlice<'_>>> {
        let cf = self.cf(cf_name)?;
        let ro = ReadOptions::default();
        self.db
            .get_pinned_cf_opt(cf, key, &ro)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))
    }

    /// Read a raw value into an owned `Vec<u8>`.
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        self.db
            .get_cf(cf, key)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))
    }

    /// Write a single raw key/value pair.
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db
            .put_cf(cf, key, value)
            .map_err(|e| FirewallError::Cache(format!("RocksDB put failed: {e}")))
    }

    /// Delete a single key.
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db
            .delete_cf(cf, key)
            .map_err(|e| FirewallError::Cache(format!("RocksDB delete failed: {e}")))
    }

    /// Create a fresh empty [`WriteBatch`] for batched writes.
    pub fn batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Write a batch to RocksDB.
    pub fn apply_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db
            .write(batch)
            .map_err(|e| FirewallError::Cache(format!("RocksDB batch write failed: {e}")))
    }

    /// Iterate a column family in ascending key order.
    pub fn iter(&self, cf_name: &str) -> Result<rocksdb::DBIterator<'_>> {
        let cf = self.cf(cf_name)?;
        let mut options = ReadOptions::default();
        options.fill_cache(false); // Sequential spool scans must not evict lookup blocks.
        let iter = self.db.iterator_cf_opt(cf, options, IteratorMode::Start);
        Ok(iter)
    }

    /// Visit borrowed RocksDB values. The slice is valid only until the cursor advances.
    /// Unlike DBIterator, this does not allocate owned key/value buffers per row.
    pub(crate) fn visit_values(
        &self,
        cf_name: &str,
        mut visitor: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut options = ReadOptions::default();
        options.fill_cache(false);
        let mut cursor = self.db.raw_iterator_cf_opt(self.cf(cf_name)?, options);
        cursor.seek_to_first();
        while cursor.valid() {
            visitor(cursor.value().expect("valid RocksDB iterator"))?;
            cursor.next();
        }
        // Invalid can mean either EOF or an I/O error; never silently accept a partial scan.
        cursor
            .status()
            .map_err(|e| FirewallError::Cache(format!("RocksDB scan failed: {e}")))
    }

    pub(crate) fn visit_pairs(
        &self,
        name: &str,
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut options = ReadOptions::default();
        options.fill_cache(false);
        let mut cursor = self.db.raw_iterator_cf_opt(self.cf(name)?, options);
        cursor.seek_to_first();
        while cursor.valid() {
            visitor(cursor.key().unwrap(), cursor.value().unwrap())?;
            cursor.next();
        }
        cursor
            .status()
            .map_err(|e| FirewallError::Cache(format!("RocksDB scan failed: {e}")))
    }

    pub(crate) fn clear_contributions(&self) -> Result<()> {
        self.db
            .delete_range_cf(self.cf(cf::CONTRIBUTIONS)?, [0u8; 26], [255u8; 26])
            .map_err(|e| FirewallError::Cache(e.to_string()))
    }

    /// Wait for the import's memtables to reach SST files (included in write timing).
    pub(crate) fn flush_import(&self) -> Result<()> {
        let mut options = rocksdb::FlushOptions::default();
        options.set_wait(true);
        self.db
            .flush_cfs_opt(
                &[
                    self.cf(cf::ENTRIES)?,
                    self.cf(cf::CONTRIBUTIONS)?,
                    self.cf(cf::RULE_CONTEXT)?,
                    self.cf(cf::METADATA)?,
                ],
                &options,
            )
            .map_err(|e| FirewallError::Cache(e.to_string()))
    }

    /// Flush pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| FirewallError::Cache(format!("RocksDB flush failed: {e}")))
    }

    /// Number of live keys in the given column family.
    pub fn estimate_keys(&self, cf_name: &str) -> Result<u64> {
        let cf = self.cf(cf_name)?;
        let prop = self
            .db
            .property_int_value_cf(cf, "rocksdb.estimate-num-keys")
            .map_err(|e| FirewallError::Cache(format!("RocksDB property failed: {e}")))?
            .unwrap_or(0);
        Ok(prop)
    }

    // ---------------------------------------------------------------------
    // rkyv serialization (zero-copy / low-allocation wire format)
    // ---------------------------------------------------------------------

    /// Serialize `FireholMetadata` into an aligned byte buffer using `rkyv`.
    pub fn serialize_metadata_into(&self, m: &FireholMetadata, out: &mut AlignedVec) -> Result<()> {
        out.clear();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(m, out)
            .map_err(|e| FirewallError::Cache(format!("rkyv serialize metadata: {e}")))?;
        Ok(())
    }

    /// Serialize `FireholMetadata` into a newly allocated [`AlignedVec`].
    pub fn serialize_metadata(&self, m: &FireholMetadata) -> Result<AlignedVec> {
        rkyv::to_bytes::<rkyv::rancor::Error>(m)
            .map_err(|e| FirewallError::Cache(format!("rkyv serialize metadata: {e}")))
    }

    /// Serialize [`FireholMetadata`] and write it into the METADATA CF.
    pub fn put_metadata(&self, m: &FireholMetadata) -> Result<()> {
        let mut buf = AlignedVec::with_capacity(256);
        self.serialize_metadata_into(m, &mut buf)?;
        self.put(cf::METADATA, &metadata_key(m.id), &buf)
    }

    /// Zero-copy access to archived metadata from raw bytes with bytecheck validation.
    pub fn access_metadata(bytes: &[u8]) -> Result<&ArchivedFireholMetadata> {
        rkyv::access::<ArchivedFireholMetadata, rkyv::rancor::Error>(bytes)
            .map_err(|e| FirewallError::Cache(format!("rkyv access metadata: {e}")))
    }

    /// Zero-copy unchecked access to archived metadata.
    ///
    /// # Safety
    /// The bytes must represent a valid archived [`FireholMetadata`].
    pub unsafe fn access_metadata_unchecked(bytes: &[u8]) -> &ArchivedFireholMetadata {
        unsafe { rkyv::access_unchecked::<ArchivedFireholMetadata>(bytes) }
    }

    /// Deserialize a raw rkyv blob into owned [`FireholMetadata`].
    pub fn deserialize_metadata(&self, bytes: &[u8]) -> Result<FireholMetadata> {
        let archived = Self::access_metadata(bytes)?;
        rkyv::deserialize::<FireholMetadata, rkyv::rancor::Error>(archived)
            .map_err(|e| FirewallError::Cache(format!("rkyv deserialize metadata: {e}")))
    }

    /// Read + deserialize metadata by id from RocksDB block cache.
    pub fn get_metadata(&self, id: u32) -> Result<Option<FireholMetadata>> {
        let key = metadata_key(id);
        let cf = self.cf(cf::METADATA)?;
        let ro = ReadOptions::default();
        let pinned = self
            .db
            .get_pinned_cf_opt(cf, key, &ro)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))?;
        match pinned {
            None => Ok(None),
            Some(p) => self.deserialize_metadata(p.as_ref()).map(Some),
        }
    }

    /// Zero-copy inspect metadata directly from RocksDB pinned block cache slice.
    pub fn with_metadata<R>(
        &self,
        id: u32,
        f: impl FnOnce(&ArchivedFireholMetadata) -> R,
    ) -> Result<Option<R>> {
        let key = metadata_key(id);
        let cf = self.cf(cf::METADATA)?;
        let ro = ReadOptions::default();
        let pinned = self
            .db
            .get_pinned_cf_opt(cf, key, &ro)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))?;
        match pinned {
            None => Ok(None),
            Some(p) => {
                let archived = Self::access_metadata(p.as_ref())?;
                Ok(Some(f(archived)))
            }
        }
    }

    /// Serialize [`RuleBlockContext`] into an aligned byte buffer using `rkyv`.
    pub fn serialize_rule_context_into(
        &self,
        ctx: &RuleBlockContext,
        out: &mut AlignedVec,
    ) -> Result<()> {
        out.clear();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(ctx, out)
            .map_err(|e| FirewallError::Cache(format!("rkyv serialize rule context: {e}")))?;
        Ok(())
    }

    /// Serialize [`RuleBlockContext`] into a newly allocated [`AlignedVec`].
    pub fn serialize_rule_context(&self, ctx: &RuleBlockContext) -> Result<AlignedVec> {
        rkyv::to_bytes::<rkyv::rancor::Error>(ctx)
            .map_err(|e| FirewallError::Cache(format!("rkyv serialize rule context: {e}")))
    }

    /// Serialize [`RuleBlockContext`] and write it into the RULE_CONTEXT CF under `key`.
    pub fn put_rule_context(&self, key: &[u8], ctx: &RuleBlockContext) -> Result<()> {
        let mut buf = AlignedVec::with_capacity(128);
        self.serialize_rule_context_into(ctx, &mut buf)?;
        self.put(cf::RULE_CONTEXT, key, &buf)
    }

    /// Zero-copy access to archived rule context from raw bytes with bytecheck validation.
    pub fn access_rule_context(bytes: &[u8]) -> Result<&ArchivedRuleBlockContext> {
        rkyv::access::<ArchivedRuleBlockContext, rkyv::rancor::Error>(bytes)
            .map_err(|e| FirewallError::Cache(format!("rkyv access rule context: {e}")))
    }

    /// Zero-copy unchecked access to archived rule context.
    ///
    /// # Safety
    /// The bytes must represent a valid archived [`RuleBlockContext`].
    pub unsafe fn access_rule_context_unchecked(bytes: &[u8]) -> &ArchivedRuleBlockContext {
        unsafe { rkyv::access_unchecked::<ArchivedRuleBlockContext>(bytes) }
    }

    /// Deserialize a raw rkyv blob into owned [`RuleBlockContext`].
    pub fn deserialize_rule_context(&self, bytes: &[u8]) -> Result<RuleBlockContext> {
        let archived = Self::access_rule_context(bytes)?;
        rkyv::deserialize::<RuleBlockContext, rkyv::rancor::Error>(archived)
            .map_err(|e| FirewallError::Cache(format!("rkyv deserialize rule context: {e}")))
    }

    /// Read + deserialize a rule context by key from RocksDB.
    pub fn get_rule_context(&self, key: &[u8]) -> Result<Option<RuleBlockContext>> {
        let cf = self.cf(cf::RULE_CONTEXT)?;
        let ro = ReadOptions::default();
        let pinned = self
            .db
            .get_pinned_cf_opt(cf, key, &ro)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))?;
        match pinned {
            None => Ok(None),
            Some(p) => self.deserialize_rule_context(p.as_ref()).map(Some),
        }
    }

    /// Zero-copy inspect rule context directly from RocksDB pinned block cache slice.
    pub fn with_rule_context<R>(
        &self,
        key: &[u8],
        f: impl FnOnce(&ArchivedRuleBlockContext) -> R,
    ) -> Result<Option<R>> {
        let cf = self.cf(cf::RULE_CONTEXT)?;
        let ro = ReadOptions::default();
        let pinned = self
            .db
            .get_pinned_cf_opt(cf, key, &ro)
            .map_err(|e| FirewallError::Cache(format!("RocksDB get failed: {e}")))?;
        match pinned {
            None => Ok(None),
            Some(p) => {
                let archived = Self::access_rule_context(p.as_ref())?;
                Ok(Some(f(archived)))
            }
        }
    }
}

/// One writer owns the entire bulk budget; workers never allocate giant batches.
/// WAL is disabled only for disposable import generations, which are never recovered.
/// The active registry is published only after the import has fully succeeded.
pub(crate) struct BulkWriter<'a> {
    cache: &'a CacheRocksDb,
    batch: WriteBatch,
    limit: usize,
    pub write_seconds: f64,
    pub written_bytes: u64,
}

pub(crate) const MAX_IMPORT_BATCH_BYTES: usize = 300 * 1024 * 1024;

impl<'a> BulkWriter<'a> {
    pub fn new(cache: &'a CacheRocksDb, limit: usize) -> Self {
        let limit = limit.clamp(1024 * 1024, MAX_IMPORT_BATCH_BYTES);
        Self {
            cache,
            batch: WriteBatch::with_capacity_bytes(limit),
            limit,
            write_seconds: 0.0,
            written_bytes: 0,
        }
    }

    pub fn commit(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let bytes = self.batch.size_in_bytes() as u64;
        let batch = std::mem::take(&mut self.batch);
        let start = std::time::Instant::now();
        let mut options = WriteOptions::default();
        options.disable_wal(self.cache.temporary.is_some());
        options.set_sync(false);
        self.cache
            .db
            .write_opt(batch, &options)
            .map_err(|e| FirewallError::Cache(format!("bulk write failed: {e}")))?;
        self.write_seconds += start.elapsed().as_secs_f64();
        self.written_bytes += bytes;
        Ok(())
    }

    pub fn put(&mut self, name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.put_cf(self.cache.cf(name)?, key, value);
        if self.batch.size_in_bytes() >= self.limit {
            self.commit()?;
        }
        Ok(())
    }

    /// Pack the sequential spool in blocks, and let RocksDB sort compact contributions.
    /// Each contribution contains a target + sequence key and just the metadata ID and source line.
    pub fn entries(
        &mut self,
        entries: &[crate::firehol::entry::FireholEntry],
        sequence: u64,
        spool: bool,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        let contributions = self.cache.cf(cf::CONTRIBUTIONS)?;
        buffer.clear();
        let mut key = [0u8; 26];
        let mut target_buffer = [0u8; 18];
        for (offset, entry) in entries.iter().enumerate() {
            let encoded = entry.encode();
            let target = entry.target.context_key(&mut target_buffer);
            let len = target.len();
            key[..len].copy_from_slice(target);
            key[len..len + 8].copy_from_slice(&(sequence + offset as u64).to_be_bytes());
            self.batch
                .put_cf(contributions, &key[..len + 8], &encoded[22..]);
            if spool {
                buffer.extend_from_slice(&encoded);
            }
        }
        if spool {
            self.batch.put_cf(
                self.cache.cf(cf::ENTRIES)?,
                sequence.to_be_bytes(),
                &*buffer,
            );
        }
        // Overshoot is bounded by one worker block, not by the size of an input file.
        if self.batch.size_in_bytes() >= self.limit {
            self.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehol::metadata::FireholCategory;
    use std::sync::Arc;

    fn sample_metadata(id: u32) -> FireholMetadata {
        FireholMetadata {
            id,
            category: FireholCategory::Malware,
            source_url: Some(Arc::from("https://example.com/feed")),
            maintainer: Some(Arc::from("SANS")),
            maintainer_url: Some(Arc::from("https://isc.sans.edu")),
            source_file_date: Some(Arc::from("2026-09-14T00:00:00+00:00")),
            file_name: Arc::from("dshield.netset"),
            version: Some(Arc::from("1.2")),
            update_frequency: Some(Arc::from("1 day")),
        }
    }

    #[test]
    fn missing_and_corrupt_records_do_not_invoke_inspection_callbacks() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path()).unwrap();
        let key = ctx_key_v6_lpm(64, &[0; 16]);
        assert_eq!(db.get_metadata(99).unwrap(), None);
        assert_eq!(db.get_rule_context(&key).unwrap(), None);
        assert_eq!(
            db.with_metadata(99, |_| panic!("missing metadata"))
                .unwrap(),
            None::<()>
        );
        assert_eq!(
            db.with_rule_context(&key, |_| panic!("missing context"))
                .unwrap(),
            None::<()>
        );

        // Truncated archives must fail validation before any borrowed access is exposed.
        db.put(cf::METADATA, &metadata_key(99), &[255]).unwrap();
        db.put(cf::RULE_CONTEXT, &key, &[255]).unwrap();
        assert!(matches!(db.get_metadata(99), Err(FirewallError::Cache(_))));
        assert!(matches!(
            db.get_rule_context(&key),
            Err(FirewallError::Cache(_))
        ));
        assert!(db
            .with_metadata(99, |_| panic!("corrupt metadata"))
            .is_err());
        assert!(db
            .with_rule_context(&key, |_| panic!("corrupt context"))
            .is_err());
    }

    #[test]
    fn batch_writes_are_isolated_by_column_family_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = CacheRocksDb::open(dir.path()).unwrap();
            let mut batch = db.batch();
            db.batch_put(&mut batch, cf::METADATA, b"key", b"metadata")
                .unwrap();
            db.batch_put(&mut batch, cf::RULE_CONTEXT, b"key", b"context")
                .unwrap();
            assert!(db.get(cf::METADATA, b"key").unwrap().is_none());
            db.apply_batch(batch).unwrap();
            assert_eq!(
                db.get_pinned(cf::METADATA, b"key")
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                b"metadata"
            );
            db.delete(cf::METADATA, b"key").unwrap();
            db.delete(cf::METADATA, b"missing").unwrap();
            assert!(db.get_pinned(cf::METADATA, b"key").unwrap().is_none());
            db.flush_import().unwrap();
        }
        let db = CacheRocksDb::open(dir.path()).unwrap();
        assert_eq!(db.get(cf::METADATA, b"key").unwrap(), None);
        assert_eq!(
            db.get(cf::RULE_CONTEXT, b"key").unwrap(),
            Some(b"context".to_vec())
        );
    }

    #[test]
    fn missing_column_family_returns_cache_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open_single(dir.path()).unwrap();
        let mut batch = db.batch();
        for result in [
            db.get(cf::METADATA, b"key").map(|_| ()),
            db.get_pinned(cf::METADATA, b"key").map(|_| ()),
            db.put(cf::METADATA, b"key", b"value"),
            db.delete(cf::METADATA, b"key"),
            db.batch_put(&mut batch, cf::METADATA, b"key", b"value"),
            db.iter(cf::METADATA).map(|_| ()),
            db.estimate_keys(cf::METADATA).map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(FirewallError::Cache(message)) if message.contains("not found"))
            );
        }
    }

    #[test]
    fn borrowed_context_inspection_preserves_all_sources() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path()).unwrap();
        let key = ctx_key_v4_lpm(24, &[192, 0, 2, 0]);
        let context = RuleBlockContext {
            files: vec![Arc::from("a.ipset"), Arc::from("b.netset")],
            lines: vec![3, 42],
            categories: vec![FireholCategory::Abuse, FireholCategory::Botnet],
        };
        db.put_rule_context(&key, &context).unwrap();
        let inspected = db
            .with_rule_context(&key, |archived| {
                assert_eq!(&*archived.files[0], "a.ipset");
                assert_eq!(&*archived.files[1], "b.netset");
                assert_eq!(archived.lines[0], 3);
                assert_eq!(archived.lines[1], 42);
                assert_eq!(archived.categories[0].to_native(), FireholCategory::Abuse);
                assert_eq!(archived.categories[1].to_native(), FireholCategory::Botnet);
                archived.files.len()
            })
            .unwrap();
        assert_eq!(inspected, Some(2));
    }

    #[test]
    fn test_metadata_roundtrip_via_rocksdb() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        let m = sample_metadata(7);
        db.put_metadata(&m).unwrap();
        let back = db.get_metadata(7).unwrap().unwrap();
        assert_eq!(back, m);
        assert_eq!(back.category, FireholCategory::Malware);
        assert_eq!(&*back.file_name, "dshield.netset");
    }

    #[test]
    fn test_rule_context_roundtrip_via_rocksdb() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        let ctx = RuleBlockContext {
            files: vec![Arc::from("a.ipset"), Arc::from("b.netset")],
            lines: vec![10, 20],
            categories: vec![FireholCategory::Abuse, FireholCategory::Botnet],
        };
        let key = ctx_key_v4_exact(&[203, 0, 113, 9]);
        db.put_rule_context(&key, &ctx).unwrap();
        let back = db.get_rule_context(&key).unwrap().unwrap();
        assert_eq!(back, ctx);
    }

    #[test]
    fn borrowed_scan_orders_values_and_propagates_visitor_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        db.visit_values(cf::ENTRIES, |_| panic!("empty scan"))
            .unwrap();
        db.put(cf::ENTRIES, b"b", b"second").unwrap();
        db.put(cf::ENTRIES, b"a", b"first").unwrap();
        let mut values = Vec::new();
        db.visit_values(cf::ENTRIES, |value| {
            values.push(value.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(values, [b"first".to_vec(), b"second".to_vec()]);
        let mut visited = 0;
        let result = db.visit_values(cf::ENTRIES, |_| {
            visited += 1;
            Err(FirewallError::Cache("stop scan".into()))
        });
        assert!(result.unwrap_err().to_string().contains("stop scan"));
        assert_eq!(visited, 1);
    }

    #[test]
    fn rkyv_zero_copy_and_unaligned_access() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        let mut buffer = AlignedVec::with_capacity(256);
        for count in [200usize, 1, 0, 300] {
            let ctx = RuleBlockContext {
                files: (0..count)
                    .map(|i| Arc::from(format!("long-blocklist-file-{i}.netset")))
                    .collect(),
                lines: (0..count as u32).collect(),
                categories: vec![FireholCategory::Abuse],
            };
            db.serialize_rule_context_into(&ctx, &mut buffer).unwrap();

            // 1. Zero-copy access directly
            let archived = CacheRocksDb::access_rule_context(&buffer).unwrap();
            assert_eq!(archived.files.len(), count);
            assert_eq!(archived.lines.len(), count);

            // 2. Unaligned slice read: offset by 1 odd byte
            let mut unaligned = vec![0u8];
            unaligned.extend_from_slice(&buffer);
            let unaligned_archived = CacheRocksDb::access_rule_context(&unaligned[1..]).unwrap();
            assert_eq!(unaligned_archived.files.len(), count);

            // 3. Full deserialization back to owned
            assert_eq!(db.deserialize_rule_context(&unaligned[1..]).unwrap(), ctx);
        }
    }

    #[test]
    fn test_zero_copy_pinned_access() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        let m = sample_metadata(42);
        db.put_metadata(&m).unwrap();

        let inspected = db
            .with_metadata(42, |archived| {
                assert_eq!(archived.id, 42);
                assert_eq!(archived.file_name_str(), "dshield.netset");
                assert_eq!(archived.category.to_native(), FireholCategory::Malware);
                archived.file_name_str().to_string()
            })
            .unwrap();
        assert_eq!(inspected, Some("dshield.netset".to_string()));
    }

    #[test]
    fn test_key_encodings_are_unique_per_target_kind() {
        assert_ne!(
            ctx_key_v4_exact(&[1, 2, 3, 4]),
            ctx_key_v4_lpm(24, &[1, 2, 3, 0])[..]
        );
        assert_eq!(ctx_key_v4_exact(&[1, 2, 3, 4])[0], tag::V4_EXACT);
        assert_eq!(ctx_key_v6_exact(&[0; 16])[0], tag::V6_EXACT);
    }

    #[test]
    fn test_flush_estimate_keys_and_owned_rkyv_paths() {
        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();
        db.flush().unwrap();

        // estimate_keys mirrors the live key count.
        db.put(cf::ENTRIES, b"a", b"1").unwrap();
        db.put(cf::ENTRIES, b"b", b"22").unwrap();
        assert_eq!(db.estimate_keys(cf::ENTRIES).unwrap(), 2);

        // Owned (non-into) serialization + unchecked zero-copy access paths.
        let meta = sample_metadata(77);
        let bytes = db.serialize_metadata(&meta).unwrap();
        let archived = unsafe { CacheRocksDb::access_metadata_unchecked(&bytes) };
        assert_eq!(archived.id, 77);
        assert_eq!(archived.category.to_native(), FireholCategory::Malware);
        assert_eq!(db.deserialize_metadata(&bytes).unwrap(), meta);

        let ctx = RuleBlockContext {
            files: vec![Arc::from("ctx-file.netset")],
            lines: vec![12],
            categories: vec![FireholCategory::Botnet],
        };
        let ctx_bytes = db.serialize_rule_context(&ctx).unwrap();
        let archived_ctx = unsafe { CacheRocksDb::access_rule_context_unchecked(&ctx_bytes) };
        let files: Vec<&str> = archived_ctx.files_iter().collect();
        assert_eq!(files, vec!["ctx-file.netset"]);
        assert_eq!(db.deserialize_rule_context(&ctx_bytes).unwrap(), ctx);
    }

    #[test]
    fn test_bulk_writer_auto_commit_on_threshold() {
        use crate::firehol::entry::{FireholEntry, FireholIpTarget};

        let dir = tempfile::tempdir().unwrap();
        let db = CacheRocksDb::open(dir.path().join("cache")).unwrap();

        // put() auto-commits once the batch exceeds the (lowered) byte limit.
        let mut writer = BulkWriter::new(&db, 1024 * 1024);
        writer.limit = 64;
        let value = [0u8; 128];
        writer.put(cf::ENTRIES, b"k1", &value).unwrap();
        writer.put(cf::ENTRIES, b"k2", &value).unwrap();
        assert!(writer.written_bytes > 0);
        writer.commit().unwrap();

        // entries() auto-commits overshoots bounded by one worker block.
        let mut writer2 = BulkWriter::new(&db, 1024 * 1024);
        writer2.limit = 64;
        let entries = [
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 1]), 1, 1, 5),
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 2]), 2, 1, 6),
        ];
        let mut buffer = Vec::new();
        writer2
            .entries(&entries, 0, true, &mut buffer)
            .unwrap();
        assert!(buffer.len() >= 2);
        assert!(writer2.write_seconds >= 0.0);
        writer2.commit().unwrap();

        // Data lands in the column families regardless of commit boundaries.
        assert!(db.estimate_keys(cf::ENTRIES).unwrap() >= 1);
        assert!(db.estimate_keys(cf::CONTRIBUTIONS).unwrap() >= 2);
    }
}
