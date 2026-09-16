# AGENTS.md — Developer & AI Agent Guidelines

> **Target Audience:** Autonomous AI coding agents, maintainers, and systems engineers working on the **eBPF IP Reputation Firewall**.

---

## 1. Mission & System Overview

The **eBPF IP Reputation Firewall** is a production-grade, high-performance packet filtering system built with **Rust** and the **Aya eBPF library**. It operates inside the Linux kernel at the **XDP (eXpress Data Path)** layer—the earliest hook in the Linux network subsystem—enabling wire-speed packet inspection and sub-microsecond drops before the kernel network stack allocates an `sk_buff`.

### Key Capabilities
- **Line-rate dropping:** Sub-microsecond decisions in kernel space via XDP driver/generic modes.
- **Dual-tier matching:**
  - **Tier 1:** Exact $O(1)$ Hash maps (`BPF_MAP_TYPE_HASH`) for `/32` IPv4 and `/128` IPv6 host addresses.
  - **Tier 2:** Longest Prefix Match Tries (`BPF_MAP_TYPE_LPM_TRIE`) for arbitrary CIDR subnet blocks.
- **Automated Threat Intelligence:** Automated Git synchronization, validation, parsing, and scheduling with **FireHOL IP reputation blocklists**.
- **Disjoint Rule ID Namespaces:** FireHOL rules and static rules are isolated by ID to prevent metadata cross-contamination in drop telemetry.
- **Zero-Copy & Low Memory Footprint:**
  - **rkyv 0.8** zero-copy serialization/deserialization.
  - Optional **RocksDB** on-disk LZ4 cache for heavy threat intelligence metadata.
  - **tikv-jemallocator** for high-throughput, low-fragmentation userspace memory management.
- **Lockless Telemetry:** eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`) emitting strict **64-byte** aligned events for drop logging and security monitoring.
- **Observability:** Built-in Prometheus metrics exporter (`/metrics`), dynamic Top-N blocked IP cardinality management, and Grafana dashboard provisioning.

---

## 2. Workspace & Repository Layout

The project is organized as a Cargo workspace with distinct crate boundaries to separate kernel-space eBPF code from userspace runtime logic:

```
eBPF-ip-reputation-firewall/
├── Cargo.toml                  # Workspace root manifest (userspace, common, scripts, xtask)
├── Makefile                    # Unified orchestrator for builds, tests, benchmarks, docker
├── Dockerfile                  # Multi-stage container with eBPF tools & traffic generators
├── docker-compose.yml          # Container topology (firewall, traffic-generator, prometheus, grafana)
├── README.md                   # User-facing system documentation & architecture diagrams
│
├── firewall-common/            # #![no_std] crate shared between kernel eBPF and userspace
│   ├── Cargo.toml
│   └── src/lib.rs              # PacketLogEvent (64B), RuleValue, LpmKeyV4/V6, FirewallStats, Pod impls
│
├── firewall-ebpf/              # Kernel-space XDP firewall program (bpfel-unknown-none target)
│   ├── Cargo.toml              # Excluded from main workspace; compiled with nightly rustc + bpf-linker
│   └── src/main.rs             # #[xdp] hook, packet parsing, map lookups, ring buffer events
│
├── src/                        # Userspace control daemon (firewall binary & library)
│   ├── main.rs                 # Daemon entrypoint, task orchestration, graceful shutdown
│   ├── lib.rs                  # Module exports for library and integration testing
│   ├── config.rs               # CLI arguments (clap) and environment variable resolution
│   ├── console.rs              # ANSI styling and terminal color initialization
│   ├── error.rs                # Error types using thiserror
│   ├── maps.rs                 # MapManager: Map abstraction and differential rule synchronization
│   ├── xdp.rs                  # XdpFirewall: Aya program loader and XDP attachment handling
│   ├── ringbuf.rs              # RingBufConsumer: Async telemetry processor (AsyncFd)
│   ├── loader.rs               # RuleLoader & StaticRuleRegistry: Static text file blocklist parser
│   ├── cache_rocksdb.rs        # RocksDB column families, LZ4 compression, rkyv zero-copy cache
│   ├── top_n.rs                # BlockedIpTopN: Bounded cardinality Top-N tracker with auto-eviction
│   ├── metrics.rs              # Prometheus metrics registry and HTTP exporter server
│   ├── stats.rs                # StatsReporter: Periodic kernel counter polling and reporting
│   └── firehol/                # FireHOL threat intelligence subsystem
│       ├── mod.rs              # Subsystem coordinator and execute_firehol_sync
│       ├── blocklist.rs        # FireholBlockList manager
│       ├── entry.rs            # FireholEntry and IP target representations
│       ├── git_repository.rs   # Shallow Git repository management (libgit2/git2)
│       ├── metadata.rs         # Metadata structures, categories, and FireholMetadataRegistry
│       ├── parser.rs           # Multi-threaded Rayon parser for .ipset and .netset files
│       └── scheduler.rs        # Cron scheduler (tokio-cron-scheduler) for periodic syncs
│
├── xtask/                      # Build automation helper (cargo xtask)
│   ├── Cargo.toml
│   └── src/main.rs             # Subcommands: build-ebpf, build, run
│
├── scripts/                    # Testing and evaluation tooling
│   ├── Cargo.toml
│   ├── benchmark/              # High-performance multi-threaded AF_PACKET benchmark tool
│   ├── test_traffic/           # End-to-end multi-protocol traffic verification tool
│   └── common/                 # Raw packet crafting utilities (Ethernet, IPv4/v6, TCP, UDP, ICMP)
│
├── rules/                      # Local static blocklist rules and threat feeds
│   ├── blocklist.txt           # Sample IPv4 exact hosts (/32)
│   ├── blocklist_v6.txt        # Sample IPv6 exact hosts (/128)
│   └── cidr_ranges.txt         # Sample IPv4/IPv6 CIDR subnets
│
├── tests/                      # Integration test suites
│   ├── integration_tests.rs
│   ├── firehol_integration_test.rs
│   ├── firehol_scheduler_test.rs
│   └── rule_id_namespace_test.rs
│
├── benches/                    # Criterion microbenchmarks
│   ├── lookup_benchmark.rs
│   ├── firehol_benchmark.rs
│   └── rocksdb_benchmark.rs
│
└── grafana/                    # Grafana dashboards and provisioning configs
```

---

## 3. Core Architecture & Technical Invariants

When reading, modifying, or extending this codebase, the following technical invariants **must never be violated**:

### 3.1 Dual-Tier Packet Matching
1. **Tier 1 (Exact Match):**
   - Maps: `IPV4_EXACT_MAP` (`[u8; 4] -> RuleValue`) and `IPV6_EXACT_MAP` (`[u8; 16] -> RuleValue`).
   - Complexity: $O(1)$ constant time lookup.
   - Used for `/32` IPv4 addresses and `/128` IPv6 addresses.
2. **Tier 2 (LPM Trie Match):**
   - Maps: `IPV4_LPM_MAP` and `IPV6_LPM_MAP` using Aya's `LpmTrie`.
   - Complexity: Longest Prefix Match over bit-trie structures.
   - **Crucial Kernel Invariant:** On Linux, `BPF_MAP_TYPE_LPM_TRIE` requires the `BPF_F_NO_PREALLOC` flag. Aya sets this flag by default; do not alter map definitions to remove it.

### 3.2 Rule ID Namespace Separation
Static rules and FireHOL threat intelligence feeds share the same eBPF maps. To prevent dropped packet telemetry from misattributing static matches to FireHOL feeds (e.g., mislabeling a local private CIDR match as a public malware feed):
- **FireHOL Rules:** Assigned dynamic, dense rule IDs starting at `1` up to `STATIC_RULE_BASE - 1`.
- **Static Rules:** Assigned IDs starting at `STATIC_RULE_BASE` (`2_000_000_000`), defined in [`src/loader.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/src/loader.rs).
- When resolving drop events:
  - IDs `< STATIC_RULE_BASE` are queried in the `FireholMetadataRegistry`.
  - IDs `>= STATIC_RULE_BASE` are queried in the `StaticRuleRegistry`.

### 3.3 Memory Layout & Ring Buffer Telemetry
The kernel passes drop telemetry to userspace via `BPF_MAP_TYPE_RINGBUF` using [`PacketLogEvent`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-common/src/lib.rs):
- **Cache-Line Alignment:** `PacketLogEvent` is asserted at compile-time to be exactly **64 bytes** (`size_of::<PacketLogEvent>() == 64`).
- **Safety:** Structs passed across the kernel-userspace boundary must use `#[repr(C)]` and implement `aya::Pod`.
- **Zero-Copy Consumption:** Userspace reads raw pointers from the ring buffer and casts them directly without heap allocation.

### 3.4 eBPF Verifier & Kernel Safety Constraints
Inside [`firewall-ebpf/src/main.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-ebpf/src/main.rs):
- **Bounds Checking:** Every single memory access must be guarded with `ptr_at<T>(ctx, offset)`. The verifier rejects any dereference where `offset + sizeof(T) > ctx.data_end()`.
- **Unaligned Memory Access:** Ethernet headers are 14 bytes long. Consequently, IPv4/IPv6 headers start at a 2-byte unaligned boundary. **Always** use `core::ptr::read_unaligned` when loading multi-byte fields (IP addresses, ports, protocol headers) from packet memory.
- **No Allocations / No Panics:** The eBPF crate is strictly `#![no_std]` and `#![no_main]`. No heap allocation (`alloc`), recursion, or panic unwinding is permitted.
- **Critical Infrastructure Bypass:** The kernel XDP hook contains hardcoded whitelists for:
  - GitHub CIDR ranges (prevents the firewall from blocking its own FireHOL Git sync).
  - DNS traffic (destination or source port 53) to preserve resolver connectivity.

### 3.5 Fail-Safe Startup Order
The daemon follows a strict startup sequencing:
1. Parse CLI configuration.
2. Initialize tracing subscriber and Prometheus metrics registry.
3. Load eBPF bytecode into the kernel (`XdpFirewall::load()`).
4. Initialize `RingBufConsumer` and `MapManager` from eBPF maps.
5. **Synchronize FireHOL blocklists and static rules into eBPF maps FIRST.**
   - *Fail-Safe Invariant:* If initial rule synchronization fails, the daemon aborts startup (`process::exit(1)`). It never attaches XDP with empty or half-populated maps.
6. **Attach XDP hook to network interface** (`xdp_firewall.attach()`). Only after maps are fully verified does live traffic hit the firewall.
7. Spawn background tasks (RingBuf consumer, Prometheus server, Stats reporter, File watcher, FireHOL cron scheduler).
8. Wait for SIGINT/SIGTERM, broadcast cancellation via `tokio::sync::watch`, cleanly detach hooks, and flush cache.

---

## 4. Developer & AI Agent Workflows

All operational tasks are standardized via the [`Makefile`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/Makefile).

### 4.1 Prerequisites
- **Rust Toolchain:**
  - Stable `rustc` (for userspace, common, scripts, xtask).
  - Nightly `rustc` with `rust-src` component (for eBPF):
    ```bash
    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly
    ```
- **eBPF Linker:**
  ```bash
  cargo install bpf-linker
  ```
- **C/C++ & LLVM Toolchain:** `clang`, `llvm`, `gcc`, `libclang-dev`.
- **Static Builds (Optional / Musl):** `x86_64-linux-musl-cross` toolchain for fully static musl compilation (configured via `MUSL_CROSS_ROOT`).

### 4.2 Build Commands

| Target | Command | Description |
|---|---|---|
| **Build All** | `make build` | Builds both the eBPF kernel program and userspace daemon in release mode. |
| **Build eBPF** | `make build-ebpf` | Compiles `firewall-ebpf` to target `bpfel-unknown-none` using `bpf-linker`. |
| **Build Userspace** | `make build-userspace` | Compiles `firewall` userspace daemon with native optimizations (`BUILD_STATIC=OFF` for dynamic glibc). |
| **Clean Artifacts** | `make clean` | Cleans cargo target directories across workspace and eBPF crates. |

> [!TIP]
> To compile dynamically linked userspace binaries against your local glibc (skipping musl-cross):
> ```bash
> make build-userspace BUILD_STATIC=OFF
> ```

### 4.3 Testing & Verification

| Target | Command | Description |
|---|---|---|
| **Run All Tests** | `make test` | Executes unit and integration test suites for both workspace and eBPF crates. |
| **Clippy** | `make clippy` | Runs linter across all targets with warnings treated as errors (`-D warnings`). |
| **Format Check** | `make fmt-check` | Verifies formatting rules across all workspace crates (`cargo fmt --check`). |
| **Auto-Format** | `make fmt` | Formats all Rust code across the workspace. |
| **Microbenchmarks** | `make bench-micro` | Runs Criterion microbenchmarks (`lookup_benchmark`, `firehol_benchmark`, `rocksdb_benchmark`). |

### 4.4 Docker & Containerized Traffic Testing

The Docker test environment boots isolated containers connected via a private Docker bridge (`firewall-net`), including Prometheus, Grafana, and an `AF_PACKET` raw traffic generator:

```bash
# 1. Build and start containers
make docker-up

# 2. Run multi-protocol traffic tests (verifies TCP/UDP/ICMP drops and accepts)
make test-traffic

# 3. Run high-throughput traffic benchmark
make bench-traffic

# 4. Follow firewall container logs
make docker-logs-follow

# 5. Tear down environment
make docker-down
```

---

## 5. CLI & Configuration Reference

The userspace daemon CLI is parsed with `clap` in [`src/config.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/src/config.rs). All parameters can be configured via flags or environment variables:

| Argument | Env Variable | Default | Description |
|---|---|---|---|
| `-i, --iface <IFACE>` | `FIREWALL_IFACE` | `eth0` | Network interface to attach XDP (e.g. `eth0`, `lo`, `ens3`). |
| `-r, --rules <PATHS>` | `FIREWALL_RULES` | `rules/blocklist.txt,...` | Comma-separated list of static rule files. |
| `-m, --mode <MODE>` | — | `auto` | XDP mode: `auto` (driver then generic), `driver`, `generic`, `hardware`. |
| `-w, --watch` | — | `false` | Enable live hot-reloading file watcher (`notify`) for rule files. |
| `--json` | — | `false` | Emit structured JSON drop telemetry for SIEM ingestion. |
| `-q, --quiet` | `FIREWALL_QUIET` | `false` | Suppress console drop logs (recommended during benchmarks). |
| `--stats-interval <SEC>`| — | `5` | Periodic throughput and drop stats display interval (0 = disabled). |
| `--metrics-listen-addr` | `METRICS_LISTEN_ADDRESS`| `0.0.0.0:9100` | Prometheus HTTP scrape address (`/metrics`). |
| `--no-metrics` | — | `false` | Disable Prometheus metrics exporter. |
| `--bpf-path <PATH>` | — | `None` (auto-detect)| Custom path to compiled eBPF object ELF file. |
| `--log-level <LEVEL>` | `RUST_LOG` | `info` | Tracing level: `trace`, `debug`, `info`, `warn`, `error`. |
| `--firehol` / `--no-firehol` | `FIREWALL_FIREHOL` | `true` | Toggle FireHOL blocklist synchronization. |
| `--firehol-dir <DIR>` | `FIREWALL_FIREHOL_DIR` | `rules/firehol-blocklist-ipsets` | Directory path for local FireHOL Git clone. |
| `--firehol-url <URL>` | `FIREWALL_FIREHOL_URL` | `https://github.com/firehol/blocklist-ipsets` | Upstream Git repo URL. |
| `--firehol-branch <BR>` | `FIREWALL_FIREHOL_BRANCH`| `master` | Git branch to track. |
| `--firehol-cache-dir` | `FIREWALL_FIREHOL_CACHE_DIR`| `cache/firehol` | RocksDB cache directory for heavy metadata. |
| `--firehol-cron <CRON>` | `FIREHOL_UPDATE_CRON`| `0 0 * * * *` | 6-field cron schedule for periodic Git sync (hourly). |
| `--no-cron` | `FIREWALL_NO_CRON` | `false` | Disable periodic scheduled FireHOL updates. |
| `--firehol-ignore-ip` | `FIREHOL_IGNORE_IP` | `""` | Comma-separated list of IPs to never block from FireHOL. |
| `--no-color` | `NO_COLOR` | `false` | Disable ANSI terminal formatting. |

---

## 6. Coding Standards & Agent Guidelines

### 6.1 General Rules
1. **Never Break `PacketLogEvent` Alignment:**
   - Any modification to [`firewall-common/src/lib.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-common/src/lib.rs) that alters `PacketLogEvent` must maintain the compile-time assertion `core::mem::size_of::<PacketLogEvent>() == 64`.
   - Update field offsets and padding systematically.
2. **Dual-Crate Compilation Check:**
   - Whenever you touch `firewall-common`, verify that **both** userspace (`cargo check --workspace`) and eBPF (`cargo xtask build-ebpf`) compile without error.
3. **Keep `firewall-common` and `firewall-ebpf` strictly `#![no_std]`:**
   - Never import `std` in `firewall-common` or `firewall-ebpf`.
   - Keep dependencies in these crates to zero-alloc libraries (`aya-ebpf`, `aya-log-ebpf`).
4. **Bounds Checking Invariance:**
   - Never use direct raw pointer indexing on packet data in `firewall-ebpf`.
   - Always route packet slicing through `ptr_at<T>()`.
5. **Always Use Unaligned Pointer Reads in eBPF:**
   - Due to the 14-byte Ethernet header, protocol headers do not sit on 4-byte or 8-byte boundaries.
   - Use `core::ptr::read_unaligned` for reading IP addresses, ports, and header fields. Direct dereferencing triggers verifier failure on architectures that disallow unaligned access.
6. **Zero-Copy Serialization:**
   - When storing or querying metadata in RocksDB, use `rkyv::to_bytes` and `CacheRocksDb::access_*` / `CacheRocksDb::with_*`. Avoid unnecessary heap copying.
7. **Thread-Safe Shared State:**
   - `MapManager` must remain protected by `Arc<tokio::sync::Mutex<MapManager>>` to guarantee that concurrent FireHOL sync and static hot-reload operations perform atomic differential map updates.

---

## 7. Step-by-Step Task Guides for Agents

### Task A: Adding a New Prometheus Metric
1. Open [`src/metrics.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/src/metrics.rs).
2. Add the metric field (`IntCounter`, `IntGauge`, `Histogram`, etc.) to the `PrometheusMetrics` struct.
3. Register the metric in `PrometheusMetrics::new()` using the `prometheus::opts!` macro and `registry.register()`.
4. Expose a helper method on `PrometheusMetrics` to update or increment the metric.
5. If the metric should appear on the Grafana dashboard, update [`grafana/provisioning/dashboards/dashboard.json`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/grafana/provisioning/dashboards/dashboard.json).
6. Run `make test` to verify metric registration and tests.

### Task B: Adding a New eBPF Map
1. Define the map in [`firewall-ebpf/src/main.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-ebpf/src/main.rs) using `#[map]`. Specify the map type (`HashMap`, `LpmTrie`, `Array`, etc.) and pin mode if needed.
2. If keys or values are shared with userspace, define the struct in [`firewall-common/src/lib.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-common/src/lib.rs) with `#[repr(C)]` and `unsafe impl aya::Pod`.
3. In [`src/maps.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/src/maps.rs):
   - Add the map handle to `MapManager`.
   - Take ownership of the map from `Ebpf` in `MapManager::new()`.
   - Add methods to synchronize, insert, or read entries from the map.
4. Compile the kernel program with `make build-ebpf` to verify verifier acceptance.
5. Compile userspace with `make build-userspace`.

### Task C: Supporting a New Network Protocol or Matching Criteria
1. Update `BlockedProtocol` in [`src/top_n.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/src/top_n.rs) to include the new protocol.
2. Update protocol parsing in [`firewall-ebpf/src/main.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-ebpf/src/main.rs) inside `process_ipv4` / `process_ipv6`.
3. Update `PacketLogEvent::protocol_name()` in [`firewall-common/src/lib.rs`](file:///home/o/RustroverProjects/eBPF-ip-reputation-firewall/firewall-common/src/lib.rs).
4. Update `scripts/common/` to support generating test packets with the new protocol.
5. Run `make test` and `make test-traffic`.
