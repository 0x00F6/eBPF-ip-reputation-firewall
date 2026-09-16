# syntax=docker/dockerfile:1

# ==============================================================================
# 🛡️ Multi-Stage Optimized Dockerfile with Docker BuildKit Caching
# ==============================================================================
# Architecture:
#   Stage 1 (toolchain): Rust 1.98+ (Bookworm) + Nightly + LLVM + bpf-linker + git
#   Stage 2 (cacher):    Pre-compile all 80+ dependencies using dummy skeletons
#   Stage 3 (builder):   Compile ONLY changed application code in src/ and scripts/
#   Stage 4 (runtime):   Ultra-lean Debian slim runtime with eBPF capabilities
# ==============================================================================

# ------------------------------------------------------------------------------
# STAGE 1: Toolchain & Build Prerequisites
# ------------------------------------------------------------------------------
FROM rust:bookworm AS toolchain

# Install LLVM/Clang (libclang is required by bindgen in librocksdb-sys, and
# clang/clang++ are required by the Makefile for the native RocksDB **LTO** build),
# Git and Linux kernel build headers.
# `clang`/`clang++`/`llvm`/`libclang-dev` meta-packages resolve to 14 on Bookworm
# and ship both the `clang`/`clang++` binaries the Makefile expects (`CC=clang`)
# and the matching libclang used by bindgen.
# `g++` provides the libstdc++ headers that clang uses to compile RocksDB.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libclang-dev \
    g++ \
    pkg-config \
    libelf-dev \
    make \
    curl \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && git config --global --add safe.directory '*'

# Point bindgen (librocksdb-sys) at the installed libclang-14
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# Install Rust nightly toolchain with rust-src for eBPF target bpfel-unknown-none,
# plus the musl target used for the fully static userspace build
RUN rustup toolchain install nightly --component rust-src && \
    rustup target add x86_64-unknown-linux-musl

# Install the musl-cross C/C++ toolchain (musl.cc) at the location the Makefile
# expects by default (MUSL_CROSS_ROOT=$(HOME)/.local/x86_64-linux-musl-cross, and
# HOME=/root in this image). Debian's musl-tools only ships musl-gcc (C only), but
# the workspace builds rocksdb/librocksdb-sys which requires a musl C++ compiler,
# libstdc++ and a musl-aware linker.
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://musl.cc/x86_64-linux-musl-cross.tgz -o /tmp/musl-cross.tgz && \
    mkdir -p /root/.local && \
    tar -xzf /tmp/musl-cross.tgz -C /root/.local && \
    rm /tmp/musl-cross.tgz

# Make the musl-cross toolchain discoverable on PATH (its bin dir is also what the
# Makefile prepends via STATIC_ENV when static builds are enabled)
ENV PATH=/root/.local/x86_64-linux-musl-cross/bin:$PATH

# Install bpf-linker via cargo-binstall for fast and reproducible installation
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash && \
    (cargo-binstall -y bpf-linker@0.11.1 || cargo install bpf-linker --version 0.11.1 --locked)

WORKDIR /build

# ------------------------------------------------------------------------------
# STAGE 2: Dependency Pre-Compilation (Cached Layer)
# ------------------------------------------------------------------------------
# This stage ONLY invalidates when Cargo.toml or Cargo.lock manifests are modified.
# Source code modifications in src/ or scripts/ will NOT invalidate this layer!
FROM toolchain AS cacher

# Copy all Cargo manifests, workspace configurations, and build script
COPY Cargo.toml Cargo.lock Makefile build.rs ./
COPY firewall-common/Cargo.toml ./firewall-common/Cargo.toml
COPY firewall-ebpf/Cargo.toml ./firewall-ebpf/Cargo.toml
COPY firewall-ebpf/rust-toolchain.toml ./firewall-ebpf/rust-toolchain.toml
COPY firewall-ebpf/.cargo ./firewall-ebpf/.cargo
COPY xtask/Cargo.toml ./xtask/Cargo.toml
COPY scripts/Cargo.toml ./scripts/Cargo.toml

# Copy firewall-common shared crate source (type definitions only, fast to build)
COPY firewall-common/src ./firewall-common/src

# Create dummy source skeletons for binary and library crates
RUN mkdir -p src xtask/src firewall-ebpf/src firewall-ebpf/benches firewall-common/src firewall-common/benches benches tests scripts/common/src scripts/test_traffic/src scripts/benchmark/src && \
    echo 'pub fn dummy() {}' > src/lib.rs && \
    printf '#![no_std]\npub fn dummy() {}\n' > firewall-ebpf/src/lib.rs && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'fn main() {}' > xtask/src/main.rs && \
    echo 'fn main() {}' > benches/lookup_benchmark.rs && \
    echo 'fn main() {}' > benches/firehol_benchmark.rs && \
    echo 'fn main() {}' > benches/rocksdb_benchmark.rs && \
    echo 'fn main() {}' > firewall-common/benches/common_benchmark.rs && \
    echo 'fn main() {}' > firewall-ebpf/benches/ebpf_benchmark.rs && \
    echo 'pub fn dummy() {}' > scripts/common/src/lib.rs && \
    echo 'fn main() {}' > scripts/test_traffic/src/main.rs && \
    echo 'fn main() {}' > scripts/benchmark/src/main.rs && \
    printf '#![no_std]\n#![no_main]\nuse aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};\n#[panic_handler]\nfn panic(_: &core::panic::PanicInfo) -> ! { loop {} }\n#[xdp]\npub fn firewall(_ctx: XdpContext) -> u32 { xdp_action::XDP_PASS }\n' > firewall-ebpf/src/main.rs

# Pre-compile ALL dependencies using Docker BuildKit cache mounts:
# - Cargo crate download cache (/usr/local/cargo/registry)
# - Cargo git checkouts (/usr/local/cargo/git)
# - Target compilation artifacts (/build/target)
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=firewall-target,target=/build/target \
    make build

# ------------------------------------------------------------------------------
# STAGE 3: Final Application Builder (Fast Recompile on Source Changes)
# ------------------------------------------------------------------------------
FROM cacher AS builder
ARG GIT_REF=""
ENV GIT_REF=${GIT_REF}

# Copy git repository for build metadata, source code, benchmarks, tests, rules, and scripts
COPY .git ./.git
COPY build.rs ./build.rs
COPY src ./src
COPY firewall-ebpf/src ./firewall-ebpf/src
COPY xtask/src ./xtask/src
COPY rules ./rules
COPY benches ./benches
COPY tests ./tests
COPY scripts ./scripts

# Update mtime on all source files to ensure Cargo detects they are newer than dummy stubs
RUN touch build.rs src/lib.rs src/main.rs firewall-ebpf/src/main.rs xtask/src/main.rs \
    benches/lookup_benchmark.rs benches/firehol_benchmark.rs benches/rocksdb_benchmark.rs \
    scripts/common/src/lib.rs scripts/test_traffic/src/main.rs scripts/benchmark/src/main.rs

# Build release binaries with BuildKit caches.
# Only the changed source files are recompiled; all dependencies are reused from cache!
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=firewall-target,target=/build/target \
    make build && \
    mkdir -p /out && \
    cp /build/target/release/firewall /out/firewall && \
    cp /build/target/release/test_traffic /out/test_traffic && \
    cp /build/target/release/benchmark /out/benchmark && \
    cp /build/target/bpfel-unknown-none/release/firewall-ebpf /out/firewall-ebpf

# ------------------------------------------------------------------------------
# STAGE 4: Minimal Runtime Environment
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install essential networking utilities, git, and certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    curl \
    tcpdump \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/ /var/cache/apt/archives/ \
    && git config --global --add safe.directory '*'

WORKDIR /app

# Copy release binaries and default rule sets from the builder stage
COPY --from=builder /out/firewall /usr/local/bin/firewall
COPY --from=builder /out/test_traffic /usr/local/bin/test_traffic
COPY --from=builder /out/benchmark /usr/local/bin/benchmark
COPY --from=builder /out/firewall-ebpf /app/firewall-ebpf
COPY rules /app/rules

# Configure environment defaults
ENV RUST_LOG="info,firewall=info"
ENV FIREWALL_IFACE="eth0"
ENV FIREWALL_RULES="/app/rules/blocklist.txt,/app/rules/blocklist_v6.txt,/app/rules/cidr_ranges.txt"
ENV METRICS_LISTEN_ADDRESS="0.0.0.0:9100"
ENV FIREWALL_EBPF_PATH="/app/firewall-ebpf"

# Expose Prometheus metrics endpoint
EXPOSE 9100

# Run firewall daemon
ENTRYPOINT ["/usr/local/bin/firewall"]
CMD ["--watch"]
