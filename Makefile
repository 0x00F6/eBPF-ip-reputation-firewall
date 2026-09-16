.PHONY: all build buid build-ebpf build-userspace run test code-coverage bench bench-micro bench-traffic test-traffic clippy fmt fmt-check clean docker-build docker-up docker-down docker-logs logs docker-logs-follow

SHELL := /bin/bash

# Force ANSI color output by default across all tools (Cargo, compilers, Docker Compose)
export CARGO_TERM_COLOR ?= always
export CLICOLOR_FORCE ?= 1

# Color definitions for Makefile announcements (enabled by default)
CYAN    := \033[1;36m
GREEN   := \033[1;32m
YELLOW  := \033[1;33m
RED     := \033[1;31m
BLUE    := \033[1;34m
MAGENTA := \033[1;35m
BOLD    := \033[1m
RESET   := \033[0m

DOCKER_COMPOSE ?= docker compose --ansi always

# Allow disabling colors if NO_COLOR is explicitly set (e.g. make NO_COLOR=1)
ifneq ($(filter-out 0 false,$(NO_COLOR)),)
    CYAN    :=
    GREEN   :=
    YELLOW  :=
    RED     :=
    BLUE    :=
    MAGENTA :=
    BOLD    :=
    RESET   :=
    export CARGO_TERM_COLOR := never
    export CLICOLOR_FORCE := 0
    DOCKER_COMPOSE := docker compose --ansi never
endif

CARGO ?= cargo
RUST_NIGHTLY ?= nightly
TARGET_BPF ?= bpfel-unknown-none
TARGET_DIR ?= target
RUSTFLAGS ?= -C target-cpu=native

# ---- Clang C/C++ toolchain (required by the RocksDB `lto` feature) ----
# librocksdb-sys rejects `lto` unless the C/C++ compiler is clang. On several
# distros clang fails to auto-locate the GCC-provided libstdc++ headers (e.g.
# when the installed GCC is newer than clang's own probing default), so we point
# clang at the really-installed GCC include dirs. The final native link still
# goes through the system linker (gcc), which already locates `libstdc++`.
# `origin default` matches GNU make's built-in CC=cc / CXX=g++, which `?=` would
# otherwise refuse to override. Any value coming from the environment, the command
# line, or a prior makefile assignment is honoured as-is (e.g. `make CXX=clang++`).
CC                  := $(if $(filter default,$(origin CC)),clang,$(CC))
CXX                 := $(if $(filter default,$(origin CXX)),clang++,$(CXX))
GCC_VER             ?= $(shell gcc -dumpfullversion | cut -d. -f1)
GCC_MACH            ?= $(shell gcc -dumpmachine)
STDCPP_INCS         := -isystem /usr/include/c++/$(GCC_VER) \
                       -isystem /usr/include/$(GCC_MACH)/c++/$(GCC_VER) \
                       -isystem /usr/include/c++/$(GCC_VER)/backward
CLANG_CFLAGS        ?= $(STDCPP_INCS)
CLANG_CXXFLAGS      ?= $(STDCPP_INCS)
# Prefixed to every NATIVE (non-static) cargo invocation that compiles C/C++ deps.
CLANG_ENV           := CC=$(CC) CXX=$(CXX) CFLAGS="$(CLANG_CFLAGS)" CXXFLAGS="$(CLANG_CXXFLAGS)"

# Static compilation configuration (default: ON)
BUILD_STATIC ?= ON
TARGET_STATIC ?= x86_64-unknown-linux-musl

# Full musl-cross C/C++ toolchain (gcc/g++/ar linked against musl libc) that is
# required to compile C++ dependencies (RocksDB, vendored OpenSSL) for the fully
# static musl target. The distro's `musl-tools` only ships a C compiler, not g++.
# Override with `make MUSL_CROSS_ROOT=/path/to/toolchain`.
MUSL_CROSS_ROOT ?= $(HOME)/.local/x86_64-linux-musl-cross
MUSL_CROSS_BIN := $(MUSL_CROSS_ROOT)/bin
MUSL_CXX ?= x86_64-linux-musl-g++
# libclang is used by bindgen (librocksdb-sys) while cross-compiling.
LIBCLANG_PATH ?= /usr/lib/llvm-21/lib

ifeq ($(filter-out ON on 1 true TRUE yes YES,$(BUILD_STATIC)),)
    STATIC_CARGO_ARGS := --target $(TARGET_STATIC) --features git2/vendored-openssl
    STATIC_MSG := [Static: $(TARGET_STATIC)]
    IS_STATIC := 1
    # musl-cross toolchain binaries must be discoverable by name on PATH, and the
    # final Rust link must go through the musl g++ driver so libstdc++ and musl
    # libc resolve correctly (see https://musl.cc).
    STATIC_ENV := PATH="$(MUSL_CROSS_BIN):$$PATH" \
        LIBCLANG_PATH="$(LIBCLANG_PATH)"
    STATIC_RUSTFLAGS := $(RUSTFLAGS) \
        -C linker=$(MUSL_CXX) -C link-arg=-static
else
    STATIC_CARGO_ARGS :=
    STATIC_MSG := [Dynamic]
    IS_STATIC := 0
    STATIC_ENV :=
    STATIC_RUSTFLAGS := $(RUSTFLAGS)
endif

# Env injected into the userspace build command: the static musl build reuses the
# gcc-based musl-cross toolchain; any native (dynamic) build uses the clang
# toolchain so RocksDB's `lto` feature is available.
ifeq ($(IS_STATIC),1)
    USR_ENV := $(STATIC_ENV)
else
    USR_ENV := $(CLANG_ENV)
endif

all: build

# Print a compact artifact summary after a successful build.
# Usage: $(call print_build_banner,<artifact path>,<display name>,<linkage override>)
# The third argument is optional. When omitted, linkage is detected with file/readelf.
define print_build_banner
	@if [ -f "$(1)" ]; then \
		artifact="$(1)"; \
		name="$(2)"; \
		linkage_override="$(3)"; \
		path="$$(readlink -f "$$artifact" 2>/dev/null || realpath "$$artifact" 2>/dev/null || printf '%s' "$$artifact")"; \
		bytes="$$(stat -c '%s' "$$artifact")"; \
		size="$$(numfmt --to=iec-i --suffix=B "$$bytes" 2>/dev/null || printf '%s bytes' "$$bytes")"; \
		sha256="$$(sha256sum "$$artifact" | awk '{print $$1}')"; \
		if [ -n "$$linkage_override" ]; then \
			linkage="$$linkage_override"; \
		else \
			file_info="$$(file -b "$$artifact" 2>/dev/null || true)"; \
			if printf '%s' "$$file_info" | grep -qi 'eBPF' || \
			   readelf -h "$$artifact" 2>/dev/null | grep -qiE 'Machine:.*(BPF|Linux BPF)'; then \
				linkage='eBPF ELF'; \
			elif readelf -l "$$artifact" 2>/dev/null | grep -q 'INTERP'; then \
				linkage='Dynamic'; \
			elif printf '%s' "$$file_info" | grep -qiE 'statically linked|static-pie linked'; then \
				linkage='Static'; \
			elif readelf -h "$$artifact" >/dev/null 2>&1; then \
				linkage='Static'; \
			elif printf '%s' "$$file_info" | grep -qiE 'dynamically linked|shared object'; then \
				linkage='Dynamic'; \
			else \
				linkage='Unknown'; \
			fi; \
		fi; \
		title="✅ Build completed — $$name"; \
		line_exe="🚀 Executable : $$path"; \
		line_size="📦 Size       : $$size"; \
		line_link="🔗 Linkage    : $$linkage"; \
		line_sha="🔐 SHA-256    : $$sha256"; \
		max_width=0; \
		for line in "$$title" "$$line_dir" "$$line_exe" "$$line_size" "$$line_link" "$$line_sha"; do \
			line_width="$$(printf '%s' "$$line" | wc -L | tr -d ' ')"; \
			[ "$$line_width" -gt "$$max_width" ] && max_width="$$line_width"; \
		done; \
		inner_width=$$((max_width + 2)); \
		border="$$(printf '═%.0s' $$(seq 1 "$$inner_width"))"; \
		print_row() { \
			plain="$$1"; \
			colored="$$2"; \
			line_width="$$(printf '%s' "$$plain" | wc -L | tr -d ' ')"; \
			padding=$$((inner_width - line_width - 2)); \
			printf "$(GREEN)║$(RESET) %b%*s $(GREEN)║$(RESET)\n" "$$colored" "$$padding" ""; \
		}; \
		printf "\n$(GREEN)╔%s╗$(RESET)\n" "$$border"; \
		print_row "$$title" "$(BOLD)$$title$(RESET)"; \
		printf "$(GREEN)╠%s╣$(RESET)\n" "$$border"; \
		print_row "$$line_exe"  "🚀 Executable : $(CYAN)$$path$(RESET)"; \
		print_row "$$line_size" "📦 Size       : $(YELLOW)$$size$(RESET)"; \
		print_row "$$line_link" "🔗 Linkage    : $(MAGENTA)$$linkage$(RESET)"; \
		print_row "$$line_sha"  "🔐 SHA-256    : $(BLUE)$$sha256$(RESET)"; \
		printf "$(GREEN)╚%s╝$(RESET)\n\n" "$$border"; \
	fi
endef

## -----------------------------------------------------------------------------
## BUILD TARGETS
## -----------------------------------------------------------------------------

# Build both eBPF kernel program and userspace daemon in release mode
build: build-ebpf build-userspace


# Compile kernel-space eBPF program into ELF bytecode using bpf-linker
build-ebpf:
	@printf "$(CYAN)⚙️  Building eBPF firewall kernel program (target: $(BOLD)$(RED)$(TARGET_BPF)$(RESET)$(CYAN))...$(RESET)\n"
	RUSTFLAGS="" $(CARGO) +$(RUST_NIGHTLY) build \
		--manifest-path=firewall-ebpf/Cargo.toml \
		--target=$(TARGET_BPF) \
		-Z build-std=core \
		--release \
		--target-dir=$(TARGET_DIR)
	$(call print_build_banner,$(TARGET_DIR)/$(TARGET_BPF)/release/firewall-ebpf,eBPF firewall,eBPF ELF)

# Compile userspace firewall daemon with target-cpu=native and optional static linking
build-userspace:
	@printf "$(GREEN)🦀 Building userspace firewall daemon $(BOLD)$(RED)$(STATIC_MSG)$(RESET)$(GREEN) (RUSTFLAGS=\"$(BOLD)$(MAGENTA)$(STATIC_RUSTFLAGS)$(RESET)$(GREEN)\")...$(RESET)\n"
ifeq ($(IS_STATIC),1)
	@rustup target add $(TARGET_STATIC) 2>/dev/null || true
	@if [ ! -x "$(MUSL_CROSS_BIN)/$(MUSL_CXX)" ]; then \
		printf "$(RED)✖️  Missing musl-cross C++ toolchain at '$(MUSL_CROSS_ROOT)'.$(RESET)\n"; \
		printf "$(RED)   Download it from https://musl.cc (x86_64-linux-musl-cross.tgz) and extract to '$(MUSL_CROSS_ROOT)',$(RESET)\n"; \
		printf "$(RED)   or pass make MUSL_CROSS_ROOT=/custom/path. This is required to compile$(RESET)\n"; \
		printf "$(RED)   C++ deps (RocksDB) for the fully static build.$(RESET)\n"; \
		exit 1; \
	fi
endif
	$(USR_ENV) RUSTFLAGS="$(STATIC_RUSTFLAGS)" $(CARGO) build --release --workspace --target-dir=$(TARGET_DIR) $(STATIC_CARGO_ARGS)
ifeq ($(IS_STATIC),1)
	@mkdir -p $(TARGET_DIR)/release
	@cp -f $(TARGET_DIR)/$(TARGET_STATIC)/release/firewall $(TARGET_DIR)/release/firewall 2>/dev/null || true
	@cp -f $(TARGET_DIR)/$(TARGET_STATIC)/release/test_traffic $(TARGET_DIR)/release/test_traffic 2>/dev/null || true
	@cp -f $(TARGET_DIR)/$(TARGET_STATIC)/release/benchmark $(TARGET_DIR)/release/benchmark 2>/dev/null || true
endif
	$(call print_build_banner,$(TARGET_DIR)/release/firewall,firewall,$(if $(filter 1,$(IS_STATIC)),Static,Dynamic))



# Run firewall daemon with sudo (eBPF and XDP require CAP_NET_ADMIN / CAP_BPF / root)
run: build
	@printf "$(CYAN)🛡️  Running firewall daemon on interface '$(BOLD)$(RED)lo$(RESET)$(CYAN)'...$(RESET)\n"
	sudo FIREHOL_IGNORE_IP=127.0.0.1 $(TARGET_DIR)/release/firewall --iface lo --rules rules/blocklist.txt --rules rules/blocklist_v6.txt --rules rules/cidr_ranges.txt --watch --bpf-path $(TARGET_DIR)/$(TARGET_BPF)/release/firewall-ebpf

## -----------------------------------------------------------------------------
## QUALITY & TESTING
## -----------------------------------------------------------------------------

# Run unit and integration tests
test:
	@printf "$(CYAN)🧪 Running all test suites (workspace & eBPF)...$(RESET)\n"
	$(CLANG_ENV) $(CARGO) test --workspace --all-targets
	$(CLANG_ENV) $(CARGO) test --manifest-path=firewall-ebpf/Cargo.toml
	$(call print_build_banner,$(TARGET_DIR)/release/test_traffic,test_traffic,$(if $(filter 1,$(IS_STATIC)),Static,Dynamic))

# Generate detailed HTML code coverage report using grcov and update README badge
code-coverage:
	@./scripts/generate_coverage.sh

# Run Criterion microbenchmarks locally
bench-micro:
	@printf "$(MAGENTA)⚡ Running local Criterion performance microbenchmarks (workspace & eBPF)...$(RESET)\n"
	$(CLANG_ENV) $(CARGO) bench --workspace --benches -- --save-baseline bench-baseline
	$(CLANG_ENV) $(CARGO) bench --manifest-path=firewall-ebpf/Cargo.toml --benches -- --save-baseline bench-baseline
	$(call print_build_banner,$(TARGET_DIR)/release/benchmark,benchmark,$(if $(filter 1,$(IS_STATIC)),Static,Dynamic))

# Check codebase with Clippy
clippy:
	@printf "$(BLUE)🔍 Running Clippy linter...$(RESET)\n"
	$(CLANG_ENV) $(CARGO) clippy --all-targets -- -D warnings

# Format source files
fmt:
	@printf "$(GREEN)✨ Formatting source code...$(RESET)\n"
	$(CARGO) fmt --all

# Check formatting without modifying files
fmt-check:
	@printf "$(CYAN)🎨 Checking code formatting...$(RESET)\n"
	$(CARGO) fmt --all -- --check

# Clean all build artifacts
clean:
	@printf "$(YELLOW)🧹 Cleaning build artifacts...$(RESET)\n"
	$(CARGO) clean
	$(CARGO) clean --manifest-path=firewall-ebpf/Cargo.toml
	@rm -rf coverage target/coverage-profraw

## -----------------------------------------------------------------------------
## DOCKER & CONTAINER ENVIRONMENT
## -----------------------------------------------------------------------------

docker-build:
	@printf "$(BLUE)🐳 Building Docker container with eBPF capabilities and traffic tools...$(RESET)\n"
	$(DOCKER_COMPOSE) build

docker-up: docker-build
	@printf "$(GREEN)🚀 Starting Docker compose firewall test environment with Prometheus & Grafana...$(RESET)\n"
	$(DOCKER_COMPOSE) up -d
	@printf "$(CYAN)📊 Services available:$(RESET)\n"
	@printf "   $(BOLD)🛡️  Firewall Metrics$(RESET) : http://localhost:9100/metrics\n"
	@printf "   $(BOLD)📈 Prometheus UI$(RESET)    : http://localhost:9090\n"
	@printf "   $(BOLD)📊 Grafana Dashboard$(RESET): http://localhost:3000 (admin / admin)\n"

docker-down:
	@printf "$(RED)🛑 Stopping Docker compose environment...$(RESET)\n"
	$(DOCKER_COMPOSE) down

logs: docker-logs-follow

docker-logs:
	@printf "$(BLUE)📜 Displaying Docker compose logs...$(RESET)\n"
	$(DOCKER_COMPOSE) logs

docker-logs-follow:
	@printf "$(BLUE)📜 Streaming Docker compose logs in real-time...$(RESET)\n"
	$(DOCKER_COMPOSE) logs -f

## -----------------------------------------------------------------------------
## TRAFFIC GENERATION & BENCHMARKING
## -----------------------------------------------------------------------------

# Run multi-protocol traffic verification test inside the traffic-generator container
test-traffic: docker-up
	@printf "$(CYAN)🛡️  Running multi-protocol traffic verification test...$(RESET)\n"
	@printf "$(GREEN)🔊 Verifying and enabling firewall drop logs...$(RESET)\n"
	@curl -s -X POST "http://localhost:9100/telemetry/drop-logs?enabled=true" >/dev/null 2>&1 || true
	@$(DOCKER_COMPOSE) exec -e TERM=xterm-256color traffic-generator test_traffic $(TRAFFIC_ARGS)
	@printf "\n$(CYAN)📜 Verifying firewall logs (recent blocked packet events):$(RESET)\n"
	@$(DOCKER_COMPOSE) logs --tail=15 firewall

# Run high-performance multi-threaded firewall benchmark inside the traffic-generator container
bench-traffic: docker-up
	@printf "$(CYAN)🚀 Running high-performance firewall benchmark...$(RESET)\n"
	@$(DOCKER_COMPOSE) exec -e TERM=xterm-256color traffic-generator benchmark $(BENCH_ARGS)

# Default benchmark alias
bench: bench-micro
