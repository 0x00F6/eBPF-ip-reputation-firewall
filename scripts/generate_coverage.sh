#!/usr/bin/env bash
# ==============================================================================
# eBPF IP Reputation Firewall - Automated Code Coverage Generator
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# Ensure ~/.cargo/bin is in PATH for grcov
export PATH="${HOME}/.cargo/bin:${PATH}"

# Colors for terminal output
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
BOLD='\033[1m'
RESET='\033[0m'

if [[ "${NO_COLOR:-0}" != "0" && "${NO_COLOR:-0}" != "false" ]]; then
    CYAN=''
    GREEN=''
    YELLOW=''
    RED=''
    BLUE=''
    MAGENTA=''
    BOLD=''
    RESET=''
fi

printf "${CYAN}🧪 Preparing Code Coverage generation for eBPF IP Reputation Firewall...${RESET}\n"

# ------------------------------------------------------------------------------
# 1. Check and auto-install prerequisites (llvm-tools-preview & grcov)
# ------------------------------------------------------------------------------
if ! rustup component list --installed | grep -q "llvm-tools"; then
    printf "${YELLOW}⚡ Installing 'llvm-tools-preview' component via rustup...${RESET}\n"
    rustup component add llvm-tools-preview
fi

if ! command -v grcov >/dev/null 2>&1; then
    printf "${YELLOW}⚡ 'grcov' not found in PATH. Attempting automatic installation...${RESET}\n"
    ARCH="$(uname -m)"
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    GRCOV_INSTALLED=0

    if [[ "${OS}" == "linux" && "${ARCH}" == "x86_64" ]]; then
        GRCOV_URL="https://github.com/mozilla/grcov/releases/download/v0.10.8/grcov-x86_64-unknown-linux-musl.tar.bz2"
        TMP_ARCHIVE="/tmp/grcov-$$.tar.bz2"
        if curl -fsSL "${GRCOV_URL}" -o "${TMP_ARCHIVE}" 2>/dev/null; then
            mkdir -p "${HOME}/.cargo/bin"
            tar -xjf "${TMP_ARCHIVE}" -C /tmp
            mv /tmp/grcov "${HOME}/.cargo/bin/grcov"
            chmod +x "${HOME}/.cargo/bin/grcov"
            rm -f "${TMP_ARCHIVE}"
            GRCOV_INSTALLED=1
            printf "${GREEN}✔ Successfully installed prebuilt grcov to ~/.cargo/bin/grcov${RESET}\n"
        fi
    fi

    if [[ "${GRCOV_INSTALLED}" -eq 0 ]]; then
        printf "${YELLOW}Compiling grcov via cargo install...${RESET}\n"
        cargo install grcov --locked
    fi
fi

if ! command -v grcov >/dev/null 2>&1; then
    printf "${RED}❌ Failed to install grcov. Please install it manually: cargo install grcov${RESET}\n" >&2
    exit 1
fi

GRCOV_VERSION="$(grcov --version 2>&1 | head -n 1)"
printf "${GREEN}✔ Using ${GRCOV_VERSION}${RESET}\n"

# ------------------------------------------------------------------------------
# 2. Clang and C/C++ environment detection (required for RocksDB LTO)
# ------------------------------------------------------------------------------
CC="${CC:-clang}"
CXX="${CXX:-clang++}"
GCC_VER="$(gcc -dumpfullversion 2>/dev/null | cut -d. -f1 || echo 13)"
GCC_MACH="$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
STDCPP_INCS="-isystem /usr/include/c++/${GCC_VER} -isystem /usr/include/${GCC_MACH}/c++/${GCC_VER} -isystem /usr/include/c++/${GCC_VER}/backward"

export CC="${CC}"
export CXX="${CXX}"
export CFLAGS="${STDCPP_INCS} ${CFLAGS:-}"
export CXXFLAGS="${STDCPP_INCS} ${CXXFLAGS:-}"

# ------------------------------------------------------------------------------
# 3. Clean stale profiling data
# ------------------------------------------------------------------------------
COVERAGE_DIR="${ROOT_DIR}/coverage"
PROFRAW_DIR="${ROOT_DIR}/target/coverage-profraw"

printf "${YELLOW}🧹 Cleaning previous profiling data and coverage reports...${RESET}\n"
rm -rf "${COVERAGE_DIR}"
rm -rf "${PROFRAW_DIR}"
find "${ROOT_DIR}/target" -name "*.profraw" -delete 2>/dev/null || true
mkdir -p "${COVERAGE_DIR}"
mkdir -p "${PROFRAW_DIR}"

# ------------------------------------------------------------------------------
# 4. Compile and run test suites with LLVM source-based code coverage
# ------------------------------------------------------------------------------
printf "${CYAN}🚀 Running test suites with LLVM coverage instrumentation (-C instrument-coverage)...${RESET}\n"

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=4
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="${PROFRAW_DIR}/cargo-test-%p-%m.profraw"

printf "${BLUE}  ▶ [1/3] Workspace tests (unit, integration, benchmarks, traffic tools)...${RESET}\n"
cargo test --workspace --all-targets

printf "${BLUE}  ▶ [2/3] eBPF kernel program tests (packet parser, headers, protocols)...${RESET}\n"
cargo test --manifest-path=firewall-ebpf/Cargo.toml --target-dir target

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    printf "${BLUE}  ▶ [3/3] BPF kernel & daemon integration tests (isolated Docker container)...${RESET}\n"
    cargo test --test kernel_integration --test daemon_integration --config 'target.x86_64-unknown-linux-gnu.runner = "scripts/run_kernel_test.sh"' -- --ignored
fi

# Count generated .profraw files
PROFRAW_COUNT="$(find "${PROFRAW_DIR}" -name "*.profraw" 2>/dev/null | wc -l)"
printf "${GREEN}✔ Generated ${PROFRAW_COUNT} LLVM profraw trace file(s).${RESET}\n"

if [[ "${PROFRAW_COUNT}" -eq 0 ]]; then
    printf "${RED}❌ No .profraw files were produced by the test suites.${RESET}\n" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 5. Run grcov to generate detailed HTML report & coverage.json
# ------------------------------------------------------------------------------
printf "${CYAN}📑 Generating detailed HTML coverage report with grcov...${RESET}\n"

grcov "${PROFRAW_DIR}" \
    --binary-path "${ROOT_DIR}/target/debug/" \
    -s "${ROOT_DIR}" \
    -t html \
    --branch \
    --ignore-not-existing \
    --ignore "/*" \
    --ignore "tests/*" \
    --ignore "*/tests/*" \
    --ignore "benches/*" \
    --ignore "*/benches/*" \
    --ignore "build.rs" \
    --ignore "xtask/*" \
    -o "${COVERAGE_DIR}"

# If grcov placed output in coverage/html, ensure coverage/index.html is available
HTML_INDEX="${COVERAGE_DIR}/html/index.html"
if [[ ! -f "${HTML_INDEX}" && -f "${COVERAGE_DIR}/index.html" ]]; then
    HTML_INDEX="${COVERAGE_DIR}/index.html"
elif [[ -f "${HTML_INDEX}" && ! -f "${COVERAGE_DIR}/index.html" ]]; then
    ln -sf html/index.html "${COVERAGE_DIR}/index.html"
fi

# ------------------------------------------------------------------------------
# 6. Extract overall coverage percentage and compute badge properties
# ------------------------------------------------------------------------------
JSON_FILE="${COVERAGE_DIR}/html/coverage.json"
if [[ ! -f "${JSON_FILE}" && -f "${COVERAGE_DIR}/coverage.json" ]]; then
    JSON_FILE="${COVERAGE_DIR}/coverage.json"
fi

if [[ ! -f "${JSON_FILE}" ]]; then
    printf "${RED}❌ Coverage JSON output not found at ${JSON_FILE}.${RESET}\n" >&2
    exit 1
fi

RAW_COVERAGE="$(grep -o '"message":"[^"]*"' "${JSON_FILE}" | cut -d'"' -f4 | tr -d '%')"
if [[ -z "${RAW_COVERAGE}" ]]; then
    printf "${RED}❌ Could not parse coverage percentage from ${JSON_FILE}.${RESET}\n" >&2
    exit 1
fi

# Calculate rounded percentage and badge color
COVERAGE_INT="$(awk -v cov="${RAW_COVERAGE}" 'BEGIN { printf "%.0f", cov }')"
COVERAGE_COLOR="$(awk -v cov="${RAW_COVERAGE}" 'BEGIN {
    if (cov >= 80.0) print "brightgreen"
    else if (cov >= 70.0) print "green"
    else if (cov >= 60.0) print "yellow"
    else if (cov >= 50.0) print "orange"
    else print "red"
}')"

printf "${GREEN}✔ Calculated total code coverage: ${BOLD}${RAW_COVERAGE}%%${RESET} (Badge: ${COVERAGE_INT}%%, color: ${COVERAGE_COLOR})\n"

# ------------------------------------------------------------------------------
# 7. Dynamically update or insert coverage badge in README.md
# ------------------------------------------------------------------------------
README_FILE="${ROOT_DIR}/README.md"
if [[ -f "${README_FILE}" ]]; then
    BADGE_MARKDOWN="[![Code Coverage](https://img.shields.io/badge/coverage-${COVERAGE_INT}%25-${COVERAGE_COLOR}.svg)](coverage/html/index.html)"
    
    if grep -q '\[!\[Code Coverage\]' "${README_FILE}"; then
        # Replace existing badge in README.md
        sed -i -E "s|\[\!\[Code Coverage\]\(https://img\.shields\.io/badge/coverage-[^)]*\)\]\([^)]*\)|${BADGE_MARKDOWN}|g" "${README_FILE}"
        printf "${GREEN}✔ Updated existing Code Coverage badge in README.md${RESET}\n"
    else
        # Insert badge immediately after the eBPF badge
        sed -i "/\[\!\[eBPF\]/a ${BADGE_MARKDOWN}" "${README_FILE}"
        printf "${GREEN}✔ Inserted new Code Coverage badge into README.md${RESET}\n"
    fi
fi

# ------------------------------------------------------------------------------
# 8. Print completion summary banner
# ------------------------------------------------------------------------------
REPORT_REL_PATH="coverage/html/index.html"
[ -f "${COVERAGE_DIR}/html/index.html" ] || REPORT_REL_PATH="coverage/index.html"

TITLE="✅ Code Coverage completed — Overall: ${RAW_COVERAGE}% (${COVERAGE_INT}%)"
LINE_REPORT="📄 HTML Report : ${REPORT_REL_PATH}"
LINE_BADGE="🏷️ Badge       : coverage-${COVERAGE_INT}%-${COVERAGE_COLOR} (README.md updated)"
LINE_PROFRAW="📊 Profraw     : target/coverage-profraw (${PROFRAW_COUNT} files)"

MAX_WIDTH=0
for line in "${TITLE}" "${LINE_REPORT}" "${LINE_BADGE}" "${LINE_PROFRAW}"; do
    LINE_LEN="$(printf '%s' "${line}" | wc -L | tr -d ' ')"
    [[ "${LINE_LEN}" -gt "${MAX_WIDTH}" ]] && MAX_WIDTH="${LINE_LEN}"
done
INNER_WIDTH=$((MAX_WIDTH + 2))
BORDER="$(printf '═%.0s' $(seq 1 "${INNER_WIDTH}"))"

print_row() {
    local plain="$1"
    local colored="$2"
    local line_len="$(printf '%s' "${plain}" | wc -L | tr -d ' ')"
    local padding=$((INNER_WIDTH - line_len - 2))
    printf "${GREEN}║${RESET} %b%*s ${GREEN}║${RESET}\n" "${colored}" "${padding}" ""
}

printf "\n${GREEN}╔%s╗${RESET}\n" "${BORDER}"
print_row "${TITLE}" "${BOLD}${TITLE}${RESET}"
printf "${GREEN}╠%s╣${RESET}\n" "${BORDER}"
print_row "${LINE_REPORT}" "📄 HTML Report : ${CYAN}${REPORT_REL_PATH}${RESET}"
print_row "${LINE_BADGE}"  "🏷️ Badge       : ${YELLOW}coverage-${COVERAGE_INT}%-${COVERAGE_COLOR}${RESET} (${MAGENTA}README.md updated${RESET})"
print_row "${LINE_PROFRAW}" "📊 Profraw     : ${BLUE}target/coverage-profraw${RESET} (${PROFRAW_COUNT} files)"
printf "${GREEN}╚%s╝${RESET}\n\n" "${BORDER}"
