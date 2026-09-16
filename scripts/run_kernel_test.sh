#!/usr/bin/env bash
# Cargo runner for opt-in BPF integration tests. Never uses the host network.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile_dir="${root_dir}/target/coverage-profraw"
mkdir -p "${profile_dir}"
# Native Cargo test binaries need the same glibc and shared libraries as the host.
# The image supplies only /bin/sh, ip and ping; no image pull is performed implicitly.
image="${FIREWALL_TEST_IMAGE:-ebpf-ip-reputation-firewall-firewall:latest}"
docker image inspect "${image}" >/dev/null
exec docker run --rm --network none \
    --cap-add BPF --cap-add PERFMON --cap-add NET_ADMIN --cap-add SYS_RESOURCE \
    --security-opt seccomp=unconfined \
    --mount "type=bind,source=${root_dir},target=${root_dir},readonly" \
    --mount "type=bind,source=${profile_dir},target=${profile_dir}" \
    --mount type=bind,source=/usr/lib/x86_64-linux-gnu,target=/usr/lib/x86_64-linux-gnu,readonly \
    --workdir "${root_dir}" \
    --env "LLVM_PROFILE_FILE=${profile_dir}/kernel-%p-%m.profraw" \
    --env RUST_TEST_THREADS=1 \
    --env "FIREWALL_TEST_UID=$(id -u)" --env "FIREWALL_TEST_GID=$(id -g)" \
    --env "FIREWALL_TEST_PROFILE_DIR=${profile_dir}" \
    --entrypoint /bin/sh "${image}" -c '
        unset FIREWALL_RULES FIREWALL_IFACE FIREWALL_FIREHOL NO_COLOR RUST_LOG
        "$@"; status=$?
        chown -R "$FIREWALL_TEST_UID:$FIREWALL_TEST_GID" "$FIREWALL_TEST_PROFILE_DIR"
        exit "$status"
    ' kernel-test "$@"
