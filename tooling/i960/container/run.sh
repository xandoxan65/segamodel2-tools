#!/usr/bin/env bash
# Run a command inside the i960 toolchain container with the repo mounted at /src.
# Binutils-only image by default; set I960_DECOMP_IMAGE to use the full decomp stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=container_env.sh
source "$SCRIPT_DIR/container_env.sh"

if [[ -n "${I960_DECOMP_IMAGE:-${I960_GHIDRA_IMAGE:-}}" ]]; then
  exec "$SCRIPT_DIR/run-decomp.sh" "$@"
fi

IMAGE="${I960_TOOLCHAIN_IMAGE:-segamod2/i960-toolchain:binutils-2.30}"
ENGINE="$(segamod2_container_engine)"
ROOT="$(segamod2_repo_root)"

exec "$ENGINE" run --rm \
  -v "$ROOT:/src" \
  -w /src \
  --entrypoint "" \
  "$IMAGE" \
  "$@"
