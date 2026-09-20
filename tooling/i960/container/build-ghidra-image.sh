#!/usr/bin/env bash
# Build segamod2 container with i960 toolchain + GCC + Ghidra headless.
# Prefer build-decomp-image.sh — this wrapper keeps the old image tag.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export I960_DECOMP_IMAGE="${I960_DECOMP_IMAGE:-${I960_GHIDRA_IMAGE:-segamod2/i960-toolchain:ghidra-12.1.2}}"
exec "$SCRIPT_DIR/build-decomp-image.sh" "$@"
