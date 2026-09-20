#!/usr/bin/env bash
# Backward-compatible wrapper — use run-decomp.sh for the unified decomp container.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export I960_DECOMP_IMAGE="${I960_DECOMP_IMAGE:-${I960_GHIDRA_IMAGE:-segamod2/i960-decomp:12.1.2}}"
exec "$SCRIPT_DIR/run-decomp.sh" "$@"
