#!/usr/bin/env bash
# Run a command in the decomp container (segamod2 repo mounted at /src).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=container_env.sh
source "${SCRIPT_DIR}/container_env.sh"

export WORKSPACE_ROOT="$(segamod2_repo_root)"
export I960_DECOMP_IMAGE="${I960_DECOMP_IMAGE:-${DECOMP_IMAGE:-segamod2-decomp:12.1.2}}"
DECOMP_DIR="$(segamod2_decomp_dir)"
exec "${DECOMP_DIR}/container/run-decomp.sh" "$@"
