#!/usr/bin/env bash
# Build decomp container via standalone decomp submodule.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=container_env.sh
source "${SCRIPT_DIR}/container_env.sh"

DECOMP_DIR="$(segamod2_decomp_dir)"
export I960_DECOMP_IMAGE="${I960_DECOMP_IMAGE:-${DECOMP_IMAGE:-segamod2-decomp:12.1.2}}"
exec "${DECOMP_DIR}/container/build-image.sh" "$@"
