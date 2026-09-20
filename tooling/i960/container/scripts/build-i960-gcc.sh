#!/usr/bin/env bash
# Build i960-elf GCC in the decomp container — delegates to decomp/toolchain script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
TOOLCHAIN_SCRIPT="${REPO_ROOT}/decomp/toolchain/build-i960-toolchain.sh"

if [[ ! -x "${TOOLCHAIN_SCRIPT}" ]]; then
  echo "error: missing ${TOOLCHAIN_SCRIPT}" >&2
  echo "init submodule: git submodule update --init decomp" >&2
  exit 1
fi

export I960_TOOLCHAIN_PREFIX="${TOOLCHAIN_PREFIX:-${I960_TOOLCHAIN_PREFIX:-/opt/i960-elf}}"
exec "${TOOLCHAIN_SCRIPT}" --gcc-only "$@"
