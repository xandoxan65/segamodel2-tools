#!/usr/bin/env bash
# Shared settings when segamod2 invokes the decomp container submodule.
set -euo pipefail

segamod2_find_root() {
  if [[ -n "${SEGAMOD2_ROOT:-}" ]]; then
    echo "${SEGAMOD2_ROOT}"
    return 0
  fi
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [[ "${dir}" != "/" ]]; do
    if [[ -f "${dir}/tooling/i960/container/Dockerfile" || -d "${dir}/decomp/container" ]]; then
      echo "${dir}"
      return 0
    fi
    dir="$(dirname "${dir}")"
  done
  echo "error: segamod2 root not found (set SEGAMOD2_ROOT)" >&2
  return 1
}

segamod2_decomp_dir() {
  local root
  root="$(segamod2_find_root)"
  if [[ -d "${root}/decomp/container" ]]; then
    echo "${root}/decomp"
    return 0
  fi
  echo "error: decomp submodule missing at ${root}/decomp" >&2
  return 1
}

segamod2_repo_root() {
  segamod2_find_root
}

segamod2_decomp_image() {
  echo "${I960_DECOMP_IMAGE:-${DECOMP_IMAGE:-segamod2-decomp:12.1.2}}"
}

segamod2_toolchain_image() {
  echo "${I960_TOOLCHAIN_IMAGE:-$(segamod2_decomp_image)}"
}

# Default i960-elf-gcc flags for C compiles in decomp (override with I960_GCC_FLAGS).
export I960_GCC_FLAGS="${I960_GCC_FLAGS:--O2 -mkb}"
