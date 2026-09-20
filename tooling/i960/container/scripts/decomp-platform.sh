#!/usr/bin/env bash
# Shared platform helpers for the segamod2 decomp container.
set -euo pipefail

decomp_dpkg_arch() {
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --print-architecture
    return 0
  fi
  uname -m
}

decomp_ghidra_platform() {
  local arch
  arch="$(decomp_dpkg_arch)"
  case "$arch" in
    arm64|aarch64) echo linux_arm_64 ;;
    amd64|x86_64) echo linux_x86_64 ;;
    *)
      echo "unsupported container arch for ghidra natives: $arch" >&2
      return 1
      ;;
  esac
}

decomp_ghidra_native_dir() {
  local root="${GHIDRA_ROOT:-/opt/ghidra}"
  echo "${root}/Ghidra/Features/Decompiler/os/$(decomp_ghidra_platform)"
}
