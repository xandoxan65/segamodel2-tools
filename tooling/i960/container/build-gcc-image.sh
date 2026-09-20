#!/usr/bin/env bash
# Build segamod2 i960 toolchain image with GCC 2.95.3 + newlib 1.8.2.
# For Ghidra + decomp tooling, use build-decomp-image.sh instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${I960_TOOLCHAIN_IMAGE:-segamod2/i960-toolchain:gcc-2.95.3}"
TARGET="${I960_BUILD_TARGET:-full}"

exec "$SCRIPT_DIR/build-image.sh" --target "$TARGET" --image "$IMAGE" "$@"
