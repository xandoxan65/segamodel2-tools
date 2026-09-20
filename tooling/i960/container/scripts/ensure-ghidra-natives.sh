#!/usr/bin/env bash
# Fast no-op when prebuilt natives exist; otherwise compile from bundled C++ sources.
set -euo pipefail

LIB="${SEGAMOD2_CONTAINER_LIB:-/usr/local/lib/segamod2}"
exec "$LIB/build-ghidra-natives.sh" "$@"
