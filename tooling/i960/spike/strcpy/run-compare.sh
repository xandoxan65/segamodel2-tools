#!/usr/bin/env bash
# Delegates to decomp/scripts/compare_libc_strcpy.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec bash "$ROOT/decomp/scripts/compare_libc_strcpy.sh"
