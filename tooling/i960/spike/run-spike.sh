#!/usr/bin/env bash
# Feasibility spike: assemble ret.s and disassemble with objdump.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONTAINER="$REPO_ROOT/tooling/i960/container/run.sh"
ASM_REL="tooling/i960/spike/ret.s"
OUT_REL="tooling/i960/spike/ret.o"

echo "==> i960-elf-as -AKB"
"$CONTAINER" i960-elf-as -AKB -o "$OUT_REL" "$ASM_REL"

echo "==> i960-elf-objdump -d"
"$CONTAINER" i960-elf-objdump -d "$OUT_REL"

echo "==> file"
"$CONTAINER" file "$OUT_REL"

echo "spike ok"
