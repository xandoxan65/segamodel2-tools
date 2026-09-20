#!/usr/bin/env bash
# Install the community i960 processor module into Homebrew Ghidra.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_SRC="$ROOT/tooling/ghidra_i960"
GHIDRA_ROOT="${GHIDRA_ROOT:-/opt/homebrew/Cellar/ghidra/12.1.2/libexec}"
DEST="$GHIDRA_ROOT/Ghidra/Processors/i960"

if [[ ! -d "$MODULE_SRC/data/languages" ]]; then
  echo "Missing $MODULE_SRC — run: git clone https://github.com/mumbel/ghidra_i960.git tooling/ghidra_i960"
  exit 1
fi

if [[ ! -d "$GHIDRA_ROOT/Ghidra/Processors" ]]; then
  echo "Ghidra not found at $GHIDRA_ROOT — install with: brew install ghidra"
  exit 1
fi

rm -rf "$DEST"
cp -R "$MODULE_SRC" "$DEST"
echo "Installed i960 processor module to $DEST"
echo "Launch Ghidra: ghidraRun  (or open /opt/homebrew/bin/ghidraRun)"
