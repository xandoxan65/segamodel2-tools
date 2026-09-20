#!/usr/bin/env bash
# Push decomp/ to its own remote and register it as a submodule in segamod2.
#
# Usage:
#   bash tooling/setup_decomp_subrepo.sh git@github.com:YOU/segamod2-decomp.git
#
# Prerequisite: empty remote repo (no README/license commits on main).
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <decomp-remote-url>" >&2
  echo "example: $0 git@github.com:YOU/segamod2-decomp.git" >&2
  exit 1
fi

REMOTE_URL="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DECOMP="$REPO_ROOT/decomp"

if [[ ! -d "$DECOMP" ]]; then
  echo "error: missing $DECOMP" >&2
  exit 1
fi

if [[ ! -d "$DECOMP/.git" ]]; then
  echo "initializing git repo in decomp/"
  git -C "$DECOMP" init -b main
  git -C "$DECOMP" add -A
  git -C "$DECOMP" commit -m "Initial decomp corpus"
fi

if git -C "$DECOMP" remote get-url origin >/dev/null 2>&1; then
  git -C "$DECOMP" remote set-url origin "$REMOTE_URL"
else
  git -C "$DECOMP" remote add origin "$REMOTE_URL"
fi

echo "pushing decomp/ → $REMOTE_URL"
git -C "$DECOMP" push -u origin main

cd "$REPO_ROOT"

if [[ -f .gitmodules ]] && git config -f .gitmodules --get submodule.decomp.url >/dev/null 2>&1; then
  echo "submodule decomp already registered; updating gitlink"
  git submodule sync decomp
else
  echo "registering decomp/ as submodule in parent repo"
  git rm -r --cached decomp 2>/dev/null || true
  git submodule add "$REMOTE_URL" decomp
fi

git add .gitmodules decomp
echo
echo "Done. Review and commit in the parent repo:"
echo "  git status"
echo "  git commit -m \"Track decomp corpus as submodule\""
