"""Decomp repo paths for compile / lift pipelines (standalone decomp root)."""

from __future__ import annotations

from pathlib import Path

from tools.decomp_paths import decomp_root

DECOMP_ROOT = decomp_root()
REPO_ROOT = DECOMP_ROOT  # legacy name in compile modules


def repo_rel(path: Path) -> str:
    resolved = path if path.is_absolute() else DECOMP_ROOT / path
    return resolved.resolve().relative_to(DECOMP_ROOT.resolve()).as_posix()


def resolve_in_repo(path: Path) -> Path:
    return path if path.is_absolute() else DECOMP_ROOT / path
