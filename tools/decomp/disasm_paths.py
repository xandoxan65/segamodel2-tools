"""Canonical disassembly directory layout under decomp/."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

DECOMP_DISASM = Path("decomp/disasm")
LEGACY_DISASM = Path("out/i960/disasm")

MAINCPU_SUBDIR = "maincpu"
CLUSTERS_SUBDIR = "clusters"
PALETTE_SUBDIR = "palette"

SLICE_RE = re.compile(r"^maincpu_([0-9a-f]+)_([0-9a-f]+)\.asm$", re.I)
CLUSTER_RE = re.compile(r"^geo_cluster_\d+_0x([0-9a-f]+)\.asm$", re.I)


def classify_filename(name: str) -> str:
    if name.startswith("geo_cluster_"):
        return CLUSTERS_SUBDIR
    if name.startswith("palette"):
        return PALETTE_SUBDIR
    return MAINCPU_SUBDIR


def parse_slice_bounds(name: str) -> tuple[int, int] | None:
    m = SLICE_RE.match(name)
    if m:
        start = int(m.group(1), 16)
        length = int(m.group(2), 16)
        return start, start + length
    m = CLUSTER_RE.match(name)
    if m:
        start = int(m.group(1), 16)
        return start, start  # end filled from scan_report or listing
    return None


def iter_asm_files(disasm_root: Path) -> list[Path]:
    if not disasm_root.is_dir():
        return []
    return sorted(p for p in disasm_root.rglob("*.asm") if p.is_file())


def migrate_legacy_disasm(
    *,
    legacy: Path = LEGACY_DISASM,
    dest: Path = DECOMP_DISASM,
    move: bool = True,
) -> list[str]:
    """Move/copy flat and nested slices from out/i960/disasm into decomp/disasm/."""
    if not legacy.is_dir():
        return []

    moved: list[str] = []
    op = shutil.move if move else shutil.copy2

    for path in sorted(legacy.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in (".asm", ".dbg"):
            continue
        subdir = classify_filename(path.name)
        target = dest / subdir / path.name
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        op(str(path), str(target))
        moved.append(f"{path.relative_to(legacy)} → {target.relative_to(dest)}")

    # Remove empty nested dirs (MAME quirk: maincpu_*.asm/ folders).
    for path in sorted(legacy.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()

    if legacy.is_dir() and not any(legacy.iterdir()):
        legacy.rmdir()

    return moved
