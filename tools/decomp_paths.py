"""Repository layout helpers for standalone decomp vs segamod2 submodule."""

from __future__ import annotations

import os
from pathlib import Path


def decomp_root() -> Path:
    env = os.environ.get("DECOMP_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    # tools/decomp_paths.py → decomp/
    return Path(__file__).resolve().parents[1]


def monorepo_root() -> Path | None:
    """Parent segamod2 checkout when decomp is a submodule."""
    parent = decomp_root().parent
    if (parent / "build").is_file() and (parent / "tools" / "decomp" / "build.py").is_file():
        return parent.resolve()
    return None


def repo_root() -> Path:
    return monorepo_root() or decomp_root()


def disasm_dir() -> Path:
    return decomp_root() / "disasm"


def out_dir(name: str) -> Path:
    return decomp_root() / "out" / name


def section_map_path(name: str) -> Path:
    generated = out_dir("i960") / name
    if generated.is_file():
        return generated
    return decomp_root() / "data" / "section_maps" / name


def default_rom_dir() -> Path:
    root = decomp_root()
    env = os.environ.get("SEGAMOD2_ROM_DIR") or os.environ.get("DECOMP_ROM_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_dir() and any(p.iterdir()):
            return p
        raise FileNotFoundError(f"ROM directory empty or missing: {p}")
    for candidate in (root / "ROMS" / "srallyc-b", root / "ROMS" / "srallyc-c"):
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate.resolve()
    mono = monorepo_root()
    if mono is not None:
        for candidate in (mono / "ROMS" / "srallyc-b", mono / "ROMS" / "srallyc-c"):
            if candidate.is_dir() and any(candidate.iterdir()):
                return candidate.resolve()
    raise FileNotFoundError(
        f"No ROM dumps found. Copy MAME srallyc-b set into {root / 'ROMS' / 'srallyc-b'}/"
    )
