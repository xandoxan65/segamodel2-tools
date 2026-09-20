"""MAME i960dasm frontend for liftkit (static disasm only — no runtime capture)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def find_mame() -> str:
    for candidate in ("/opt/homebrew/bin/mame", "/opt/local/bin/mame", shutil.which("mame")):
        if candidate and Path(candidate).is_file():
            return candidate
    raise FileNotFoundError("mame not found — install with: brew install mame")


def resolve_rom_dir(explicit: Path | str | None = None, *, project: Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    for key in ("SEGAMOD2_ROM_DIR", "DECOMP_ROM_DIR", "LIFTKIT_ROM_DIR"):
        env = os.environ.get(key)
        if env:
            p = Path(env).expanduser().resolve()
            if p.is_dir():
                return p
    roots: list[Path] = []
    if project is not None:
        roots.append(project)
        roots.append(project.parent)
    roots.append(Path.cwd())
    for root in roots:
        for name in ("srallyc-b", "srallycb", "srallyc-c"):
            cand = root / "ROMS" / name
            if cand.is_dir() and any(cand.iterdir()):
                return cand.resolve()
    raise FileNotFoundError(
        "ROM directory not found. Pass --rom-dir or set SEGAMOD2_ROM_DIR / LIFTKIT_ROM_DIR."
    )


def mame_rompath(rom_dir: Path) -> Path:
    """MAME expects $ROMPATH/<gamename>/ — ensure srallycb alias exists."""
    rom_dir = rom_dir.resolve()
    if rom_dir.name in ("srallycb", "srallyc-b", "srallyc"):
        parent = rom_dir.parent
        link = parent / "srallycb"
        if rom_dir.name != "srallycb" and not link.exists():
            link.symlink_to(rom_dir.name)
        return parent
    return rom_dir


def run_mame_dasm(
    *,
    rom_dir: Path,
    out_asm: Path,
    address: int,
    length: int,
    mame_bin: str | None = None,
    game: str = "srallycb",
) -> Path:
    """Write a MAME listing for maincpu [address, address+length)."""
    mame_bin = mame_bin or find_mame()
    out_asm = out_asm.resolve()
    out_asm.parent.mkdir(parents=True, exist_ok=True)
    dbg = out_asm.with_suffix(".dbg")
    dbg.write_text(
        f"dasm {out_asm},{address:x},{length:x},1,:maincpu\nquit\n",
        encoding="utf-8",
    )
    cmd = [
        mame_bin,
        game,
        "-rompath",
        str(mame_rompath(rom_dir)),
        "-debug",
        "-debugscript",
        str(dbg),
        "-seconds_to_run",
        "1",
        "-sound",
        "none",
        "-nothrottle",
        "-skip_gameinfo",
    ]
    subprocess.run(cmd, check=True)
    if not out_asm.is_file():
        raise RuntimeError(f"MAME did not produce {out_asm}")
    return out_asm


def disasm_maincpu_slice(
    address: int,
    length: int,
    *,
    project: Path,
    rom_dir: Path | None = None,
    out_dir: Path | None = None,
    mame_bin: str | None = None,
) -> Path:
    """Disassemble one maincpu range into project disasm/maincpu/."""
    rom = resolve_rom_dir(rom_dir, project=project)
    dest = out_dir or (project / "disasm" / "maincpu")
    dest.mkdir(parents=True, exist_ok=True)
    asm_path = dest / f"maincpu_{address:06x}_{length:x}.asm"
    return run_mame_dasm(
        rom_dir=rom,
        out_asm=asm_path,
        address=address,
        length=length,
        mame_bin=mame_bin,
    )
