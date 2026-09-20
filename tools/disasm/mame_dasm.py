#!/usr/bin/env python3
"""Disassemble srallyc maincpu via MAME debugger (accurate i960dasm)."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.decomp.disasm_paths import CLUSTERS_SUBDIR, DECOMP_DISASM, MAINCPU_SUBDIR
from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir, write_bytes


def find_mame() -> str:
    for candidate in ("/opt/homebrew/bin/mame", "/opt/local/bin/mame", shutil.which("mame")):
        if candidate and Path(candidate).is_file():
            return candidate
    raise FileNotFoundError("mame not found — install with: brew install mame")


def mame_rompath(rom_dir: Path) -> Path:
    """MAME expects $ROMPATH/<gamename>/files — ensure srallycb alias exists."""
    rom_dir = rom_dir.resolve()
    if rom_dir.name in ("srallycb", "srallyc-b", "srallyc"):
        parent = rom_dir.parent
        link = parent / "srallycb"
        if rom_dir.name != "srallycb" and not link.exists():
            link.symlink_to(rom_dir.name)
        return parent
    return rom_dir


def write_debugscript(path: Path, commands: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(commands) + "\n")


def run_mame_dasm(
    *,
    rom_dir: Path,
    out_asm: Path,
    address: int,
    length: int,
    mame_bin: str,
) -> None:
    dbg = out_asm.with_suffix(".dbg")
    write_debugscript(
        dbg,
        [
            f"dasm {out_asm.resolve()},{address:x},{length:x},1,:maincpu",
            "quit",
        ],
    )

    rompath = mame_rompath(rom_dir)
    cmd = [
        mame_bin,
        "srallycb",
        "-rompath",
        str(rompath),
        "-debug",
        "-debugscript",
        str(dbg.resolve()),
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


def disasm_geo_clusters(
    rom_dir: Path,
    out_dir: Path,
    mame_bin: str,
    *,
    limit: int | None = None,
    skip_existing: bool = False,
) -> list[dict]:
    import json

    report_path = Path("out/i960/scan_report.json")
    if not report_path.is_file():
        raise FileNotFoundError(f"Run i960_scan first: {report_path}")

    report = json.loads(report_path.read_text())
    regions = report.get("exported_regions", [])
    if limit is not None:
        regions = regions[:limit]
    results = []
    for region in regions:
        load_addr = int(region["load_address"], 16)
        size = region["size"]
        asm_path = out_dir / region["file"].replace(".bin", ".asm")
        if skip_existing and asm_path.is_file():
            results.append({"asm": str(asm_path), "region": region, "skipped": True})
            continue
        run_mame_dasm(
            rom_dir=rom_dir,
            out_asm=asm_path,
            address=load_addr,
            length=size,
            mame_bin=mame_bin,
        )
        results.append({"asm": str(asm_path), "region": region})
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Disassemble maincpu regions with MAME i960dasm")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output dir (default: decomp/disasm/maincpu or …/clusters with --clusters)",
    )
    ap.add_argument("--address", type=lambda x: int(x, 0), default=None, help="Start PC (hex)")
    ap.add_argument("--length", type=lambda x: int(x, 0), default=None, help="Byte length (hex)")
    ap.add_argument("--clusters", action="store_true", help="Disassemble geo clusters from scan_report.json")
    ap.add_argument("--cluster-limit", type=int, default=None, help="Max clusters (default: all exported)")
    ap.add_argument("--skip-existing", action="store_true", help="Skip clusters whose .asm already exists")
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    mame_bin = find_mame()
    if args.out is None:
        out_dir = DECOMP_DISASM / (CLUSTERS_SUBDIR if args.clusters else MAINCPU_SUBDIR)
    else:
        out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.clusters:
        done = disasm_geo_clusters(
            rom_dir,
            out_dir,
            mame_bin,
            limit=args.cluster_limit,
            skip_existing=args.skip_existing,
        )
        new = sum(1 for d in done if not d.get("skipped"))
        print(f"Disassembled {new} cluster(s) ({len(done)} total) to {out_dir}")
        return

    if args.address is None or args.length is None:
        raw, _ = load_maincpu_words(rom_dir)
        write_bytes(out_dir / "maincpu_full.asm", b"")  # placeholder
        run_mame_dasm(
            rom_dir=rom_dir,
            out_asm=out_dir / "maincpu_full.asm",
            address=0,
            length=len(raw),
            mame_bin=mame_bin,
        )
        print(f"Wrote {out_dir / 'maincpu_full.asm'}")
        return

    asm_path = out_dir / f"maincpu_{args.address:06x}_{args.length:x}.asm"
    run_mame_dasm(rom_dir=rom_dir, out_asm=asm_path, address=args.address, length=args.length, mame_bin=mame_bin)
    print(f"Wrote {asm_path}")


if __name__ == "__main__":
    main()
