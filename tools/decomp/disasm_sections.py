#!/usr/bin/env python3
"""Disassemble layout code sections via MAME (optional)."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from tools.decomp.layout import iter_image_sections, load_layout, section_bounds
from tools.disasm.mame_dasm import find_mame, run_mame_dasm
from tools.rom_io import resolve_rom_dir


CODE_SECTION_NAMES = frozenset(
    {
        "boot_early_init",
        "scene_infrastructure",
        "game_logic_geo_core",
        "game_logic_extended",
        "late_code",
        "libc_runtime",
        "post_libc_glue",
    }
)


def disasm_maincpu_sections(
    layout: dict,
    out_dir: Path,
    rom_dir: Path,
) -> list[dict]:
    mame = find_mame()
    rows: list[dict] = []
    for section in iter_image_sections(layout, "maincpu"):
        name = section["name"]
        if name not in CODE_SECTION_NAMES and section.get("kind") != "code":
            continue
        start, end = section_bounds(section)
        length = end - start
        if length <= 0 or length > 0x10000:
            # Skip huge rodata bands; disasm targeted slices separately.
            if name not in CODE_SECTION_NAMES:
                continue
        out_asm = out_dir / "maincpu" / f"{name}.asm"
        try:
            run_mame_dasm(rom_dir=rom_dir, out_asm=out_asm, address=start, length=length, mame_bin=mame)
            rows.append({"section": name, "start": section["start"], "end": section["end"], "file": str(out_asm)})
        except Exception as exc:  # noqa: BLE001 — collect per-section failures
            rows.append({"section": name, "error": str(exc)})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="MAME disasm for decomp code sections")
    ap.add_argument("--decomp-root", type=Path, default=Path("decomp"))
    ap.add_argument("--out-dir", type=Path, default=Path("out/decomp/disasm"))
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--report", type=Path, default=Path("out/decomp/disasm_report.json"))
    args = ap.parse_args()

    if shutil.which("mame") is None and not Path("/opt/homebrew/bin/mame").is_file():
        raise SystemExit("mame not found — install with: brew install mame")

    rom_dir = resolve_rom_dir(args.rom_dir)
    layout = load_layout(
        args.decomp_root,
        maincpu_map_path=Path("out/i960/section_map.json"),
        main_data_map_path=Path("out/i960/section_map_main_data.json"),
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = disasm_maincpu_sections(layout, args.out_dir, rom_dir)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    ok = sum(1 for r in rows if "file" in r)
    print(f"Disassembled {ok}/{len(rows)} sections → {args.out_dir}")


if __name__ == "__main__":
    main()
