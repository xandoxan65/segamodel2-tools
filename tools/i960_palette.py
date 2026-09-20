"""Static RE report for Model 2 palette init (CGM → palram / colorxlat / lumaram)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.model2_palette import palette_report_dict
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


def build_palette_report(rom_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    report = palette_report_dict(main_data)
    path = out_dir / "palette_report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Model 2 palette RE report from ROM.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/i960"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    path = build_palette_report(rom_dir, args.out)
    print(path)


if __name__ == "__main__":
    main()
