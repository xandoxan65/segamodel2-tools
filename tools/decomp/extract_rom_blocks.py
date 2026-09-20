#!/usr/bin/env python3
"""Extract static ROM blobs for lifted-C sim (maincpu + main_data)."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.i960_scan import load_maincpu_words
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract maincpu / main_data deinterleaved bins")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=Path("out/i960"))
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    maincpu_raw, _ = load_maincpu_words(rom_dir)
    maincpu_path = out_dir / "maincpu_deinterleaved.bin"
    write_bytes(maincpu_path, maincpu_raw)
    print(f"Wrote {maincpu_path} ({len(maincpu_raw)} bytes)")

    main_data_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    main_data_path = out_dir / "main_data_deinterleaved.bin"
    write_bytes(main_data_path, main_data_raw)
    print(f"Wrote {main_data_path} ({len(main_data_raw)} bytes)")


if __name__ == "__main__":
    main()
