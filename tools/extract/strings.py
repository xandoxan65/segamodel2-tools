"""Scan main_data ROM for printable strings (track names, UI text, etc.)."""

from __future__ import annotations

import re
from pathlib import Path

from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes

MIN_STRING_LEN = 4


def extract_strings(rom_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    write_bytes(out_dir / "main_data_deinterleaved.bin", data)

    # ASCII runs (including common Shift-JIS leading bytes filtered loosely).
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
    found: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(data):
        s = match.group().decode("ascii")
        if s not in seen:
            seen.add(s)
            found.append(s)

    found.sort(key=str.lower)
    out_path = out_dir / "strings_ascii.txt"
    out_path.write_text("\n".join(found) + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract ASCII strings from main_data ROM.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/strings"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    path = extract_strings(rom_dir, args.out)
    count = len(path.read_text().splitlines())
    print(f"Wrote {count} strings to {path.resolve()}")


if __name__ == "__main__":
    main()
