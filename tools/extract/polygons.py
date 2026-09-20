"""Export polygon model ROM (raw + simple entropy previews). Full mesh decode is Phase 1b."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image

from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes


def extract_polygons(rom_dir: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    write_bytes(out_dir / "polygons_deinterleaved.bin", raw)

    written: list[Path] = [out_dir / "polygons_deinterleaved.bin"]
    half = len(raw) // 2
    for i, chunk in enumerate((raw[:half], raw[half:])):
        u8 = np.frombuffer(chunk, dtype=np.uint8)
        for width in (1024, 2048):
            if len(u8) % width:
                continue
            height = len(u8) // width
            if height < 256:
                continue
            img = u8.reshape((height, width))
            path = out_dir / f"bank{i}_byteview_{width}x{height}.png"
            Image.fromarray(img, mode="L").save(path)
            written.append(path)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export polygon ROM (raw; mesh parser TBD).")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/polygons"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_polygons(rom_dir, args.out)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
