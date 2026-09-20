"""Extract copro collision/height map ROMs as exploratory heatmaps."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import numpy as np
from PIL import Image

from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes


def _normalize_u16(arr: np.ndarray) -> np.ndarray:
    arr = arr.astype(np.float32)
    lo, hi = float(arr.min()), float(arr.max())
    if hi <= lo:
        return np.zeros(arr.shape, dtype=np.uint8)
    scaled = (arr - lo) / (hi - lo) * 255.0
    return scaled.astype(np.uint8)


def _try_grids(data: bytes, prefix: str, out_dir: Path) -> list[Path]:
    """Emit several plausible 2D interpretations for manual inspection."""
    written: list[Path] = []
    meta: dict[str, object] = {"size_bytes": len(data), "grids": []}

    # As little-endian u16 raster (common for height fields).
    if len(data) % 2 == 0:
        u16 = np.frombuffer(data, dtype="<u2")
        for width in (256, 512, 1024, 2048):
            if len(u16) % width != 0:
                continue
            height = len(u16) // width
            if height < 64 or height > 4096:
                continue
            grid = u16.reshape((height, width))
            img = _normalize_u16(grid)
            path = out_dir / f"{prefix}_u16_{width}x{height}.png"
            Image.fromarray(img, mode="L").save(path)
            written.append(path)
            meta["grids"].append({"dtype": "u16", "width": width, "height": height, "file": path.name})

    # As u8 raster.
    u8 = np.frombuffer(data, dtype=np.uint8)
    for width in (512, 1024, 2048):
        if len(u8) % width != 0:
            continue
        height = len(u8) // width
        if height < 64 or height > 4096:
            continue
        grid = u8.reshape((height, width))
        path = out_dir / f"{prefix}_u8_{width}x{height}.png"
        Image.fromarray(grid, mode="L").save(path)
        written.append(path)
        meta["grids"].append({"dtype": "u8", "width": width, "height": height, "file": path.name})

    meta_path = out_dir / f"{prefix}_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    written.append(meta_path)
    return written


def extract_heightmaps(rom_dir: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    combined = load32_word_region(rom_dir, SRALLY_DATA_ROMS["copro_data"])
    write_bytes(out_dir / "copro_data_deinterleaved.bin", combined)

    half = len(combined) // 2
    socket0 = combined[:half]
    socket1 = combined[half:]

    written: list[Path] = []
    written.extend(_try_grids(socket0, "socket0_mpr17754", out_dir))
    written.extend(_try_grids(socket1, "socket1_mpr17755", out_dir))
    written.extend(_try_grids(combined, "combined", out_dir))

    # u32 preview as two 16-bit lanes (high/low per word).
    u32 = struct.unpack(f"<{len(combined) // 4}I", combined)
    low = np.array([w & 0xFFFF for w in u32], dtype=np.uint16)
    high = np.array([(w >> 16) & 0xFFFF for w in u32], dtype=np.uint16)
    for lane, name in ((low, "u32_low_lane"), (high, "u32_high_lane")):
        for width in (512, 1024):
            if len(lane) % width != 0:
                continue
            height = len(lane) // width
            if 64 <= height <= 4096:
                img = _normalize_u16(lane.reshape((height, width)))
                path = out_dir / f"combined_{name}_{width}x{height}.png"
                Image.fromarray(img, mode="L").save(path)
                written.append(path)

    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract copro height/collision map ROMs.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/heightmaps"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_heightmaps(rom_dir, args.out)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
