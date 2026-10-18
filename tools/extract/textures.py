"""Decode Model 2 texture sheets into viewable PNGs.

Texel packing follows MAME model2rd.ipp get_texel(): sheets are logically 2048x1024
but stored in RAM as 1024x2048 with a fold at x >= 1024.

Important: MAME uses the ``textures`` ROM region as a u16 pool for per-polygon texture
points and headers. Runtime texel fetches read ``textureram0`` / ``textureram1`` (1 MiB
of texels each, Model 2A @ 0x12000000 / 0x12400000), which the game uploads before draw.

The texels live in 1 MiB banks of ``main_data`` from ``0x02200000``. The game does not
copy a bank flat: maincpu ``0x003940`` deals each bank's mip levels out between the two
sheets. ``tools.extract.texture_ram`` ports that routine. Decoding ``mpr-17752``/``mpr-17753``
as atlases is wrong — that ROM holds tp/th metadata only.
"""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np
from PIL import Image

from tools.model2_palette import PaletteState, load_palette_from_main_data
from tools.extract.texture_ram import build_texture_ram, load_texture_sheets, sheet_words
from tools.model2_texture import TRANSPARENT_TEXEL
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes


def get_texel(sheet: list[int], base_x: int, base_y: int, x: int, y: int) -> int:
    """MAME model2rd.ipp get_texel() — sheet is u32 ROM, offset is a u16 lane index."""
    x2 = base_x + x
    y2 = base_y + y
    if x2 >= 1024:
        x2 -= 1024
        y2 ^= 1024
    offset = (y2 // 2) * 512 + (x2 // 2)
    texel = sheet[offset >> 1]
    if offset & 1:
        texel >>= 16
    if (y & 1) == 0:
        texel >>= 8
    if (x & 1) == 0:
        texel >>= 4
    return texel & 0x0F


def decode_logical_sheet(sheet: list[int], width: int = 2048, height: int = 1024) -> np.ndarray:
    """Return grayscale 0-255 array (logical 2048x1024 layout)."""
    img = np.zeros((height, width), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            v = get_texel(sheet, 0, 0, x, y)
            img[y, x] = v * 17  # spread 4-bit index to 8-bit
    return img


def decode_logical_indices(sheet: list[int], width: int = 2048, height: int = 1024) -> np.ndarray:
    """Return 4-bit texel indices for a logical 2048x1024 sheet."""
    indices = np.zeros((height, width), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            indices[y, x] = get_texel(sheet, 0, 0, x, y)
    return indices


_SHEET_INDEX_CACHE: dict[int, np.ndarray] = {}


def clear_sheet_index_cache() -> None:
    _SHEET_INDEX_CACHE.clear()


def logical_sheet_indices(sheet: list[int]) -> np.ndarray:
    """Memoized texel index grid keyed by id(sheet) list backing."""
    key = id(sheet)
    cached = _SHEET_INDEX_CACHE.get(key)
    if cached is None:
        cached = decode_logical_indices(sheet)
        _SHEET_INDEX_CACHE[key] = cached
    return cached


def decode_colored_logical_sheet(
    sheet: list[int],
    palette: PaletteState,
    *,
    colorbase: int = 0,
    lumabase: int = 0,
    width: int = 2048,
    height: int = 1024,
    cutout_transparent: bool = False,
    checker_cutout: bool = False,
    cutout_background_zero: bool = False,
) -> np.ndarray:
    """Apply static CGM palette mapping to a logical 2048x1024 sheet (RGBA)."""
    del width, height
    lut = np.zeros((16, 4), dtype=np.uint8)
    for texel in range(16):
        lut[texel, :3] = palette.lookup_texel(texel, colorbase, lumabase)
        lut[texel, 3] = 255
    if cutout_transparent:
        lut[TRANSPARENT_TEXEL, 3] = 0
        if cutout_background_zero:
            lut[0, 3] = 0
    indices = logical_sheet_indices(sheet)
    rgba = lut[indices]
    if checker_cutout:
        xs = np.arange(indices.shape[1], dtype=np.uint8)[None, :]
        ys = np.arange(indices.shape[0], dtype=np.uint8)[:, None]
        checker_mask = (xs ^ ys) & 1
        rgba[..., 3] = np.where(checker_mask, 0, rgba[..., 3])
    return rgba


def load_sheet_banks_from_main_data(
    main_data: bytes, maincpu: bytes | None = None, course: str | int | None = "desert"
) -> tuple[list[int], list[int]]:
    """Both texture RAM sheets (1 MiB each) as the upload routine leaves them."""
    sheet0, sheet1 = build_texture_ram(main_data, maincpu, course)
    return sheet_words(sheet0), sheet_words(sheet1)


def write_sheet_pngs(
    words: list[int],
    prefix: str,
    out_dir: Path,
    palette: PaletteState,
) -> list[Path]:
    written: list[Path] = []
    logical = decode_logical_sheet(words)
    p_logical = out_dir / f"{prefix}_logical_2048x1024.png"
    Image.fromarray(logical, mode="L").save(p_logical)
    written.append(p_logical)

    colored = decode_colored_logical_sheet(words, palette, colorbase=0, lumabase=0)
    p_colored = out_dir / f"{prefix}_logical_2048x1024_palette_cb0.png"
    Image.fromarray(colored, mode="RGBA").save(p_colored)
    written.append(p_colored)

    stored = decode_stored_sheet(words)
    p_stored = out_dir / f"{prefix}_stored_1024x2048.png"
    Image.fromarray(stored, mode="L").save(p_stored)
    written.append(p_stored)
    return written


def decode_stored_sheet(sheet: list[int], width: int = 1024, height: int = 2048) -> np.ndarray:
    """Raw storage layout: 1024x2048 without logical remapping."""
    # One offset per 2x2 texels, two offsets (u16 lanes) to a u32 word.
    if len(sheet) * 2 < (width // 2) * (height // 2):
        raise ValueError("Sheet too small for stored layout")
    img = np.zeros((height, width), dtype=np.uint8)
    for y2 in range(0, height, 2):
        for x2 in range(0, width, 2):
            offset = (y2 // 2) * 512 + (x2 // 2)
            word = sheet[offset >> 1]
            for dy in range(2):
                for dx in range(2):
                    t = word
                    if offset & 1:
                        t >>= 16
                    if dy == 0:
                        t >>= 8
                    if dx == 0:
                        t >>= 4
                    img[y2 + dy, x2 + dx] = (t & 0x0F) * 17
    return img


def extract_textures(rom_dir: Path, out_dir: Path) -> list[Path]:
    clear_sheet_index_cache()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    palette = load_palette_from_main_data(main_data)
    write_bytes(out_dir / "textures_deinterleaved.bin", raw)

    written: list[Path] = []
    sheet_words = list(load_texture_sheets(rom_dir))
    for index, words in enumerate(sheet_words):
        written.extend(write_sheet_pngs(words, f"sheet{index}", out_dir, palette))

    half = len(raw) // 2
    rom_words = [
        list(struct.unpack(f"<{len(raw[:half]) // 4}I", raw[:half])),
        list(struct.unpack(f"<{len(raw[half:]) // 4}I", raw[half:])),
    ]
    for index, words in enumerate(rom_words):
        written.extend(write_sheet_pngs(words, f"sheet{index}_textures_rom", out_dir, palette))

    combined = np.hstack([decode_logical_sheet(sheet_words[0]), decode_logical_sheet(sheet_words[1])])
    p_combined = out_dir / "sheets_logical_combined.png"
    Image.fromarray(combined, mode="L").save(p_combined)
    written.append(p_combined)

    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract Sega Rally texture ROMs to PNG.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/textures"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_textures(rom_dir, args.out)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")
    for p in paths:
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
