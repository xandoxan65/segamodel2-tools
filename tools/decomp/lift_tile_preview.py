#!/usr/bin/env python3
"""Compose System-24 tile layer PNG from lift boot dumps.

Decode follows disasm @ 0x27110 (map entry) and lifted ``tile_char_upload``
(8 rows × u32 per source byte). Row stride 0x80 @ 0x27260.

Usage:
  python -m tools.decomp.lift_tile_preview --dump decomp/build/lift/boot_palette -o out/lift/boot_preview
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from PIL import Image

from tools.decomp.lift_palette_state import load_lift_palette_state
from tools.model2_palette import rgb15

TILE_MAP_BASE = 0x01000000
TILE_CHAR_BASE = 0x01080000
MAP_ROW_STRIDE = 0x80  # @ 0x272A4 lda 0x80(g6)
TILE_W = 8
TILE_H = 8  # g7 = 7…0 @ 0x26BB8 / 0x26C68 — eight rows per glyph
MAP_COLS = 64  # tile_index = row*64 + col @ 0x27108 addo g5,g7


def _read_u16(data: bytes, off: int) -> int:
    if off + 1 >= len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]


def _gfx_readbit(src: bytes, bitnum: int) -> int:
    """MAME drawgfx.cpp readbit — MSB-first within each byte."""
    return src[bitnum // 8] & (0x80 >> (bitnum % 8))


def _gfx_pixel(tile_char: bytes, char_index: int, px: int, py: int) -> int:
    """MAME gfx_element::decode for segas24_tile_device::char_layout."""
    planeoffset = (0, 1, 2, 3)
    xoffset = (0, 4, 8, 12, 16, 20, 24, 28)
    yoffset = (0, 32, 64, 96, 128, 160, 192, 224)
    charincrement = 256
    color = 0
    planebit = 8
    for plane in range(4):
        bitnum = char_index * charincrement + planeoffset[plane] + yoffset[py] + xoffset[px]
        if _gfx_readbit(tile_char, bitnum):
            color |= planebit
        planebit >>= 1
    return color


def _char_tile_pixels(tile_char: bytes, char_index: int) -> list[list[int]]:
    """One 8×8 tile via MAME char_layout (32 bytes/glyph in char RAM)."""
    return [[_gfx_pixel(tile_char, char_index, x, y) for x in range(TILE_W)] for y in range(TILE_H)]


def _map_entry_char_palette(entry: int) -> tuple[int, int, bool]:
    """MAME segas24_tile_device::tile_info @ segaic24.cpp + boot stos @ 0x27110."""
    char_index = entry & 0x3FFF
    pal_base = (entry >> 7) & 0xFF
    return char_index, pal_base, True


def render_tile_layer(
    *,
    tile_map: bytes,
    tile_char: bytes,
    palram_words: list[int],
    layer_base: int = 0,
    width: int = MAP_COLS,
    height: int = 48,
) -> Image.Image:
    img = Image.new("RGB", (width * TILE_W, height * TILE_H), (0, 0, 0))
    px = img.load()
    for row in range(height):
        for col in range(width):
            index = row * MAP_COLS + col
            entry = _read_u16(tile_map, index * 2)
            char_idx, pal_base, draw = _map_entry_char_palette(entry)
            if not draw:
                continue
            rows = _char_tile_pixels(tile_char, char_idx)
            for py in range(TILE_H):
                for px_i in range(TILE_W):
                    nib = rows[py][px_i]
                    if nib == 0:
                        continue
                    color15 = palram_words[(pal_base << 4) + nib] & 0x7FFF
                    if color15 == 0:
                        continue
                    r, g, b = rgb15(color15)
                    x = col * TILE_W + px_i
                    y = row * TILE_H + py
                    if x < img.width and y < img.height:
                        px[x, y] = (r, g, b)
    return img


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", type=Path, required=True)
    ap.add_argument("-o", "--out", type=Path, required=True)
    args = ap.parse_args()

    dump = args.dump.resolve()
    out = args.out.resolve()
    manifest = json.loads((dump / "manifest.json").read_text(encoding="utf-8"))

    state, _ = load_lift_palette_state(dump)
    tile_map = (dump / manifest["tile_map"]["file"]).read_bytes()
    tile_char = (dump / manifest["tile_char"]["file"]).read_bytes()

    img = render_tile_layer(
        tile_map=tile_map,
        tile_char=tile_char,
        palram_words=state.palram,
    )
    out.mkdir(parents=True, exist_ok=True)
    img.save(out / "lift_tile_layer0.png")
    nz = sum(1 for i in range(0, len(tile_map), 2) if _read_u16(tile_map, i) != 0)
    report = {
        "tile_map_base": hex(TILE_MAP_BASE),
        "tile_char_base": hex(TILE_CHAR_BASE),
        "map_row_stride": MAP_ROW_STRIDE,
        "nonzero_map_entries": nz,
        "image": "lift_tile_layer0.png",
    }
    (out / "lift_tile.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"tile preview: {nz} nonzero map entries → {out / 'lift_tile_layer0.png'}",
        file=__import__("sys").stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
