#!/usr/bin/env python3
"""High-level main_data ROM section map (semantic regions + coarse fill)."""

from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from tools.i960_memory import (
    CATALOG_ENTRY_COUNT,
    CATALOG_VADDR,
    MAIN_DATA_A,
    PLACEMENT_STREAM_VADDR,
)
from tools.model2_catalog import parse_placement_stream
from tools.model2_palette import find_cgm_blocks
from tools.model2_scenes import CPU_DRAW_ENTRY_VADDRS, DRAW_SCRIPT_VADDR, parse_draw_script
from tools.rom_io import load32_word_region, resolve_rom_dir, SRALLY_DATA_ROMS, u32_words


def catalog_region_end() -> int:
    entry_words = 4
    return CATALOG_VADDR + CATALOG_ENTRY_COUNT * entry_words * 4


def draw_script_region_end(main_data: list[int]) -> int:
    layers = parse_draw_script(main_data)
    if not layers:
        return DRAW_SCRIPT_VADDR + 16
    last = layers[-1]
    return last.vaddr + 16


def placement_stream_region_end(
    main_data: list[int],
    polygon_rom: list[int],
    mask: int,
) -> int:
    records = parse_placement_stream(main_data, polygon_rom, polygon_rom_mask=mask)
    if not records:
        return PLACEMENT_STREAM_VADDR + 16
    last = records[-1]
    return MAIN_DATA_A + (last.main_data_word + 4) * 4


def cgm_block_end(block, blocks: list, rom_len: int) -> int:
    for other in blocks:
        if other.rom_offset > block.rom_offset:
            return MAIN_DATA_A + other.rom_offset
    return min(block.vaddr + 0x1000, MAIN_DATA_A + rom_len)


def build_report(rom: bytes, main_data: list[int]) -> dict:
    rom_dir = resolve_rom_dir(None)
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = u32_words(poly_raw)
    mask = len(polygon_rom) - 1

    regions: list[dict] = []

    def add_region(name: str, start: int, end: int, confidence: str, notes: str) -> None:
        if end <= start:
            return
        regions.append(
            {
                "name": name,
                "start": f"0x{start:08x}",
                "end": f"0x{end:08x}",
                "size": end - start,
                "confidence": confidence,
                "notes": notes,
                "anchors": [],
            }
        )

    cat_end = catalog_region_end()
    ds_end = draw_script_region_end(main_data)
    ps_end = placement_stream_region_end(main_data, polygon_rom, mask)
    scene_start = min(min(CPU_DRAW_ENTRY_VADDRS), CATALOG_VADDR, DRAW_SCRIPT_VADDR, PLACEMENT_STREAM_VADDR)
    scene_end = max(cat_end, ds_end, ps_end)
    add_region(
        "scene_geometry_tables",
        scene_start,
        scene_end,
        "high",
        "CPU draw entries, catalog, draw script, placement stream (parser-derived bounds)",
    )

    cgm_blocks = find_cgm_blocks(rom)
    for idx, block in enumerate(cgm_blocks):
        end = cgm_block_end(block, cgm_blocks, len(rom))
        if end <= scene_start or block.vaddr >= scene_end:
            add_region(
                f"cgm_palette_{idx:02d}",
                block.vaddr,
                end,
                "high",
                f"CGM magic block version={block.version}",
            )

    anchors = [
        {"address": f"0x{CATALOG_VADDR:08x}", "label": "object_catalog", "confidence": "high"},
        {"address": f"0x{DRAW_SCRIPT_VADDR:08x}", "label": "draw_script", "confidence": "high"},
        {"address": f"0x{PLACEMENT_STREAM_VADDR:08x}", "label": "placement_stream", "confidence": "high"},
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "image": "main_data",
        "rom_bytes": len(rom),
        "base_vaddr": f"0x{MAIN_DATA_A:08x}",
        "summary": (
            f"{len(rom) // 1024} KiB main_data; semantic islands for catalog, draw script, "
            "placement stream, CGM blocks; gaps filled by 1 MiB coarse chunks in layout."
        ),
        "regions": regions,
        "anchors": anchors,
        "limitations": [
            "Semantic region ends come from existing parsers, not guessed spans.",
            "Coarse main_data_XX chunks are layout-only fillers for roundtrip verify.",
            "CGM blocks may overlap coarse chunks unless layout partition deduplicates.",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build main_data section map")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960/section_map_main_data.json"))
    ap.add_argument("--dump-bin", type=Path, default=Path("out/decomp/main_data_deinterleaved.bin"))
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    rom = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    main_data = u32_words(rom)
    report = build_report(rom, main_data)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.dump_bin.parent.mkdir(parents=True, exist_ok=True)
    args.dump_bin.write_bytes(rom)
    print(f"Wrote {args.out}")
    print(report["summary"])


if __name__ == "__main__":
    main()
