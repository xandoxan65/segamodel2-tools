#!/usr/bin/env python3
"""Build an i960 / main_data cross-reference report for srallyc."""

from __future__ import annotations

import argparse
import json
import struct
from collections import defaultdict
from pathlib import Path

from tools.i960_memory import CATALOG_VADDR, GEO_PORT_CONSTANTS, PLACEMENT_STREAM_VADDR
from tools.model2_scenes import CPU_SCENE_ANCHORS, DRAW_SCRIPT_VADDR
from tools.rom_io import load32_word_region, resolve_rom_dir


def load_maincpu_words(rom_dir: Path) -> list[int]:
    raw = load32_word_region(rom_dir, [("epr-17888b.12", "epr-17889b.13")])
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def xref_value(words: list[int], value: int) -> list[str]:
    return [f"0x{i * 4:06x}" for i, w in enumerate(words) if w == value]


def xref_band(words: list[int], lo: int, hi: int) -> dict[str, list[str]]:
    hits: dict[int, list[str]] = defaultdict(list)
    for i, w in enumerate(words):
        if lo <= w <= hi:
            hits[w].append(f"0x{i * 4:06x}")
    return {f"0x{v:08x}": offs for v, offs in sorted(hits.items())}


def geo_cluster_summary(words: list[int]) -> list[dict]:
    write_start = GEO_PORT_CONSTANTS["geo_write_start"]
    hits = [i * 4 for i, w in enumerate(words) if w == write_start]
    clusters: list[list[int]] = []
    for off in hits:
        if not clusters or off - clusters[-1][-1] > 0x400:
            clusters.append([off])
        else:
            clusters[-1].append(off)
    ranked = sorted(clusters, key=len, reverse=True)[:12]
    out = []
    for cl in ranked:
        start, end = cl[0], cl[-1]
        catalog_refs = sum(
            1 for i in range(start // 4, end // 4 + 1) if words[i] == CATALOG_VADDR
        )
        out.append(
            {
                "rom_start": f"0x{start:06x}",
                "rom_end": f"0x{end:06x}",
                "geo_write_start_refs": len(cl),
                "catalog_base_refs": catalog_refs,
            }
        )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="i960 xref report")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960/xref_report.json"))
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    words = load_maincpu_words(rom_dir)

    targets = {
        **GEO_PORT_CONSTANTS,
        **{f"scene_{k}": v for k, v in CPU_SCENE_ANCHORS.items()},
        "draw_script": DRAW_SCRIPT_VADDR,
        "catalog_base": CATALOG_VADDR,
        "placement_stream": PLACEMENT_STREAM_VADDR,
        "geo_push_helper": 0x0003_EF70,
    }

    report = {
        "rom_dir": str(rom_dir),
        "constant_xrefs": {k: xref_value(words, v) for k, v in targets.items()},
        "catalog_base_xref_count": len(xref_value(words, CATALOG_VADDR)),
        "scene_descriptor_band_0x02865600": xref_band(words, 0x0286_5600, 0x0286_5800),
        "geo_feeder_clusters": geo_cluster_summary(words),
        "notes": [
            "0x02864b40 is referenced 34× from maincpu — master polygon catalog (782×16 bytes).",
            "Placement stream at 0x02867c20 is not a direct immediate; indexed via catalog + workram cursors.",
            "Track label strings live in main_data but are not direct pointers in maincpu ROM.",
            "Scene setup cluster @ ROM 0x015524 loads descriptor block 0x02865730.",
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
