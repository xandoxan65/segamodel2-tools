#!/usr/bin/env python3
"""Scan srallyc maincpu ROM for Model 2 geo / main_data constants."""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path

from tools.i960_memory import GEO_PORT_CONSTANTS, MAINCPU_SIZE
from tools.rom_io import load32_word_region, resolve_rom_dir, write_bytes


def load_maincpu_words(rom_dir: Path) -> tuple[bytes, list[int]]:
    raw = load32_word_region(rom_dir, [("epr-17888b.12", "epr-17889b.13")])
    words = list(struct.unpack(f"<{len(raw) // 4}I", raw))
    return raw, words


def find_word_refs(words: list[int], value: int) -> list[int]:
    return [i * 4 for i, w in enumerate(words) if w == value]


def cluster_offsets(offsets: list[int], gap: int = 0x400) -> list[list[int]]:
    if not offsets:
        return []
    sorted_offs = sorted(offsets)
    clusters: list[list[int]] = [[sorted_offs[0]]]
    for off in sorted_offs[1:]:
        if off - clusters[-1][-1] > gap:
            clusters.append([off])
        else:
            clusters[-1].append(off)
    return clusters


def scan_geo_ports(words: list[int]) -> dict:
    hits: dict[str, list[int]] = {}
    for name, val in GEO_PORT_CONSTANTS.items():
        hits[name] = find_word_refs(words, val)

    write_start = hits.get("geo_write_start", [])
    clusters = cluster_offsets(write_start)
    cluster_info = []
    for idx, cl in enumerate(clusters):
        start, end = cl[0], cl[-1]
        window = words[start // 4 : (end // 4) + 1]
        main_data_ptrs = [
            i * 4 + start
            for i, w in enumerate(window)
            if 0x0200_0000 <= w <= 0x03FF_FFFF or 0x0600_0000 <= w <= 0x06FF_FFFF
        ]
        cluster_info.append(
            {
                "id": idx,
                "rom_start": f"0x{start:06x}",
                "rom_end": f"0x{end:06x}",
                "ref_count": len(cl),
                "main_data_ptr_count": len(main_data_ptrs),
                "main_data_ptrs": [f"0x{o:06x}" for o in main_data_ptrs[:12]],
            }
        )

    return {
        "constant_hits": {k: len(v) for k, v in hits.items()},
        "geo_write_start_clusters": cluster_info,
    }


def scan_main_data_pointers(words: list[int]) -> dict:
    band_counts = Counter()
    band_examples: dict[str, list[str]] = defaultdict(list)
    for i, w in enumerate(words):
        if 0x0280_0000 <= w <= 0x028F_FFFF:
            band_counts["0x028xxxxx"] += 1
            if len(band_examples["0x028xxxxx"]) < 40:
                band_examples["0x028xxxxx"].append(f"0x{i * 4:06x}:0x{w:08x}")
        elif 0x0200_0000 <= w <= 0x03FF_FFFF:
            band_counts["main_data_a"] += 1
        elif 0x0600_0000 <= w <= 0x06FF_FFFF:
            band_counts["main_data_b"] += 1
    return {
        "pointer_bands": dict(band_counts),
        "near_placement_table_refs": band_examples["0x028xxxxx"],
    }


def export_regions(raw: bytes, clusters: list[dict], out_dir: Path, pad: int = 0x200) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exported = []
    ranked = sorted(clusters, key=lambda c: c["ref_count"], reverse=True)
    for rank, cl in enumerate(ranked[:12]):
        start = int(cl["rom_start"], 16)
        end = int(cl["rom_end"], 16)
        lo = max(0, start - pad)
        hi = min(len(raw), end + pad + 4)
        blob = raw[lo:hi]
        name = f"geo_cluster_{rank:02d}_0x{start:06x}.bin"
        path = out_dir / name
        write_bytes(path, blob)
        exported.append(
            {
                "file": name,
                "load_address": f"0x{lo:06x}",
                "size": len(blob),
                "cluster": cl,
            }
        )
    return exported


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan srallyc maincpu for geo-related constants")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960"))
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    raw, words = load_maincpu_words(rom_dir)
    if len(raw) != MAINCPU_SIZE:
        print(f"warning: maincpu size {len(raw)} != expected {MAINCPU_SIZE}")

    geo = scan_geo_ports(words)
    ptrs = scan_main_data_pointers(words)

    write_bytes(args.out / "maincpu_deinterleaved.bin", raw)

    regions = export_regions(raw, geo["geo_write_start_clusters"], args.out / "regions")

    report = {
        "rom_dir": str(rom_dir),
        "maincpu_bytes": len(raw),
        "geo_scan": geo,
        "main_data_pointers": ptrs,
        "exported_regions": regions,
        "next_steps": [
            "Disassemble geo_write_start clusters with: python -m tools.disasm.mame_dasm",
            "Import maincpu_deinterleaved.bin in Ghidra (i960 LE, base 0x0) after tooling/setup_ghidra_i960.sh",
            "Xref 0x02864b40 / placement_group_026 in largest geo cluster",
        ],
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "scan_report.json").write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
