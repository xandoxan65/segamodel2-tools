#!/usr/bin/env python3
"""High-level maincpu ROM section map from scans, anchors, and density heuristics."""

from __future__ import annotations

import argparse
import json
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from tools.i960_memory import (
    COPY_CATALOG_INDEX_TABLE_FN,
    DRAW_CATALOG_SEQUENCE_FN,
    GEO_PRG_FIFO,
    GEO_WRITE_START,
    MAINCPU_SIZE,
    SCENE_ROOT_TABLE_ROM,
    VEHICLE_ASSEMBLY_CATALOG_ROM,
    VEHICLE_DRAW_CATALOG_FN,
    VEHICLE_DRAW_LIST_ROM,
    VEHICLE_GEO_FIFO,
)
from tools.rom_io import resolve_rom_dir

BUCKET_SIZE = 0x10_000
MIN_STRING_LEN = 8
GEO_PORTS = frozenset({GEO_WRITE_START, VEHICLE_GEO_FIFO, GEO_PRG_FIFO})
MAIN_DATA_LO = 0x0200_0000
MAIN_DATA_HI = 0x03FF_FFFF
WORKRAM_LO = 0x0020_0000
WORKRAM_HI = 0x005F_FFFF

# Curated ROM anchors (address, label, confidence, category).
ROM_ANCHORS: tuple[tuple[int, str, str, str], ...] = (
    (0x0000B0, "boot_prcb", "high", "rodata"),
    (0x000420, "maincpu_reset_entry", "high", "code"),
    (0x003C00, "math_thunk_palette", "high", "code"),
    (0x004BA8, "placement_cursor_reset", "high", "code"),
    (0x012D00, "scene_setup_init", "high", "code"),
    (0x0146A8, "scene_classifier", "high", "code"),
    (0x014760, "scene_root_table", "high", "rodata"),
    (0x014788, "scene_lookup_fn", "high", "code"),
    (0x015524, "scene_descriptor_loader", "high", "code"),
    (0x016164, "scene_matrix_init", "high", "code"),
    (0x023CC8, "placement_geo_feeder", "high", "code"),
    (0x0282D0, "copy_catalog_index_table", "high", "code"),
    (0x029C10, "draw_scene_dispatch", "high", "code"),
    (0x029EB0, "catalog_draw_setup", "high", "code"),
    (0x0322F0, "placement_float_adjust", "high", "code"),
    (0x034E40, "vehicle_assembly_catalog", "high", "rodata"),
    (0x034E88, "vehicle_draw_list", "high", "rodata"),
    (0x03EF70, "catalog_draw_variant", "medium", "code"),
    (0x03F040, "object_name_strings", "high", "rodata"),
    (0x044F00, "draw_car_primary", "high", "code"),
    (0x05CDC8, "libc_strcpy", "high", "code"),
    (0x05CEC0, "libc_printf", "high", "code"),
    (0x05CF50, "libc_printf_dispatch", "high", "code"),
    (0x05DAA0, "libc_memcpy", "high", "code"),
    (0x009B70, "ui_course_strings", "high", "rodata"),
    (0x083600, "late_code_island", "low", "code"),
)

REGION_TEMPLATES: tuple[tuple[int, int, str, str, str], ...] = (
    (0x000000, 0x006000, "boot_early_init", "high", "Vectors, early init, geo clusters @ 0x34EC/0x4724/0x5040"),
    (0x006000, 0x010000, "service_diagnostic_rodata", "high", "I/O and service menu format strings (CHUTE, SHIFT, VR, …)"),
    (0x010000, 0x020000, "scene_infrastructure", "medium", "Scene tables @ 0x14760, classifier/lookup, scene-init clusters"),
    (0x020000, 0x030000, "game_logic_geo_core", "high", "Placement feeder, draw dispatch, heaviest geo FIFO density"),
    (0x030000, 0x050000, "game_logic_extended", "medium", "Vehicle draw, catalog tables, object-name rodata"),
    (0x050000, 0x05C000, "late_code", "medium", "Geo activity tapers; last geo port refs ~0x5AD38"),
    (0x05C000, 0x05E000, "libc_runtime", "high", "C stdio/memcpy (printf, sprintf dispatch, strcpy, memcpy)"),
    (0x05E000, 0x060000, "post_libc_glue", "low", "Short transition between libc and rodata band"),
    (0x060000, 0x0BD600, "rodata_pointer_tables", "medium", "Dense strings, main_data pointer tables, UI text; little geo"),
    (0x0BD600, 0x100000, "erase_fill", "high", "0xFF padding to 1 MiB image size"),
)


def load_maincpu(rom_dir: Path | None, binary: Path | None) -> bytes:
    if binary is not None:
        return binary.read_bytes()
    from tools.i960_scan import load_maincpu_words

    raw, _ = load_maincpu_words(resolve_rom_dir(rom_dir))
    return raw


def scan_strings(rom: bytes, min_len: int = MIN_STRING_LEN) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    start: int | None = None
    chars: list[str] = []
    for offset, byte in enumerate(rom):
        if 32 <= byte < 127:
            if start is None:
                start = offset
            chars.append(chr(byte))
        else:
            if start is not None and len(chars) >= min_len:
                rows.append(
                    {
                        "start": f"0x{start:06x}",
                        "end": f"0x{offset:06x}",
                        "preview": "".join(chars)[:72],
                    }
                )
            start = None
            chars = []
    return rows


def classify_bucket(
    rom: bytes,
    words: tuple[int, ...],
    bucket: int,
) -> dict[str, object]:
    start = bucket * BUCKET_SIZE
    end = min(start + BUCKET_SIZE, len(rom))
    chunk = rom[start:end]
    word_lo = start // 4
    word_hi = end // 4

    printable = sum(1 for b in chunk if 32 <= b < 127)
    ff_bytes = sum(1 for b in chunk if b == 0xFF)
    geo_refs = sum(1 for i in range(word_lo, word_hi) if words[i] in GEO_PORTS)
    main_data_refs = sum(
        1 for i in range(word_lo, word_hi) if MAIN_DATA_LO <= words[i] <= MAIN_DATA_HI
    )
    workram_refs = sum(
        1 for i in range(word_lo, word_hi) if WORKRAM_LO <= words[i] <= WORKRAM_HI
    )
    call_ops = sum(1 for i in range(word_lo, word_hi) if (words[i] >> 24) & 0xFF in (0x09, 0x0B))

    tags: list[str] = []
    if ff_bytes / max(len(chunk), 1) > 0.95:
        tags.append("erase_fill")
    elif geo_refs >= 100:
        tags.append("geo_code")
    elif geo_refs >= 20:
        tags.append("geo_mixed")
    if main_data_refs >= 80 and geo_refs < 30:
        tags.append("main_data_tables")
    if call_ops >= 300:
        tags.append("code_heavy")
    elif call_ops >= 80 and geo_refs >= 20:
        tags.append("code_mixed")
    if printable / max(len(chunk), 1) > 0.35 and geo_refs < 20:
        tags.append("strings")

    return {
        "start": f"0x{start:06x}",
        "end": f"0x{end:06x}",
        "printable_pct": round(100 * printable / max(len(chunk), 1), 1),
        "ff_pct": round(100 * ff_bytes / max(len(chunk), 1), 1),
        "geo_port_refs": geo_refs,
        "main_data_ptr_refs": main_data_refs,
        "workram_ptr_refs": workram_refs,
        "call_bal_ops": call_ops,
        "tags": tags,
    }


def find_fill_start(rom: bytes, min_run: int = 0x400) -> int:
    run = 0
    for offset in range(len(rom) - 1, -1, -1):
        if rom[offset] == 0xFF:
            run += 1
        else:
            if run >= min_run:
                return offset + 1
            run = 0
    return len(rom) if run >= min_run else len(rom)


def find_last_geo_ref(words: tuple[int, ...]) -> int:
    last = 0
    for i, word in enumerate(words):
        if word in GEO_PORTS:
            last = i * 4
    return last


def load_geo_clusters(scan_path: Path) -> list[dict[str, object]]:
    if not scan_path.is_file():
        return []
    report = json.loads(scan_path.read_text(encoding="utf-8"))
    return report.get("geo_scan", {}).get("geo_write_start_clusters", [])


def load_decode_intervals(decode_path: Path) -> list[dict[str, object]]:
    if not decode_path.is_file():
        return []
    report = json.loads(decode_path.read_text(encoding="utf-8"))
    intervals = []
    for item in report.get("merged_intervals", []):
        start = int(item["start"], 16)
        end = int(item["end"], 16)
        if start < MAINCPU_SIZE:
            intervals.append(
                {
                    "start": item["start"],
                    "end": item["end"],
                    "bytes": item["bytes"],
                }
            )
    return intervals


def anchors_in_range(start: int, end: int) -> list[dict[str, object]]:
    rows = []
    for addr, label, confidence, category in ROM_ANCHORS:
        if start <= addr < end:
            rows.append(
                {
                    "address": f"0x{addr:06x}",
                    "label": label,
                    "confidence": confidence,
                    "category": category,
                }
            )
    return rows


def build_regions(fill_start: int, last_geo: int) -> list[dict[str, object]]:
    regions: list[dict[str, object]] = []
    for start, end, name, confidence, notes in REGION_TEMPLATES:
        if name == "erase_fill":
            start = fill_start
        elif name == "rodata_pointer_tables":
            end = min(end, fill_start)
        elif name == "late_code":
            notes = f"{notes}; last geo port ref @ 0x{last_geo:06x}"
        regions.append(
            {
                "name": name,
                "start": f"0x{start:06x}",
                "end": f"0x{end:06x}",
                "size": end - start,
                "confidence": confidence,
                "notes": notes,
                "anchors": anchors_in_range(start, end),
            }
        )
    return regions


def build_report(
    rom: bytes,
    scan_path: Path,
    decode_path: Path,
    track_path: Path,
) -> dict[str, object]:
    words = struct.unpack(f"<{len(rom) // 4}I", rom)
    fill_start = find_fill_start(rom)
    last_geo = find_last_geo_ref(words)
    used_end = fill_start

    buckets = [classify_bucket(rom, words, b) for b in range(len(rom) // BUCKET_SIZE)]
    strings = scan_strings(rom)
    string_dense = defaultdict(int)
    for item in strings:
        bucket = int(str(item["start"]), 16) // 0x4000
        string_dense[bucket] += 1

    regions = build_regions(fill_start, last_geo)

    extra_anchors = [
        {"address": f"0x{DRAW_CATALOG_SEQUENCE_FN:06x}", "label": "draw_catalog_sequence", "source": "i960_memory"},
        {"address": f"0x{COPY_CATALOG_INDEX_TABLE_FN:06x}", "label": "copy_catalog_index_table", "source": "i960_memory"},
        {"address": f"0x{VEHICLE_DRAW_CATALOG_FN:06x}", "label": "vehicle_draw_catalog_fn", "source": "i960_memory"},
        {"address": f"0x{SCENE_ROOT_TABLE_ROM:06x}", "label": "scene_root_table", "source": "i960_memory"},
        {"address": f"0x{VEHICLE_ASSEMBLY_CATALOG_ROM:06x}", "label": "vehicle_assembly_catalog", "source": "i960_memory"},
        {"address": f"0x{VEHICLE_DRAW_LIST_ROM:06x}", "label": "vehicle_draw_list", "source": "i960_memory"},
    ]

    track_refs: dict[str, object] = {}
    if track_path.is_file():
        track = json.loads(track_path.read_text(encoding="utf-8"))
        track_refs = {
            "ui_courses": track.get("ui_courses", {}),
            "placement_cursor": track.get("placement_cursor", {}),
            "scene_init": {
                k: track["scene_init"][k]
                for k in ("classifier_fn", "lookup_fn", "catalog_index_read")
                if k in track.get("scene_init", {})
            },
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "image": "maincpu",
        "rom_bytes": len(rom),
        "used_bytes": used_end,
        "used_end": f"0x{used_end:06x}",
        "fill_start": f"0x{fill_start:06x}",
        "last_geo_port_ref": f"0x{last_geo:06x}",
        "summary": (
            f"~{used_end // 1024} KiB used program ROM; "
            f"geo-heavy code in 0x020000–0x050000; libc @ 0x05C000; "
            f"rodata/tables 0x060000–0x{fill_start:06x}; 0xFF fill after."
        ),
        "regions": regions,
        "buckets_64k": buckets,
        "string_density_16k": [
            {"bucket_start": f"0x{b * 0x4000:06x}", "string_count": string_dense[b]}
            for b in sorted(string_dense)
            if string_dense[b] >= 3
        ],
        "anchors": [
            {
                "address": f"0x{addr:06x}",
                "label": label,
                "confidence": confidence,
                "category": category,
            }
            for addr, label, confidence, category in ROM_ANCHORS
        ],
        "symbol_anchors": extra_anchors,
        "geo_clusters": load_geo_clusters(scan_path),
        "disasm_coverage_intervals": load_decode_intervals(decode_path),
        "track_report_refs": track_refs,
        "related_images": [
            {
                "name": "main_data",
                "vaddr": "0x02000000",
                "mirror": "0x06000000",
                "notes": "Object catalog @ 0x02864B40, placement @ 0x02867C20 — separate ROM, not in maincpu map",
            },
            {
                "name": "workram",
                "vaddr": "0x00500000",
                "notes": "Runtime tables (0x5B4340 catalog index, scene roots); not in ROM",
            },
        ],
        "limitations": [
            "Region boundaries are heuristic; 0x060000–0x0BD600 code vs rodata split is not proven.",
            "Bucket printable% is inflated by 0x0020xxxx workram pointer immediates in code.",
            "Disasm coverage is ~5%; regions are scan/anchor-driven, not full CFG analysis.",
            "Not sufficient for splat-style auto-split without a second code/data pass.",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build high-level maincpu ROM section map")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--binary", type=Path, default=Path("out/i960/maincpu_deinterleaved.bin"))
    ap.add_argument("--scan", type=Path, default=Path("out/i960/scan_report.json"))
    ap.add_argument("--decode", type=Path, default=Path("out/i960/decode_report.json"))
    ap.add_argument("--track", type=Path, default=Path("out/i960/track_report.json"))
    ap.add_argument("--out", type=Path, default=Path("out/i960/section_map.json"))
    args = ap.parse_args()

    rom = load_maincpu(args.rom_dir, args.binary if args.binary.is_file() else None)
    report = build_report(rom, args.scan, args.decode, args.track)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(report["summary"])


if __name__ == "__main__":
    main()
