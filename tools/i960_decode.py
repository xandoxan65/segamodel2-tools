#!/usr/bin/env python3
"""Summarize targeted i960 disassembly for geo/scene RE."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

MAINCPU_ROM_BYTES = 0x100_000

from tools.i960_memory import (
    CATALOG_VADDR,
    CATALOG_INDEX_TABLE,
    GEO_WRITE_START,
    PLACEMENT_CURSOR,
    PLACEMENT_STREAM_VADDR,
    SCENE_METADATA_TABLE,
    VEHICLE_ASSEMBLY_CATALOG_ROM,
    VEHICLE_DRAW_CATALOG_FN,
    VEHICLE_GEO_FIFO,
    WORKRAM_SCENE_SYMBOLS,
)
from tools.decomp.disasm_paths import DECOMP_DISASM, iter_asm_files
from tools.model2_scenes import DRAW_SCRIPT_VADDR

# MAME dasm: 00015690: 90A83915 005B4340 ld ...
IMM_RE = re.compile(
    r"^[0-9A-Fa-f]{8}:\s+(?:[0-9A-Fa-f]{8}\s+){1,3}(?:ld|st|lda|stq|ldq|ldl|stl|bal|call)\s+.*?(0x[0-9a-f]+)",
    re.M | re.I,
)
ADDR_LINE = re.compile(r"^([0-9A-Fa-f]{8}):\s+([0-9A-Fa-f]{8}(?:\s+[0-9A-Fa-f]{8})*)\s+(\S+)", re.M)


def classify_immediate(value: int) -> str | None:
    if value == GEO_WRITE_START:
        return "geo_write_start"
    if value == CATALOG_VADDR:
        return "catalog_base"
    if value == PLACEMENT_STREAM_VADDR:
        return "placement_stream"
    if value == DRAW_SCRIPT_VADDR:
        return "draw_script"
    if value == PLACEMENT_CURSOR:
        return "placement_cursor"
    if value == CATALOG_INDEX_TABLE:
        return "catalog_index_table"
    if value == SCENE_METADATA_TABLE:
        return "scene_metadata_table"
    if value in WORKRAM_SCENE_SYMBOLS.values():
        for name, v in WORKRAM_SCENE_SYMBOLS.items():
            if v == value:
                return name
    if value == VEHICLE_GEO_FIFO:
        return "vehicle_geo_fifo"
    if value == VEHICLE_DRAW_CATALOG_FN:
        return "vehicle_draw_fn"
    if VEHICLE_ASSEMBLY_CATALOG_ROM <= value <= VEHICLE_ASSEMBLY_CATALOG_ROM + 0x100:
        return "vehicle_catalog_rom"
    if 0x005E_3D00 <= value <= 0x005E_4500:
        return "vehicle_workram"
    if 0x0286_5600 <= value <= 0x0286_5800:
        return "draw_script_band"
    if 0x0286_4B00 <= value <= 0x0286_4C00:
        return "catalog_band"
    if 0x0286_7C00 <= value <= 0x0286_7D00:
        return "placement_band"
    if 0x0080_0000 <= value <= 0x0080_4000:
        return "geo_regs"
    if 0x005B_3600 <= value <= 0x005B_4500:
        return "scene_workram"
    if 0x0200_0000 <= value <= 0x03FF_FFFF:
        return "main_data"
    return None


def scan_asm_file(path: Path, *, rel: str | None = None) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    addrs = [int(m.group(1), 16) for m in ADDR_LINE.finditer(text)]
    rom_start = min(addrs) if addrs else 0
    rom_end = max(addrs) + 16 if addrs else 0

    hits: dict[str, list[str]] = defaultdict(list)
    immediates: dict[str, int] = defaultdict(int)
    calls: dict[str, int] = defaultdict(int)

    for line in lines:
        for imm_s in re.findall(r"0x[0-9a-f]+", line, re.I):
            val = int(imm_s, 16)
            kind = classify_immediate(val)
            if kind:
                hits[kind].append(imm_s)
                immediates[kind] += 1
        call_m = re.search(r"(?:bal|call|callx)\s+0x([0-9a-f]+)", line, re.I)
        if call_m:
            calls[f"0x{int(call_m.group(1), 16):06x}"] += 1

    geo_writes = immediates.get("geo_write_start", 0)
    catalog = immediates.get("catalog_base", 0) + immediates.get("catalog_band", 0)
    scene = sum(immediates.get(k, 0) for k in ("draw_script", "draw_script_band", "scene_workram", "catalog_index_table", "scene_metadata_table"))

    vehicle = (
        immediates.get("vehicle_geo_fifo", 0)
        + immediates.get("vehicle_workram", 0)
        + immediates.get("vehicle_draw_fn", 0)
    )
    if geo_writes >= 3 and catalog >= 2 and vehicle >= 2:
        role = "vehicle_geo_feeder"
    elif geo_writes >= 3 and catalog >= 2:
        role = "geo_feeder"
    elif vehicle >= 3:
        role = "vehicle_geo_feeder"
    elif scene >= 5:
        role = "scene_setup"
    elif geo_writes >= 1:
        role = "geo_helper"
    else:
        role = "other"

    return {
        "file": rel or path.name,
        "rom_range": [f"0x{rom_start:06x}", f"0x{rom_end:06x}"],
        "bytes": rom_end - rom_start,
        "role": role,
        "hits": {k: len(v) for k, v in sorted(hits.items())},
        "top_calls": dict(sorted(calls.items(), key=lambda x: -x[1])[:8]),
    }


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def disasm_coverage_summary(disasm_dir: Path) -> dict:
    """Compact coverage stats for embedding in other reports."""
    report = build_decode_report(disasm_dir)
    return {
        "file_count": report["file_count"],
        "raw_bytes": report["raw_bytes"],
        "unique_bytes": report["unique_bytes"],
        "maincpu_rom_bytes": report["maincpu_rom_bytes"],
        "coverage_pct": report["coverage_pct"],
        "interval_count": report["interval_count"],
        "by_role": {k: len(v) for k, v in report["by_role"].items()},
    }


def build_decode_report(disasm_dir: Path) -> dict:
    files = iter_asm_files(disasm_dir)
    summaries = [
        scan_asm_file(p, rel=str(p.relative_to(disasm_dir))) for p in files
    ]

    intervals: list[tuple[int, int]] = []
    raw_bytes = 0
    for s in summaries:
        start = int(s["rom_range"][0], 16)
        end = int(s["rom_range"][1], 16)
        intervals.append((start, end))
        raw_bytes += end - start

    merged = merge_intervals(intervals)
    merged_bytes = sum(e - s for s, e in merged)

    by_role: dict[str, list[str]] = defaultdict(list)
    for s in summaries:
        by_role[s["role"]].append(s["file"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disasm_dir": str(disasm_dir),
        "file_count": len(summaries),
        "maincpu_rom_bytes": MAINCPU_ROM_BYTES,
        "raw_bytes": raw_bytes,
        "unique_bytes": merged_bytes,
        "coverage_pct": round(100 * merged_bytes / MAINCPU_ROM_BYTES, 2),
        "interval_count": len(merged),
        "merged_intervals": [
            {"start": f"0x{s:06x}", "end": f"0x{e:06x}", "bytes": e - s} for s, e in merged
        ],
        "by_role": {k: sorted(v) for k, v in sorted(by_role.items())},
        "files": summaries,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize targeted i960 disassembly")
    ap.add_argument("--disasm-dir", type=Path, default=DECOMP_DISASM)
    ap.add_argument("--out", type=Path, default=Path("out/i960/decode_report.json"))
    args = ap.parse_args()

    report = build_decode_report(args.disasm_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out} ({report['file_count']} files, {report['coverage_pct']}% coverage)")


if __name__ == "__main__":
    main()
