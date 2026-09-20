"""Scene metadata tables from i960 ROM (interval keys + catalog dispatch)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir

# Interval key bytes for scene_lookup @ 0x14788 (ROM template before ptr table @ 0x14760).
SCENE_INTERVAL_ROM = 0x0001_46E4
SCENE_ROOT_PTR_ROM = 0x0001_4760

# Catalog-index dispatch tables in workram (runtime; read sites in ROM).
CATALOG_DISPATCH_BY_SLOT = 0x005C_A210  # ld 0x5ca210[g5*4] @ 0x2B538
CATALOG_DISPATCH_BY_QUAD = 0x005C_A280  # ld 0x5ca280[g4*4] @ 0x2B6A4
CATALOG_BATCH_BUFFERS_ROM = 0x0002_B280  # -> 0x5CA180, 0x5CA1A0, 0x5CA1D0

# Course-select workram roots @ ROM 0x3EFD0 (UI / mode tables).
COURSE_SELECT_WORKRAM_ROM = 0x0003_EFD0


@dataclass
class IntervalGroup:
    index: int
    intervals: list[tuple[int, int]]


def parse_scene_interval_groups(rom_dir: Path | None = None) -> list[IntervalGroup]:
    """
    Parse 0xFF-separated (start, end) word pairs embedded before the scene root ptr table.

    Used by ``0x14788`` with key byte ``0x00202050 & 0xff``.
    """
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    start = SCENE_INTERVAL_ROM // 4
    end = SCENE_ROOT_PTR_ROM // 4
    vals = [words[i] for i in range(start, end)]

    groups: list[IntervalGroup] = []
    cur: list[int] = []
    for v in vals:
        if v == 0xFF:
            if cur:
                pairs = [(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
                intervals = [(min(a, b), max(a, b)) for a, b in pairs if max(a, b) > 0]
                groups.append(IntervalGroup(index=len(groups), intervals=intervals))
                cur = []
        else:
            cur.append(v)
    if cur:
        pairs = [(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        intervals = [(min(a, b), max(a, b)) for a, b in pairs if max(a, b) > 0]
        groups.append(IntervalGroup(index=len(groups), intervals=intervals))
    return groups


def parse_scene_root_ptrs(rom_dir: Path | None = None) -> list[dict[str, str | int]]:
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    base = SCENE_ROOT_PTR_ROM // 4
    out: list[dict[str, str | int]] = []
    for i in range(8):
        w = words[base + i]
        if w == 0:
            break
        out.append(
            {
                "index": i,
                "workram_vaddr": f"0x{w:08x}",
                "rom_ptr": f"0x{SCENE_ROOT_PTR_ROM + i * 4:06x}",
            }
        )
    return out


def parse_course_select_workram_ptrs(rom_dir: Path | None = None) -> list[dict[str, str]]:
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    base = COURSE_SELECT_WORKRAM_ROM // 4
    out: list[dict[str, str]] = []
    for i in range(12):
        w = words[base + i]
        if w == 0:
            break
        if 0x0050_0000 <= w <= 0x0060_0000:
            out.append(
                {
                    "index": i,
                    "workram_vaddr": f"0x{w:08x}",
                    "rom_ptr": f"0x{COURSE_SELECT_WORKRAM_ROM + i * 4:06x}",
                }
            )
    return out


def catalog_dispatch_report(rom_dir: Path | None = None) -> dict:
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    buf_base = CATALOG_BATCH_BUFFERS_ROM // 4
    buffers = [f"0x{words[buf_base + i]:08x}" for i in range(4) if words[buf_base + i]]

    return {
        "batch_placement_fn": "0x0002b290",
        "single_placement_fn": "0x0002b420",
        "batch_callers": ["0x0002b6b0", "0x0002bab8"],
        "single_caller": "0x0002bb74",
        "workram_tables": {
            "batch_buffers": buffers,
            "catalog_index_by_slot": f"0x{CATALOG_DISPATCH_BY_SLOT:08x}",
            "catalog_index_by_quad": f"0x{CATALOG_DISPATCH_BY_QUAD:08x}",
        },
        "slot_index_source": "byte at offset 0x5c in scene object → ld 0x5ca210[index*4]",
        "quad_index_source": "byte at offset 0x54 & 3 → ld 0x5ca280[index*4]",
        "notes": [
            "0x5CA210 / 0x5CA280 map scene slots to catalog row indices (then ldq 0x2864b40).",
            "Tables are runtime workram — infer from disasm trace or lifted harness state.",
        ],
    }


def build_scene_tables_report(rom_dir: Path | None = None) -> dict:
    groups = parse_scene_interval_groups(rom_dir)
    return {
        "scene_interval_rom": f"0x{SCENE_INTERVAL_ROM:06x}",
        "scene_lookup_fn": "0x00014788",
        "lookup_key_byte": "0x00202050",
        "interval_groups": [
            {"index": g.index, "intervals": [{"lo": lo, "hi": hi} for lo, hi in g.intervals]}
            for g in groups
        ],
        "scene_root_ptrs": parse_scene_root_ptrs(rom_dir),
        "course_select_workram_ptrs": parse_course_select_workram_ptrs(rom_dir),
        "catalog_dispatch": catalog_dispatch_report(rom_dir),
        "metadata_table": {
            "workram_vaddr": "0x005b375c",
            "read_site": "0x000147a4",
            "init": "Pointers copied to workram at boot; interval templates from ROM 0x146E4.",
        },
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Scene interval + catalog dispatch tables (i960 ROM)")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960/scene_tables.json"))
    args = ap.parse_args()

    report = build_scene_tables_report(args.rom_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out} ({len(report['interval_groups'])} interval groups)")


if __name__ == "__main__":
    main()
