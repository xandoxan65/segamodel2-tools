"""Course select → scene pool → catalog dispatch call graph (i960 static RE)."""

from __future__ import annotations

import json
from pathlib import Path

from tools.i960_memory import (
    CATALOG_DISPATCH_BY_QUAD,
    CATALOG_DISPATCH_BY_SLOT,
    COURSE_SELECT_INDEX,
    COURSE_VARIANT_INDEX,
    VEHICLE_CATALOG_BATCH_FN,
    VEHICLE_CATALOG_SINGLE_FN,
)
from tools.i960_scene_tables import build_scene_tables_report, parse_scene_interval_groups
from tools.i960_tracks import UI_COURSE_ORDER, UI_COURSE_STRINGS_ROM
from tools.rom_io import resolve_rom_dir

# ROM anchors (maincpu disasm).
COURSE_SELECT_HANDLER_ROM = 0x0003_F220
COURSE_INDEX_SWAP_FN_ROM = 0x0003_F1F8
COURSE_HANDLER_TABLE_WORKRAM = 0x005D_E190  # ld @ 0x3F308 indexed by 0x214354
COURSE_SCENE_ROOT_TABLE_WORKRAM = 0x005D_DFC0  # ld @ 0x3F24C
CATALOG_INDEX_BY_VARIANT_WORKRAM = 0x005B_34E0  # ld @ 0x14B70
COURSE_SCENE_POOL_PTR_ROM = 0x0003_EFD0

SCENE_CLASSIFIER_ROM = 0x0001_46A8
SCENE_LOOKUP_ROM = 0x0001_4788
SCENE_RACE_INIT_ROM = 0x0001_4820

CATALOG_BATCH_THUNK_A_ROM = 0x0002_B580  # bx via 0x5CA5A0
CATALOG_BATCH_THUNK_B_ROM = 0x0002_BA80  # bx via 0x5CABA0
CATALOG_SINGLE_THUNK_ROM = 0x0002_BB50

CATALOG_BATCH_INNER_ROM = 0x0002_B5B0  # → call 0x2B6B0
CATALOG_BATCH_INNER_B_ROM = 0x0002_BAB8  # → call 0x2B290
CATALOG_SINGLE_INNER_ROM = 0x0002_BB74  # → call 0x2B420

# main_data track object labels (static strings).
TRACK_OBJECT_LABELS: dict[str, str] = {
    "desert": "0x020c98fc",
    "forest": "0x020d7cec",
    "lakeside": "0x020e683c",
    "mountain": "0x020f73d4",
    "championship_top": "0x0286b710",
}

# Hypothesis: menu index → scene pool @ ROM 0x3EFD0 (confirm with workram capture).
UI_COURSE_SCENE_POOL_HINT: dict[str, dict[str, str]] = {
    "desert": {
        "menu_index": "0",
        "scene_pool_workram": "0x005ca580",
        "track_label": "DESERT16",
        "confidence": "rom_ptr_order",
    },
    "forest": {
        "menu_index": "1",
        "scene_pool_workram": "0x005e3540",
        "track_label": "FOREST16",
        "confidence": "rom_ptr_order",
    },
    "mountain": {
        "menu_index": "2",
        "scene_pool_workram": "0x005ca6d0",
        "track_label": "MOUNTAIN16",
        "confidence": "rom_ptr_order",
    },
    "championship": {
        "menu_index": "3",
        "scene_pool_workram": "0x005caae0+ (multi-leg; LAKESIDE16 @ 0x020e683c)",
        "track_label": "CHAMP_TOP16 / LAKESIDE16",
        "confidence": "heuristic",
    },
}


def build_course_dispatch_report(*, rom_dir: Path | None = None) -> dict[str, object]:
    rom_dir = resolve_rom_dir(rom_dir)
    scene_tables = build_scene_tables_report(rom_dir)

    return {
        "workram_symbols": {
            "course_select_index": f"0x{COURSE_SELECT_INDEX:08x}",
            "course_variant_index": f"0x{COURSE_VARIANT_INDEX:08x}",
            "catalog_index_by_variant": f"0x{CATALOG_INDEX_BY_VARIANT_WORKRAM:08x}",
            "catalog_dispatch_by_slot": f"0x{CATALOG_DISPATCH_BY_SLOT:08x}",
            "catalog_dispatch_by_quad": f"0x{CATALOG_DISPATCH_BY_QUAD:08x}",
            "course_handler_table": f"0x{COURSE_HANDLER_TABLE_WORKRAM:08x}",
            "course_scene_root_table": f"0x{COURSE_SCENE_ROOT_TABLE_WORKRAM:08x}",
        },
        "ui_courses": {
            key: {
                "menu_string_rom": f"0x{UI_COURSE_STRINGS_ROM[key]:06x}",
                **UI_COURSE_SCENE_POOL_HINT[key],
            }
            for key in UI_COURSE_ORDER
        },
        "track_object_labels_main_data": TRACK_OBJECT_LABELS,
        "course_select_flow": {
            "handler_rom": f"0x{COURSE_SELECT_HANDLER_ROM:06x}",
            "index_swap_fn": f"0x{COURSE_INDEX_SWAP_FN_ROM:06x}",
            "steps": [
                "UI writes menu index → workram 0x215380 (ROM touch @ 0x3F200).",
                f"Handler @ 0x{COURSE_SELECT_HANDLER_ROM:06x} swaps index via 0x{COURSE_INDEX_SWAP_FN_ROM:06x}.",
                f"Scene root = ld 0x{COURSE_SCENE_ROOT_TABLE_WORKRAM:08x}[(entry+4)&31].",
                "Scene object built in course pool (ROM ptr table @ 0x3EFD0).",
                "callx *(scene_object+0xc) — indirect per-course setup.",
            ],
            "scene_pool_ptr_rom": f"0x{COURSE_SCENE_POOL_PTR_ROM:06x}",
            "scene_pools": scene_tables["course_select_workram_ptrs"],
        },
        "scene_race_init_flow": {
            "entry_rom": f"0x{SCENE_RACE_INIT_ROM:06x}",
            "classifier_rom": f"0x{SCENE_CLASSIFIER_ROM:06x}",
            "lookup_rom": f"0x{SCENE_LOOKUP_ROM:06x}",
            "steps": [
                "scene_classifier @ 0x146A8 reads 0x20A8B8 → mode 0/1/2.",
                "scene_lookup @ 0x14788 with table index 5 → course_variant_index @ 0x214354 = result - 2.",
                "Branch @ 0x14B04 on course_variant_index picks scene-object field block.",
                f"ld 0x{CATALOG_INDEX_BY_VARIANT_WORKRAM:08x}[variant&3] → catalog row for first push.",
                "Pushes draw layers 0x2865650, 0x2865620, 0x2865740 (scene-init path).",
            ],
            "variant_branches": [
                {
                    "variant": 0,
                    "site": "0x014b14",
                    "effect": "Use workram snapshot @ 0x5B3800 for scene object +0x40/+0x48",
                },
                {
                    "variant": 1,
                    "site": "0x014b30",
                    "effect": "Use 0x5B3808 path for +0x48 handler target",
                },
                {
                    "variant": "2+",
                    "site": "0x014b3c",
                    "effect": "Alternate workram snapshot for +0x68/+0x60 fields",
                },
            ],
            "interval_groups": [
                {
                    "scene_table_index": g.index,
                    "catalog_index_intervals": [{"lo": lo, "hi": hi} for lo, hi in g.intervals],
                }
                for g in parse_scene_interval_groups(rom_dir)
            ],
        },
        "catalog_dispatch_call_graph": {
            "batch_placement_fn": f"0x{VEHICLE_CATALOG_BATCH_FN:06x}",
            "single_placement_fn": f"0x{VEHICLE_CATALOG_SINGLE_FN:06x}",
            "thunks": [
                {
                    "thunk_rom": f"0x{CATALOG_BATCH_THUNK_A_ROM:06x}",
                    "jump_table_workram": "0x005ca5a0",
                    "handler_table_workram": "0x005ca420",
                    "inner_rom": f"0x{CATALOG_BATCH_INNER_ROM:06x}",
                    "calls": f"0x{CATALOG_BATCH_INNER_ROM:06x} → 0x2B6B0 → 0x2B290",
                    "index_source": "scene_object+0x54 & 3 → ld 0x5CA280[index*4]",
                    "batch_buffer": "workram batch struct @ 0x5CA1A0 area",
                    "role": "Quad/split batch catalog push during scene tick",
                },
                {
                    "thunk_rom": f"0x{CATALOG_BATCH_THUNK_B_ROM:06x}",
                    "jump_table_workram": "0x005caba0",
                    "handler_table_workram": "0x005cab50",
                    "inner_rom": f"0x{CATALOG_BATCH_INNER_B_ROM:06x}",
                    "calls": f"0x{CATALOG_BATCH_INNER_B_ROM:06x} → 0x2B290",
                    "batch_buffer": "ld 0x5CA180",
                    "role": "Alternate batch path (preview/menu scene objects)",
                },
                {
                    "thunk_rom": f"0x{CATALOG_SINGLE_THUNK_ROM:06x}",
                    "jump_table_workram": "0x005caba0",
                    "inner_rom": f"0x{CATALOG_SINGLE_INNER_ROM:06x}",
                    "calls": f"0x{CATALOG_SINGLE_INNER_ROM:06x} → 0x2B420",
                    "gates": [
                        "0x202230 == 0",
                        "0x217184 bit 2 clear",
                        "0x202098 != 2",
                    ],
                    "index_source": "scene_object+0x5c → ld 0x5CA210[slot*4]",
                    "preview_vs_race": "0x2B420 XORs object+0x60 with 0x2020A4 for geo preamble",
                    "role": "Single catalog row push (tail placements / props)",
                },
            ],
        },
        "draw_script_binding": {
            "shared_race_script": {
                "vaddr": "0x028656c0",
                "layers": 136,
                "placement_segments": 13,
                "note": "All courses share one placement stream; course differs by which intervals/catalog rows are active.",
            },
            "preview_lists": {
                "vaddr": "0x02865790",
                "fed_by": "geo_cluster_01 @ 0x42d2c via scene slot byte +0x5c",
                "note": "Separate smaller command lists for menu/preview rotation.",
            },
            "race_branches": {
                "layers": ["0x028656e0", "0x02865780", "0x02865770"],
                "fed_by": "geo_cluster_10 @ 0x13e84 branches on 0x202230",
            },
        },
        "static_confirmed": [
            "0x3EFD0 ROM table lists seven course scene pool workram roots.",
            "0x214354 written by scene_lookup @ 0x148AC (index 5, minus 2).",
            "0x14B70 indexes catalog via 0x5B34E0[variant&3].",
            "Catalog dispatch uses bx thunks — not direct call immediates.",
        ],
        "needs_workram_re": [
            f"0x{CATALOG_INDEX_BY_VARIANT_WORKRAM:08x} — four catalog indices per variant",
            f"0x{COURSE_HANDLER_TABLE_WORKRAM:08x} — per-variant callx targets",
            f"0x{COURSE_SCENE_ROOT_TABLE_WORKRAM:08x} — scene root pointers",
            "0x005B4340 — definitive catalog row per course slot",
            "0x005CA210 / 0x005CA280 — slot/quad dispatch tables at race start",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Course select → catalog dispatch call graph")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960/course_dispatch_report.json"))
    args = ap.parse_args()

    report = build_course_dispatch_report(rom_dir=args.rom_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
