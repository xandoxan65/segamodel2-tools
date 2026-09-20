"""Track geometry command lists from i960 code usage (not ROM heuristics)."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from tools.i960_memory import (
    CATALOG_VADDR,
    MAIN_DATA_A,
    PLACEMENT_STREAM_VADDR,
    VEHICLE_CATALOG_BATCH_FN,
    VEHICLE_CATALOG_SINGLE_FN,
)
from tools.i960_course_dispatch import build_course_dispatch_report
from tools.i960_scene_tables import build_scene_tables_report
from tools.model2_catalog import parse_catalog, parse_placement_stream
from tools.model2_scenes import (
    DRAW_SCRIPT_VADDR,
    DrawLayer,
    parse_cpu_draw_entry,
    parse_track_draw_layers,
    placement_segments_from_draw_layers,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, u32_words

# main_data band holding draw-layer records (16-byte stride-4 quads).
DRAW_LAYER_BAND_LO = 0x0286_5600
DRAW_LAYER_BAND_HI = 0x0286_9000

DRAW_LDQ_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):.*\bldq\s+0x(286[0-9a-f]{3,5})",
    re.I,
)
DRAW_LD_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):.*\bld\s+0x(286[0-9a-f]{3,5})",
    re.I,
)
STQ_GEO_FIFO_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):.*\bstq\s+\S+,\s*0x804000",
    re.I,
)

# Code-referenced draw-layer blocks with known roles (from disasm cluster names).
KNOWN_DRAW_BLOCKS: dict[int, dict[str, str]] = {
    0x0286_56C0: {"role": "race_scene_primary", "cluster": "geo_cluster_10 @ 0x13e84"},
    0x0286_56D0: {"role": "race_scene_followup", "cluster": "geo_cluster_10 @ 0x1409c"},
    0x0286_56E0: {"role": "race_scene_branch_a", "cluster": "geo_cluster_10 @ 0x13f90 (0x202230)"},
    0x0286_5780: {"role": "race_scene_branch_b", "cluster": "geo_cluster_10 @ 0x13ff4"},
    0x0286_5770: {"role": "race_scene_branch_c", "cluster": "geo_cluster_10 @ 0x14118"},
    0x0286_5620: {"role": "scene_init_preamble", "cluster": "geo_cluster_11 @ 0x14c18"},
    0x0286_5650: {"role": "scene_init_preamble", "cluster": "geo_cluster_11 @ 0x149e8"},
    0x0286_5660: {"role": "scene_batch_b", "cluster": "geo_cluster_04 @ 0x158ec"},
    0x0286_5680: {"role": "scene_batch_a", "cluster": "geo_cluster_04 @ 0x157bc"},
    0x0286_5730: {"role": "scene_descriptor_block", "cluster": "geo_cluster_04 @ 0x15548"},
    0x0286_5740: {"role": "scene_lookup_major", "cluster": "geo_cluster_11 @ 0x14c94"},
    0x0286_57C0: {"role": "preview_menu_block_0", "cluster": "geo_cluster_01 @ 0x42d4c"},
    0x0286_5790: {"role": "preview_menu_block_1", "cluster": "geo_cluster_01 @ 0x42f74"},
    0x0286_57A0: {"role": "preview_menu_block_2", "cluster": "geo_cluster_01 @ 0x42dfc"},
    0x0286_57B0: {"role": "preview_menu_block_3", "cluster": "geo_cluster_01 @ 0x4317c"},
    0x0286_7DC0: {"role": "race_fx_catalog_a", "cluster": "geo_cluster_02 @ 0x456f4"},
    0x0286_7E00: {"role": "race_fx_catalog_b", "cluster": "geo_cluster_02 @ 0x456a8"},
    0x0286_5C30: {"role": "vehicle_scene_catalog", "cluster": "geo_cluster_02 @ 0x45cd8"},
    0x0286_A540: {"role": "unknown_aux_block", "cluster": "geo_cluster_07 @ 0x3bbc8"},
}


@dataclass(frozen=True)
class DrawLayerPush:
    draw_vaddr: int
    caller_pc: int
    stq_pc: int
    disasm_file: str


def normalize_main_data_vaddr(raw: int) -> int:
    if raw < MAIN_DATA_A:
        return MAIN_DATA_A + (raw & 0x00FF_FFFF)
    return raw


def scan_draw_layer_pushes(disasm_dir: Path) -> list[DrawLayerPush]:
    """Find ldq main_data draw record → stq geo_prg_fifo (0x804000) in disassembly."""
    pushes: list[DrawLayerPush] = []
    if not disasm_dir.is_dir():
        return pushes

    for path in sorted(disasm_dir.glob("*.asm")):
        pending_vaddr: int | None = None
        pending_pc: int | None = None
        age = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = DRAW_LDQ_RE.match(line)
            if m:
                pending_pc = int(m.group(1), 16)
                pending_vaddr = normalize_main_data_vaddr(int(m.group(2), 16))
                age = 0
                continue
            if pending_vaddr is not None:
                m2 = STQ_GEO_FIFO_RE.match(line)
                if m2 and age <= 48:
                    pushes.append(
                        DrawLayerPush(
                            draw_vaddr=pending_vaddr,
                            caller_pc=pending_pc or 0,
                            stq_pc=int(m2.group(1), 16),
                            disasm_file=path.name,
                        )
                    )
                    pending_vaddr = None
                    age = 0
                    continue
                age += 1
                if age > 48:
                    pending_vaddr = None
    return pushes


def scan_draw_field_load_clusters(disasm_dir: Path) -> dict[int, list[dict[str, str]]]:
    """ld 0x2865xxx (individual draw-layer fields loaded before stack ldq/stq)."""
    hits: dict[int, list[dict[str, str]]] = defaultdict(list)
    if not disasm_dir.is_dir():
        return hits
    for path in sorted(disasm_dir.glob("*.asm")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = DRAW_LD_RE.match(line)
            if not m:
                continue
            vaddr = normalize_main_data_vaddr(int(m.group(2), 16))
            if DRAW_LAYER_BAND_LO <= vaddr < DRAW_LAYER_BAND_HI:
                hits[vaddr].append(
                    {
                        "pc": f"0x{int(m.group(1), 16):06x}",
                        "file": path.name,
                    }
                )
    return dict(hits)


def layer_record(layer: DrawLayer | None) -> dict[str, object] | None:
    if layer is None:
        return None
    return {
        "vaddr": f"0x{layer.vaddr:08x}",
        "workram_field_a": layer.field_a,
        "workram_field_b": layer.field_b,
        "polygon_oba": f"0x{layer.oba:08x}",
        "placement_cursor_end": layer.obc,
    }


def build_track_geometry_report(
    *,
    rom_dir: Path | None = None,
    disasm_dir: Path | None = None,
) -> dict[str, object]:
    rom_dir = resolve_rom_dir(rom_dir)
    disasm_dir = disasm_dir or (Path(__file__).resolve().parents[1] / "out" / "i960" / "disasm")

    main_data = u32_words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
    polygon_rom = u32_words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"]))
    mask = len(polygon_rom) - 1

    placements = parse_placement_stream(main_data, polygon_rom, polygon_rom_mask=mask)
    catalog = parse_catalog(main_data, mask=mask)
    track_layers = parse_track_draw_layers(main_data, max_placement_index=len(placements))
    segments = placement_segments_from_draw_layers(track_layers, max_placement_index=len(placements))
    layer_by_index = {layer.index: layer for layer in track_layers}

    pushes = scan_draw_layer_pushes(disasm_dir)
    field_loads = scan_draw_field_load_clusters(disasm_dir)

    # Unique code-pushed draw-layer records (exclude catalog @ 0x2864B40).
    by_vaddr: dict[int, list[DrawLayerPush]] = defaultdict(list)
    for push in pushes:
        if push.draw_vaddr == CATALOG_VADDR:
            continue
        if DRAW_LAYER_BAND_LO <= push.draw_vaddr < DRAW_LAYER_BAND_HI:
            by_vaddr[push.draw_vaddr].append(push)

    code_referenced: list[dict[str, object]] = []
    for vaddr in sorted(by_vaddr):
        layer = parse_cpu_draw_entry(main_data, vaddr)
        meta = KNOWN_DRAW_BLOCKS.get(vaddr, {})
        callers = by_vaddr[vaddr]
        code_referenced.append(
            {
                "draw_vaddr": f"0x{vaddr:08x}",
                "role": meta.get("role", "code_referenced"),
                "cluster": meta.get("cluster"),
                "push_count": len(callers),
                "callers": [
                    {
                        "rom_pc": f"0x{c.caller_pc:06x}",
                        "stq_pc": f"0x{c.stq_pc:06x}",
                        "disasm": c.disasm_file,
                    }
                    for c in callers[:8]
                ],
                "layer": layer_record(layer),
            }
        )

    # Contiguous draw-script sequences (one list may span many layers).
    sequences: list[dict[str, object]] = [
        {
            "name": "race_placement_draw_script",
            "start_vaddr": f"0x{DRAW_SCRIPT_VADDR:08x}",
            "layer_count": len(track_layers),
            "end_vaddr": f"0x{track_layers[-1].vaddr:08x}" if track_layers else None,
            "placement_instances": len(placements),
            "fed_by": "geo_cluster_10 @ 0x13e84 pushes layer 0; subsequent layers driven by draw script",
            "placement_segments": [
                {
                    "placement_range": [start, end],
                    "draw_layer_index": layer_idx,
                    "draw_layer_vaddr": (
                        f"0x{layer_by_index[layer_idx].vaddr:08x}"
                        if layer_idx in layer_by_index
                        else None
                    ),
                    "placement_cursor_obc": (
                        layer_by_index[layer_idx].obc if layer_idx in layer_by_index else None
                    ),
                }
                for start, end, layer_idx in segments
            ],
        },
        {
            "name": "preview_menu_draw_blocks",
            "start_vaddr": "0x02865790",
            "layer_count": 4,
            "fed_by": "geo_cluster_01 @ 0x42d2c (slot index @ scene object +0x5c)",
            "notes": "Separate smaller lists for course preview / menu rotation",
            "blocks": [
                layer_record(parse_cpu_draw_entry(main_data, v))
                for v in (0x0286_57C0, 0x0286_5790, 0x0286_57A0, 0x0286_57B0)
            ],
        },
        {
            "name": "race_scene_branch_layers",
            "fed_by": "geo_cluster_10 branches on workram 0x202230 / 0x202008",
            "blocks": [
                layer_record(parse_cpu_draw_entry(main_data, v))
                for v in (0x0286_56E0, 0x0286_5780, 0x0286_5770, 0x0286_56D0)
            ],
        },
    ]

    return {
        "storage_model": {
            "summary": (
                "Track geometry is not one ROM mesh. It is (1) mesh templates in the master "
                "catalog, (2) a static placement stream of instances, and (3) draw-layer command "
                "records the CPU pushes to geo FIFO 0x804000. Each draw layer is a 16-byte quad "
                "(workram_a, workram_b, polygon_oba, placement_cursor_end)."
            ),
            "catalog": {
                "vaddr": f"0x{CATALOG_VADDR:08x}",
                "entries": len(catalog),
                "bytes_per_entry": 16,
            },
            "placement_stream": {
                "vaddr": f"0x{PLACEMENT_STREAM_VADDR:08x}",
                "instances": len(placements),
                "stride_bytes": 16,
                "record": "(tpa, tha, polygon_oba, obc)",
            },
            "draw_layer_record": {
                "stride_bytes": 16,
                "record": "(workram_field_a, workram_field_b, polygon_oba, placement_cursor_end)",
                "placement_cursor_workram": "0x0020B940",
                "feeder_cluster": "0x00023CC8 (ldq catalog → stq FIFO; cursor += catalog.obc)",
            },
        },
        "geo_pipelines": {
            "track_placement_feeder": {
                "entry": "0x00023cc8",
                "pushes": "ldq 0x2864b40[index×16] per catalog row",
                "catalog_push_sites_in_disasm": sum(1 for p in pushes if p.draw_vaddr == CATALOG_VADDR),
            },
            "batch_catalog_dispatch": {
                "entry": f"0x{VEHICLE_CATALOG_BATCH_FN:06x}",
                "role": "Iterates draw-script-linked batch buffers; pushes catalog rows",
                "callers": ["0x0002b6b0", "0x0002bab8"],
            },
            "single_catalog_dispatch": {
                "entry": f"0x{VEHICLE_CATALOG_SINGLE_FN:06x}",
                "role": "One catalog row via 0x5CA210[slot]; XOR 0x2020A4 vs object+0x60 toggles preamble",
                "callers": ["0x0002bb74"],
                "preview_vs_race_hint": "Different geo preamble constants on XOR branch",
            },
        },
        "unique_code_pushed_draw_layers": code_referenced,
        "draw_field_load_sites": {
            f"0x{v:08x}": sites[:4]
            for v, sites in sorted(field_loads.items())
            if v not in by_vaddr
        },
        "draw_script_sequences": sequences,
        "course_dispatch": build_course_dispatch_report(rom_dir=rom_dir),
        "scene_tables": build_scene_tables_report(rom_dir),
        "notes": [
            "Do not use polygon ROM bank quarters (bank2/bank3) as track identity — those are mesh libraries.",
            "Use placement_segments from draw_script_sequences.race_placement_draw_script, not walk_polygon_rom.",
            "Monotonic draw-script cursors reach placement index 511 (layer 135); placements 511–517 are not "
            "tied to a further obc step in the main script — likely drawn via catalog batch/single dispatch.",
            "Course names (desert/forest/…) require workram capture of 0x005B4340 / 0x005CA210 at course select.",
            "Interval groups @ ROM 0x146E4 filter which catalog/placement slices scene_lookup @ 0x14788 activates.",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Track geometry command lists from i960 code xrefs")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--disasm-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out/i960/track_geometry_report.json"))
    args = ap.parse_args()

    report = build_track_geometry_report(rom_dir=args.rom_dir, disasm_dir=args.disasm_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    seq = report["draw_script_sequences"][0]
    print(
        f"Race draw script: {seq['layer_count']} layers, "
        f"{len(seq['placement_segments'])} placement segments, "
        f"{len(report['unique_code_pushed_draw_layers'])} code-pushed unique draw blocks"
    )


if __name__ == "__main__":
    main()
