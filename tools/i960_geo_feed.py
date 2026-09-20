#!/usr/bin/env python3
"""Map maincpu ROM sites that feed the Model 2 geometry engine (static RE)."""

from __future__ import annotations

import argparse
import json
import re
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from tools.decomp.disasm_paths import DECOMP_DISASM, iter_asm_files
from tools.i960_memory import (
    CATALOG_VADDR,
    COPY_CATALOG_INDEX_TABLE_FN,
    DRAW_CATALOG_SEQUENCE_FN,
    GEO_PRG_FIFO,
    GEO_WRITE_START,
    PLACEMENT_CURSOR,
    VEHICLE_CATALOG_SINGLE_FN,
    VEHICLE_DRAW_CATALOG_FN,
    VEHICLE_GEO_FIFO,
    VEHICLE_OBJECT_SETUP_FN,
)
from tools.i960_scan import load_maincpu_words
from tools.i960_vehicles import (
    build_vehicle_geo_chain,
    parse_rom_vehicle_descriptors,
    parse_vehicle_catalog_tables,
)
from tools.model2_scenes import CPU_DRAW_ENTRY_VADDRS, DRAW_SCRIPT_VADDR, parse_cpu_draw_entries
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

GEO_FEED_PORTS: dict[int, str] = {
    VEHICLE_GEO_FIFO: "copro_fifo",
    GEO_PRG_FIFO: "geo_prg_fifo",
    GEO_WRITE_START: "geo_write_start",
    0x0080_2008: "geo_context",
}

CATALOG_LDQ_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):\s+.*ldq\s+0x2864b40",
    re.I,
)
FIFO_STQ_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):\s+.*stq\s+\S+,\s*(0x804000|0x884000)",
    re.I,
)
CALL_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):\s+.*\b(?:call|bal|callx|bl)\s+0x([0-9a-f]+)",
    re.I,
)
PORT_ST_RE = re.compile(
    r"^([0-9A-Fa-f]{8}):\s+.*\bst(?:q)?\s+\S+,\s*(0x[0-9a-f]+)",
    re.I,
)


@dataclass(frozen=True)
class CatalogPushSite:
    rom_pc: int
    catalog_ldq_pc: int
    fifo_stq_pc: int
    fifo: str


@dataclass(frozen=True)
class KnownPipeline:
    entry: int
    name: str
    role: str
    fifo: str
    catalog_source: str
    index_source: str
    callers: list[str]


KNOWN_PIPELINES: list[KnownPipeline] = [
    KnownPipeline(
        0x0002_3CC8,
        "track_placement_feeder",
        "Per-frame track/object placement from main_data catalog",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[index×16]",
        "placement stream + workram cursor 0x20B940",
        ["scene draw loop"],
    ),
    KnownPipeline(
        DRAW_CATALOG_SEQUENCE_FN,
        "draw_catalog_sequence",
        "Batch catalog rows → geo FIFO during vehicle/scene object setup",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[g5×16] from staging struct",
        "workram staging 0x5E2890 / 0x5E2900 (indices from ROM descriptors)",
        [f"0x{VEHICLE_OBJECT_SETUP_FN:06x} vehicle_object_setup"],
    ),
    KnownPipeline(
        COPY_CATALOG_INDEX_TABLE_FN,
        "copy_catalog_index_table",
        "Copies catalog index arrays into workram (indirect via dest pointer r11) "
        "and runs a geo-push loop @ 0x28528 (ldq catalog → stq 0x804000)",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[g5×16] in tail loop @ 0x28658",
        "ROM descriptor +0x0C index runs → workram; staging g5 from struct",
        ["vehicle init chain"],
    ),
    KnownPipeline(
        VEHICLE_CATALOG_SINGLE_FN,
        "catalog_single_dispatch",
        "Single catalog object dispatch (car parts path)",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[g5×16]",
        "argument struct + workram tables",
        ["0x2BAB8", "0x2BB74"],
    ),
    KnownPipeline(
        0x0002_B290,
        "catalog_batch_dispatch",
        "Scene/vehicle batch dispatch (draw-script driven)",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[g5×16]",
        "main_data draw-script entries @ 0x2856xx",
        ["0x2B6B0"],
    ),
    KnownPipeline(
        VEHICLE_DRAW_CATALOG_FN,
        "draw_car_primary",
        "Race-time per-player vehicle draw",
        "copro_fifo + geo_prg_fifo",
        "ldq 0x2864b40[slot×16]",
        "workram 0x5E3DF0 / 0x5E3DF8[slot×4] (filled by copy_catalog_index_table)",
        ["vehicle_state_dispatch 0x451E0"],
    ),
]


def scan_port_immediates(words: list[int]) -> dict[str, list[str]]:
    """ROM PCs where a geo port address appears as an instruction immediate."""
    out: dict[str, list[str]] = defaultdict(list)
    for i, w in enumerate(words):
        name = GEO_FEED_PORTS.get(w)
        if name:
            out[name].append(f"0x{i * 4:06x}")
    return {k: v for k, v in sorted(out.items())}


def scan_catalog_push_pairs(words: list[int], *, window_words: int = 24) -> list[CatalogPushSite]:
    """Find ldq catalog → stq fifo sequences in raw ROM (word-aligned scan)."""
    sites: list[CatalogPushSite] = []
    for i, w in enumerate(words):
        if w != CATALOG_VADDR:
            continue
        ldq_pc = (i - 1) * 4 if i > 0 else i * 4
        for j in range(i + 1, min(i + 1 + window_words, len(words))):
            wj = words[j]
            if wj == GEO_PRG_FIFO:
                sites.append(
                    CatalogPushSite(
                        rom_pc=ldq_pc,
                        catalog_ldq_pc=ldq_pc,
                        fifo_stq_pc=j * 4,
                        fifo="geo_prg_fifo",
                    )
                )
                break
            if wj == VEHICLE_GEO_FIFO:
                # copro-only push without prg fifo — skip unless no prg follows soon
                continue
    return sites


def cluster_pcs(pcs: list[int], gap: int = 0x180) -> list[dict[str, str | int]]:
    if not pcs:
        return []
    pcs = sorted(pcs)
    clusters: list[list[int]] = [[pcs[0]]]
    for pc in pcs[1:]:
        if pc - clusters[-1][-1] > gap:
            clusters.append([pc])
        else:
            clusters[-1].append(pc)
    return [
        {
            "rom_start": f"0x{cl[0]:06x}",
            "rom_end": f"0x{cl[-1]:06x}",
            "site_count": len(cl),
        }
        for cl in clusters
    ]


def parse_disasm_dir(disasm_dir: Path) -> dict[str, object]:
    catalog_pushes: list[dict[str, str]] = []
    port_stores: dict[str, list[str]] = defaultdict(list)
    calls: dict[str, list[str]] = defaultdict(list)
    fn_entries: dict[str, str] = {}

    for path in iter_asm_files(disasm_dir):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        pending_ldq: str | None = None
        pending_age = 0
        for line in lines:
            m = CATALOG_LDQ_RE.match(line)
            if m:
                pending_ldq = m.group(1)
                pending_age = 0
                continue
            m = FIFO_STQ_RE.match(line)
            if m and pending_ldq and pending_age <= 20:
                catalog_pushes.append(
                    {
                        "file": path.name,
                        "catalog_ldq": f"0x{int(pending_ldq, 16):06x}",
                        "fifo_stq": f"0x{int(m.group(1), 16):06x}",
                        "fifo": "geo_prg_fifo" if m.group(2).lower() == "0x804000" else "copro_fifo",
                    }
                )
                pending_ldq = None
                pending_age = 0
                continue
            if pending_ldq:
                pending_age += 1
                if pending_age > 20:
                    pending_ldq = None

            m = PORT_ST_RE.match(line)
            if m:
                port = int(m.group(2), 16)
                if port in GEO_FEED_PORTS:
                    port_stores[GEO_FEED_PORTS[port]].append(
                        f"0x{int(m.group(1), 16):06x}"
                    )

            m = CALL_RE.match(line)
            if m:
                src = f"0x{int(m.group(1), 16):06x}"
                dst = f"0x{int(m.group(2), 16):06x}"
                calls[dst].append(src)
                fn_entries[src] = path.name

    vehicle_targets = [
        f"0x{COPY_CATALOG_INDEX_TABLE_FN:06x}",
        f"0x{DRAW_CATALOG_SEQUENCE_FN:06x}",
        f"0x{VEHICLE_OBJECT_SETUP_FN:06x}",
        f"0x{VEHICLE_DRAW_CATALOG_FN:06x}",
        "0x0451e0",
        "0x045240",
        "0x034f40",
        "0x033e90",
    ]
    vehicle_callers = {
        dst: sorted(set(srcs))
        for dst, srcs in calls.items()
        if dst in vehicle_targets
    }

    return {
        "catalog_push_sites": catalog_pushes,
        "port_stores_from_disasm": {k: len(v) for k, v in port_stores.items()},
        "callers": {k: sorted(set(v))[:16] for k, v in sorted(calls.items()) if len(v) <= 32},
        "vehicle_callers": vehicle_callers,
        "top_callees": sorted(
            ((dst, len(srcs)) for dst, srcs in calls.items()),
            key=lambda x: -x[1],
        )[:20],
    }


def static_table_feeders(rom_dir: Path) -> dict[str, object]:
    main_data = list(
        struct.unpack(
            f"<{len(load32_word_region(rom_dir, SRALLY_DATA_ROMS['main_data'])) // 4}I",
            load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]),
        )
    )
    draw_layers = parse_cpu_draw_entries(main_data)
    vehicle_tables = parse_vehicle_catalog_tables(rom_dir)
    descriptors = parse_rom_vehicle_descriptors(rom_dir)

    return {
        "main_data_draw_script": {
            "vaddr": f"0x{DRAW_SCRIPT_VADDR:08x}",
            "cpu_entry_anchors": [f"0x{v:08x}" for v in CPU_DRAW_ENTRY_VADDRS],
            "parsed_layers": len(draw_layers),
            "layers": [
                {
                    "vaddr": f"0x{layer.vaddr:08x}",
                    "oba": f"0x{layer.oba:08x}",
                    "obc": layer.obc,
                }
                for layer in draw_layers[:16]
            ],
        },
        "vehicle_rom_tables": [
            {
                "rom": f"0x{t.rom_offset:06x}",
                "name": t.name,
                "catalog_indices": t.catalog_indices[:24],
                "feeds": f"0x{VEHICLE_OBJECT_SETUP_FN:06x} via 0x{DRAW_CATALOG_SEQUENCE_FN:06x}",
            }
            for t in vehicle_tables
        ],
        "vehicle_rom_descriptors": [
            {
                "rom": f"0x{d.rom_offset:06x}",
                "kind": d.kind,
                "main_data_vaddr": f"0x{d.main_data_vaddr:08x}",
                "catalog_indices": d.catalog_indices,
                "feeds": f"copy_catalog_index_table @ 0x{COPY_CATALOG_INDEX_TABLE_FN:06x}",
            }
            for d in descriptors
        ],
    }


def build_geo_feed_report(
    *,
    rom_dir: Path | None = None,
    disasm_dir: Path | None = None,
) -> dict[str, object]:
    from tools.i960_decode import disasm_coverage_summary

    rom_dir = resolve_rom_dir(rom_dir)
    disasm_dir = disasm_dir or DECOMP_DISASM

    _, words = load_maincpu_words(rom_dir)
    port_hits = scan_port_immediates(words)
    push_pairs = scan_catalog_push_pairs(words)

    catalog_ldq_pcs = [i * 4 for i, w in enumerate(words) if w == CATALOG_VADDR]
    disasm = parse_disasm_dir(disasm_dir) if disasm_dir.is_dir() else {}

    pipelines = []
    call_map = disasm.get("callers", {})
    for p in KNOWN_PIPELINES:
        entry = f"0x{p.entry:06x}"
        pipelines.append(
            {
                "entry": entry,
                "name": p.name,
                "role": p.role,
                "fifo": p.fifo,
                "catalog_source": p.catalog_source,
                "index_source": p.index_source,
                "callers": sorted(set(call_map.get(entry, []) + p.callers)),
            }
        )

    disasm_coverage = disasm_coverage_summary(disasm_dir) if disasm_dir.is_dir() else {}

    return {
        "rom_dir": str(rom_dir),
        "disasm_dir": str(disasm_dir),
        "disasm_coverage": disasm_coverage,
        "geo_port_hits": {k: len(v) for k, v in port_hits.items()},
        "catalog_base_immediates": len(catalog_ldq_pcs),
        "catalog_push_pairs_rom_scan": len(push_pairs),
        "catalog_push_clusters": cluster_pcs([s.catalog_ldq_pc for s in push_pairs]),
        "catalog_push_sites_disasm": disasm.get("catalog_push_sites", []),
        "feed_pipelines": pipelines,
        "static_table_feeders": static_table_feeders(rom_dir),
        "vehicle_geometry": build_vehicle_geo_chain(rom_dir),
        "disasm_call_summary": {
            "catalog_push_count": len(disasm.get("catalog_push_sites", [])),
            "port_stores": disasm.get("port_stores_from_disasm", {}),
            "top_callees": disasm.get("top_callees", []),
            "vehicle_callers": disasm.get("vehicle_callers", {}),
        },
        "next_rom_slices": [
            {
                "rom": "0x03ee98",
                "length": "0x200",
                "why": "callee of geo push helper @ 0x03EF70",
            },
            {
                "rom": "0x042000",
                "length": "0x400",
                "why": "vehicle ctor cluster near descriptor tables",
            },
            {
                "rom": "0x015524",
                "length": "0x400",
                "why": "scene descriptor loader → draw-script tables",
            },
        ],
        "notes": [
            "Geometry is fed via copro FIFO 0x884000 (opcodes/matrix) then geo prg FIFO 0x804000 (catalog ldq rows).",
            "geo_write_start 0x801008 commits bufferram pointer after each object batch.",
            "Track and vehicles share catalog 0x2864B40 but use different index sources and FIFO scheduling.",
            "Vehicle bodies: ROM descriptors @ 0x43830 + tables @ 0x34E40/0x34E88 → copy_catalog @ 0x282D0 → draw_catalog_sequence @ 0x280D0 → draw_car_primary @ 0x44F00.",
            "Body shells are catalog 96–99 and 106–107; export via: python3 -m tools.extract.vehicles",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="ROM map of Model 2 geometry engine feed sites")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--disasm-dir", type=Path, default=DECOMP_DISASM)
    ap.add_argument("--out", type=Path, default=Path("out/i960/geo_feed_report.json"))
    args = ap.parse_args()

    report = build_geo_feed_report(rom_dir=args.rom_dir, disasm_dir=args.disasm_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    n_push = len(report.get("catalog_push_sites_disasm", []))
    n_pipe = len(report.get("feed_pipelines", []))
    print(f"Wrote {args.out} ({n_pipe} pipelines, {n_push} catalog→fifo sites in disasm)")


if __name__ == "__main__":
    main()
