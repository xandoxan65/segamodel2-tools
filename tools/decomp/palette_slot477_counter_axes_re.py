#!/usr/bin/env python3
"""Disasm RE: counter axes for tier-B slot 477 — ``0x20C950`` vs ``0x20C954`` vs FIFO.

Clarifies why ``0x29F7C`` group index ≠ colorbase slot 477, documents
``0x02A120`` / ``0x02A290`` reachability, and correlates Python replay with
static ``0x29F0C`` node walks (negative for marker-split payload).

No MAME.  No XOR inference.

  python3 -m tools.decomp.palette_slot477_counter_axes_re
  python3 -m tools.decomp.palette_slot477_counter_axes_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_1111_stream_walk_re import build_report as build_1111_walk
from tools.decomp.palette_block_stream_link_re import build_report as build_block_link
from tools.decomp.palette_record_plus14_fifo_re import _fifo_read_inventory
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_1111 import replay_1111_record
from tools.model2_palette import PaletteState, load_colorxlat_from_main_data
from tools.decomp.palette_29eb0_stream_walker import _desert_1111_payload
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

COUNTER_AXES = (
    {
        "workram": "0x0020C950",
        "name": "colorbase_slot_cursor",
        "disasm": "``0x29F54`` span add; ``0x2A290`` +24 batch; replay ``stream_cursor``",
        "slot_477_meaning": "Python replay assigns **palette slot 477** here during format-walk ``D``",
    },
    {
        "workram": "0x0020C954",
        "name": "group_table_index",
        "disasm": "``0x029F7C`` loop index → ``0x20B950[g4*8]`` row; ``0x02A120`` merge bound",
        "slot_477_meaning": "**Not** colorbase slot — tier-B clamp @ ``0x029AA0`` rejects ``g0>0x7F`` for low-slot thunks",
    },
    {
        "workram": "0x0020C958",
        "name": "g13_anchor",
        "disasm": "``0x2A290`` ``shlo 7`` from ``0x20C950``; ``0x29CD8`` OR into ``g13``",
        "slot_477_meaning": "Mask seed for ADD/XOR paths — ``(477<<7)|0x8040`` style anchors in replay",
    },
    {
        "name": "fifo_read_index",
        "disasm": "``0x29CF8`` / ``0x02A148`` / ``0x02A250`` ``ldos`` consumers",
        "slot_477_meaning": "Replay: **463** prior u16 reads before ``0x8843`` @ ``fifo+0x3A6``",
    },
)

DISASM_2A120 = (
    {"rom": "0x02A120", "effect": "``ldob 0x20B953[g0*8]`` — merge enable; **ret** if zero"},
    {"rom": "0x02A148", "effect": "``ldos (g4),g3`` — FIFO u16 from group row head chain"},
    {"rom": "0x02A164", "effect": "Linked-list copy loop — **no** ``xor g13``"},
    {"rom": "0x02A1C0", "effect": "``bal 0x026918`` — scratch → palram commit"},
    {"rom": "0x02A1F0", "effect": "``ret`` — record-end flush complete"},
)

DISASM_2A290 = (
    {"rom": "0x02A290", "effect": "Load ``0x20C958``; if zero seed ``cursor<<7`` and ``0x20C950+=24``"},
    {"rom": "0x02A2B4", "effect": "``bal 0x029AA8`` — slot clamp helper"},
    {"rom": "0x02A2C4", "effect": "``lda 0x005C9280`` → ``call 0x05CEC0`` — **format compile** on batch boundary"},
)

MATCHED_VS_1111_PATHS = (
    {
        "id": "matched_29eb0_tail",
        "entry": "``0x012E3C`` → ``0x029EF0`` → ``0x29FF8`` ``call 0x029C10``",
        "fifo_consumer": "``0x29CF8`` ADD @ ``0x29CFC``",
        "uses_2a120": False,
        "uses_1111_marker_split": False,
        "static_reaches_slot477": False,
        "note": "First prefix node ``inner=0xFFFF`` → ``20C950=30`` after span 16 — not 477",
    },
    {
        "id": "record_end_2a120",
        "entry": "``bx`` via ``0x005C9118`` compiled thunk (not ``bal 0x02A0F8`` matched loop)",
        "fifo_consumer": "``0x02A148`` ``ldos``",
        "uses_2a120": True,
        "uses_1111_marker_split": "via compile+run of embedded format strings",
        "static_reaches_slot477": False,
        "note": "Zero ROM ``call``/``bal`` to ``0x02A120`` — ``bx``-only via patched ``0x005C9118``",
    },
    {
        "id": "python_replay_1111",
        "entry": "``replay_1111_record`` format-walk + ``CgmStagingSim``",
        "fifo_consumer": "simulated ``D`` decode (``xor_table`` default)",
        "uses_2a120": "simulated flush @ record end",
        "uses_1111_marker_split": True,
        "static_reaches_slot477": True,
        "note": "Practical oracle ~90–95%; not hardware-proven",
    },
)


def _rom_xrefs() -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir(None))
    targets = {
        "0x02A0F8": 0x02A0F8,
        "0x02A120": 0x02A120,
        "0x02A290": 0x02A290,
        "0x005C9118": 0x005C9118,
    }
    rows = {}
    for label, addr in targets.items():
        refs = find_word_refs(words, addr)
        rows[label] = {
            "addr": f"0x{addr:05X}",
            "static_word_refs": len(refs),
            "sites": [f"0x{r:06X}" for r in refs[:10]],
        }
    return rows


def _replay_cursor_at_slot(main_data: bytes, slot: int) -> dict[str, Any]:
    pal = PaletteState()
    pal._install_default_lumaram()
    load_colorxlat_from_main_data(pal, main_data)
    payload = _desert_1111_payload(main_data)
    result = replay_1111_record(pal, payload, trace_slots=frozenset({slot}))
    row = result.trace[0] if result.trace else {}
    return {
        "slot": slot,
        "stream_cursor_at_d": row.get("slot"),
        "chunk": row.get("chunk"),
        "g13_seed": row.get("g13_seed"),
        "raw": row.get("raw"),
        "color15": row.get("color15"),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    fifo = _fifo_read_inventory(main_data, slot=slot, raw_u16=0x8843)
    walk = build_1111_walk(focus_slot=slot, focus_raw=0x8843)
    link = build_block_link()
    xrefs = _rom_xrefs()
    replay = _replay_cursor_at_slot(main_data, slot)

    walk_summary = {}
    for w in walk.get("walks_29f_layout") or []:
        walk_summary[w.get("label", "?")] = {
            "nodes": w.get("nodes_walked"),
            "final_20c950": w.get("final_20c950"),
            "final_20c954": w.get("final_20c954"),
            "slot_477_reached": w.get("slot_477_reached"),
            "stop": w.get("stop_reason"),
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "disasm counter map + static node walks + replay correlation",
        "focus_slot": slot,
        "counter_axes": list(COUNTER_AXES),
        "disasm_2a120": list(DISASM_2A120),
        "disasm_2a290": list(DISASM_2A290),
        "path_matrix": list(MATCHED_VS_1111_PATHS),
        "rom_xrefs": xrefs,
        "static_29f_walks": walk_summary,
        "block_prefix_sim": link["prefix_walk"]["simulation_first_node_only"],
        "fifo_inventory": {
            "fifo_offset": (fifo.get("slot_focus_hit") or {}).get("fifo_offset_hex"),
            "read_index": fifo.get("reads_before_slot_hit"),
            "total_reads": fifo.get("total_u16_reads"),
        },
        "replay_oracle": replay,
        "conclusions": (
            "**Slot 477** in Python replay = ``0x20C950`` stream cursor — **not** ``0x20C954`` index 477.",
            "Static ``0x29F0C`` prefix walk: max ``20C950=30`` after first node — **cannot** reach slot 477 without ``0x1111`` body chain fixup.",
            "``0x02A120`` has **zero** static ``call``/``bal`` refs — reachable only via ``0x005C9118`` ``bx`` (patched thunks).",
            "Matched desert init uses ``0x29FF8`` → ``0x029C10`` ADD tail — **not** ``0x02A120`` record-end flush on static path.",
            "``0x02A290`` batch (+24 cursor) + ``0x05CEC0`` @ ``0x02A2C4`` is compile-on-boundary — ties ``0x1111`` format to upload thunks (workram OPEN).",
            f"Replay slot {slot}: FIFO ``0x3A6`` after {fifo.get('reads_before_slot_hit')} reads — independent of ``0x29CB8`` group index.",
        ),
        "open_gaps": (
            "Runtime stream root: ``fp+0x40`` / ``ld (r5)`` fixup before ``0x29EF4``",
            "``0x005C9118`` patched body → ``0x02A120`` for tier-B ``D`` slot 477",
            "``record+0x14`` FIFO cursor writer on ``D`` compile path",
            "Prove or refute ``0x29CFC`` ADD vs xor_table for lone ``D`` @ ``0x8843``",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Slot 477 counter axes RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_slot477_counter_axes_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    sim = report["block_prefix_sim"]
    fifo = report["fifo_inventory"]
    print(f"First-node sim: 20C950={sim['final_20c950']} slot477={sim['slot_477_reached']}")
    print(f"Replay: fifo {fifo['fifo_offset']} read#{fifo['read_index']} slot={args.slot}")
    print(f"2A120 static refs: {report['rom_xrefs']['0x02A120']['static_word_refs']}")
    for line in report["conclusions"][:3]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
