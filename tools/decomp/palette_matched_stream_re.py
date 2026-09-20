#!/usr/bin/env python3
"""Disasm trace: ``0x029EF0`` matched-stream path for desert ``0x1111`` / slot 477.

Documents the **hardware** inner loop (@ ``0x29EF4``–``0x29FD0``) separately from
Python marker-split ``0x1111`` replay.  Reports ROM/CGM byte facts for tier-B
``0x8843`` without inferring XOR or workram thunk bodies.

  python3 -m tools.decomp.palette_matched_stream_re
  python3 -m tools.decomp.palette_matched_stream_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import (
    DISASM_29EB0_BRANCH,
    STREAM_NODE_FIELDS,
    cgm_block_head_facts,
)
from tools.decomp.palette_29eb0_stream_walker import build_report as build_walker_report
from tools.model2_cgm_1111 import replay_1111_record
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    load_colorxlat_from_main_data,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Matched path only (@ ``maincpu_029eb0_600.asm``).
DISASM_MATCHED_PATH: tuple[dict[str, str], ...] = (
    {
        "rom": "0x029EF0",
        "effect": "``r5 = lda 0x40(fp)`` — saved block head dword from ``0x29ECC``",
    },
    {
        "rom": "0x029EF4",
        "effect": "``ld (r5),g4`` — outer node; inner cursor = ``*(r5)``",
    },
    {
        "rom": "0x29F00",
        "effect": "``addo g4,8,g4`` — skip 8-byte prefix before ``+0x08`` span u16",
    },
    {
        "rom": "0x29F0C",
        "effect": "``ldos (g4),r9`` → ``r8 = r9 & 0xFFFF``; bit 7 set on mask @ ``0x29F18``",
    },
    {
        "rom": "0x29F54",
        "effect": "``0x20C950 += r8`` — colorbase slot cursor advance before inner loop",
    },
    {
        "rom": "0x29F34",
        "effect": (
            "``call 0x02A050`` — ``g0=0x20C950`` (pre-span), ``g1=r5`` outer root, "
            "``g2=r9`` header u16; copies via ``0x01080000`` / ``bal 0x026918`` "
            "(see ``palette_2a050_span_re``)"
        ),
    },
    {
        "rom": "0x29F50",
        "effect": "``ldos (g5),r4`` — inner iteration count for ``0x029F7C`` loop",
    },
    {
        "rom": "0x29F68",
        "effect": "``cmpibe 0,r4,0x29FD0`` — zero inner count skips ``0x029F7C``",
    },
    {
        "rom": "0x29F7C",
        "effect": (
            "Per iteration: fill ``0x20B950[0x20C954*8]`` row; ``st g0,0x4(row)`` "
            "compile-record ptr; ``bal 0x02A0F8``"
        ),
    },
    {
        "rom": "0x02A0F8",
        "effect": (
            "``ldis +0x10/+0x12``; ``lda +0x14[g4*2],g0``; ``bx (g1)`` with "
            "``g1=g14`` (``bal`` return link) — **returns to ``0x29FA4``** on "
            "``0x029F7C`` path; record handler word loaded into ``g0`` but not branched"
        ),
    },
    {
        "rom": "0x29FCC",
        "effect": "``cmpible g4,r15,0x29F7C`` — repeat while inner count ``r4 <= 0x1FF``",
    },
    {
        "rom": "0x29FD0",
        "effect": (
            "Tail: patch ``0x20B950[r7*8]`` row (+2/+3); ``call 0x029C10`` when "
            "``(entry_g4 & 7) >= 3`` (@ ``0x29FE4``)"
        ),
    },
)

DISASM_FIFO_HELPERS: tuple[dict[str, str], ...] = (
    {
        "rom": "0x02A120",
        "effect": (
            "``ldob 0x20B953[g0*8],g1`` — merge enable per group; ``ldos (g4),g3`` "
            "@ ``0x02A148`` reads FIFO u16 chain; **no static ROM ``bal``/``call`` "
            "sites** (reachable via ``0x005C9118`` handler table or relative branch only)"
        ),
    },
    {
        "rom": "0x02A200",
        "effect": "``#`` batch XOR @ ``0x02A258`` when ``g3>0`` — not lone ``D``",
    },
    {
        "rom": "0x05D860",
        "effect": (
            "Compile-only ``D`` emit (@ mismatch ``0x02A01C`` → ``0x05CEC0`` path); "
            "not invoked from ``0x029F7C`` matched loop"
        ),
    },
)

OPEN_GAPS: tuple[dict[str, str], ...] = (
    {
        "id": "block_head_pointer_fixup",
        "note": (
            "``0x29ECC`` / ``0x05CE18`` treat block word0 as pointer for ``ldob (g0)``; "
            "static vaddr dword is ASCII ``CGM `` (``0x204D4743``). Runtime fixup to "
            "live string / linked root before ``0x29EF4`` not traced in static ROM"
        ),
    },
    {
        "id": "stream_node_vs_marker_split",
        "note": (
            "Desert ``0x1111`` marker-split binary chunks carry ASCII digit pairs "
            "(``33``/``13``/…), not ``+0x08``/``+0x0A`` u16 headers — **0** valid "
            "``0x29F0C``/``0x29F50`` candidates in static replay"
        ),
    },
    {
        "id": "slot477_29f7c_reach",
        "note": (
            "``--simulate-headers`` yields **0** ``0x29F7C`` events with "
            "``0x20C950==477``; Python ``replay_1111_record`` slot order is format-walk "
            "only — not hardware stream-node order"
        ),
    },
    {
        "id": "2a0f8_bx_g1_not_g0",
        "note": (
            "``0x02A114`` ``bx (g1)`` after loading handler into ``g0`` — matched-path "
            "``bal 0x02A0F8`` @ ``0x29FA0`` sets ``g1`` to return link, so dispatch "
            "table word @ record ``+0x14`` is read but not branched on this path"
        ),
    },
    {
        "id": "2a120_static_caller",
        "note": "No ROM word xref to ``0x02A120``; matched record end uses ``0x29FF8`` ``0x029C10`` instead",
    },
    {
        "id": "lone_d_decode_matched",
        "note": (
            "Tier-B ``D`` / ``0x8843`` correlates to format frag ``3333DD3D…`` (replay "
            "chunk 85) but hardware decode insn between ``0x02A148`` ``ldos`` and "
            "``palram`` commit not proven"
        ),
    },
)


def _replay_slot_facts(main_data: bytes, slot: int) -> dict[str, Any] | None:
    palette = PaletteState()
    palette._install_default_lumaram()
    load_colorxlat_from_main_data(palette, main_data)
    from tools.decomp.palette_29eb0_stream_walker import _desert_1111_payload

    payload = _desert_1111_payload(main_data)
    result = replay_1111_record(palette, payload, trace_slots=frozenset({slot}))
    if not result.trace:
        return None
    row = result.trace[0]
    return {
        "replay_chunk": row.get("chunk"),
        "format_frag": row.get("format_frag"),
        "bin_pos": row.get("bin_pos"),
        "op": row.get("op"),
        "slot": row.get("slot"),
        "raw_u16": row.get("raw"),
        "python_color15": row.get("color15"),
        "g13_seed": row.get("g13_seed"),
        "note": (
            "``replay_chunk`` counts all inner chunks including empties (87 here); "
            "format text lives in marker-split segment 85 — not binary segment 87 "
            "(ASCII digit pairs ``33``/``13``/…)"
        ),
    }


def build_report(*, slot: int | None = 477, raw_u16: int | None = 0x8843) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    block = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    walker = build_walker_report(simulate_headers=True, focus_raw=raw_u16)

    sim = walker.get("simulation") or {}
    events_29f7c = [e for e in sim.get("events", []) if e.get("rom") == "0x029F7C"]
    at_slot = [e for e in events_29f7c if slot is not None and e.get("20c950") == slot]

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM CGM bytes — no MAME, no XOR inference",
        "desert_block": block,
        "gate_path": {
            "predicted": block.get("predicted_29eb0_path"),
            "stream_walk_reachable": block.get("stream_walk_reachable"),
            "compare_vs_rom_mirror": block.get("compare_vs_rom_mirror_template"),
        },
        "disasm_matched_path": list(DISASM_MATCHED_PATH),
        "disasm_29eb0_branch": list(DISASM_29EB0_BRANCH),
        "stream_node_fields": list(STREAM_NODE_FIELDS),
        "disasm_fifo_helpers": list(DISASM_FIFO_HELPERS),
        "marker_split_negative": {
            "binary_segments_with_valid_inner_count": sum(
                1
                for s in walker.get("segments", [])
                if s.get("disasm_header_candidate")
                and 0 < int(s["disasm_header_candidate"]["inner_loop_count"]) <= 0x1FF
            ),
            "29f7c_simulated_events": len(events_29f7c),
            "29f7c_simulated_at_focus_slot": len(at_slot),
            "segments_skipped_total": sim.get("segments_skipped_total"),
            "conclusion": (
                "Marker-split ``0x1111`` layout does not satisfy ``0x29F0C``/``0x29F50`` "
                "— matched-stream node chain must come from runtime block link fixup "
                "(@ ``0x29EF4``), not raw inner-chunk bytes"
            ),
        },
        "fifo_raw_hits": (walker.get("focus_raw") or {}).get("fifo_hits"),
        "open_gaps": list(OPEN_GAPS),
    }

    if slot is not None and raw_u16 is not None:
        report["focus"] = {"slot": slot, "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}"}
        report["cgm_replay_correlation"] = _replay_slot_facts(main_data, slot)

    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x029EF0 matched-stream RE (desert 0x1111)")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_matched_stream_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    gate = report["gate_path"]
    print(f"Desert gate: {gate['predicted']['path']} @ {gate['predicted']['rom']}")
    neg = report["marker_split_negative"]
    print(
        f"Marker-split valid headers: {neg['binary_segments_with_valid_inner_count']}  "
        f"sim 29F7C events: {neg['29f7c_simulated_events']}  "
        f"at slot {args.slot}: {neg['29f7c_simulated_at_focus_slot']}"
    )
    corr = report.get("cgm_replay_correlation") or {}
    if corr:
        print(
            f"\nSlot {args.slot} replay: chunk={corr.get('replay_chunk')} "
            f"raw={corr.get('raw_u16')} frag={str(corr.get('format_frag', ''))[:28]}…"
        )
    print("\nOpen gaps:")
    for g in OPEN_GAPS:
        print(f"  {g['id']}")


if __name__ == "__main__":
    main()
