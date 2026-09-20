#!/usr/bin/env python3
"""Disasm-only format-char → upload-path matrix for desert ``0x1111``.

Maps each CGM format character to its proven maincpu handler and runtime upload
insn.  Replays desert ``0x1111`` counting ops per path and runs negative decode
comparison for tier-B slots (>127) — **without** treating ``xor_table`` as hardware.

  python3 -m tools.decomp.palette_disasm_decode_re
  python3 -m tools.decomp.palette_disasm_decode_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_re import sample_geometry_colorbases
from tools.model2_cgm_1111 import (
    CGM_RECORD_1111,
    _is_format_chunk,
    _split_inner_chunks,
    replay_1111_record,
)
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.model2_cgm_staging import D_DECODE_XOR_TABLE, D_DECODE_ADD_TABLE
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Proven handler → runtime upload mapping (static disasm citations).
FORMAT_CHAR_PATHS: dict[str, dict[str, Any]] = {
    "D": {
        "handler_rom": "0x05D3DC",
        "emit_rom": "0x05D860",
        "runtime_rom": "0x02A5A0",
        "upload_insn": "0x02A4E0 merge (@ 0x02A61C when r5 bit 0)",
        "fifo_effect": "``setbit 0,r9`` → compiled thunk reads FIFO; merge g2=r14",
        "disasm_proven_decode": False,
        "python_replay": "xor_table (oracle — not disasm-proven for lone D)",
    },
    "U": {
        "handler_rom": "0x05D3DC",
        "emit_rom": "0x05D860",
        "runtime_rom": "0x029C10",
        "upload_insn": "0x29CFC addo g13,g4,g4",
        "fifo_effect": "Same emit as D; ADD on legacy ``0x029C10`` sweep",
        "disasm_proven_decode": True,
        "python_replay": "add_table (matches 29CFC semantics)",
    },
    "#": {
        "handler_rom": "0x05D3DC",
        "emit_rom": "0x05D860",
        "runtime_rom": "0x02A200",
        "upload_insn": "0x02A258 xor g4,g13,g4 (g3>0 inner loop)",
        "fifo_effect": "Second pass XOR over staging window",
        "disasm_proven_decode": True,
        "python_replay": "hash_batch → g13_hash_mask",
    },
    "E": {
        "handler_rom": "0x05DE00",
        "emit_rom": "0x05D860",
        "runtime_rom": "0x02A0F8",
        "upload_insn": "record+0x14 param table (@ 0x05DE00)",
        "fifo_effect": "``ldis 0x14(g0)[idx*2]`` — 32-bit FIFO consume",
        "disasm_proven_decode": True,
        "python_replay": "read_u32 skip",
    },
    "3": {
        "handler_rom": "0x05D3DC",
        "emit_rom": "0x05D860",
        "runtime_rom": "0x02A490",
        "upload_insn": "scratch colorbase @ 0x01800000",
        "fifo_effect": "Digit repeat → width; no direct u16 color decode",
        "disasm_proven_decode": "n/a",
        "python_replay": "cursor advance only",
    },
}

TIER_B_THRESHOLD = 128


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def _format_char_counts(payload: bytes) -> Counter[str]:
    counts: Counter[str] = Counter()
    for chunk in _split_inner_chunks(payload):
        if _is_format_chunk(chunk):
            for ch in chunk.decode("latin1", "replace"):
                if ch.isdigit():
                    continue
                counts[ch] += 1
    return counts


def _tier_b_slot_report(main_data: bytes, needed: set[int]) -> dict[str, Any]:
    """Compare disasm-proven ADD replay vs xor_table oracle on tier-B slots."""
    from tools.model2_palette import load_colorxlat_from_main_data

    payload = _desert_1111_payload(main_data)
    tier_b_needed = {s for s in needed if s >= TIER_B_THRESHOLD}

    def replay(mode: str) -> dict[int, int]:
        st = PaletteState()
        st._install_default_lumaram()
        load_colorxlat_from_main_data(st, main_data)
        return dict(replay_1111_record(st, payload, d_decode=mode).slots_written)

    oracle = replay(D_DECODE_XOR_TABLE)
    add_path = replay(D_DECODE_ADD_TABLE)

    diffs_oracle_vs_add = [
        s for s in tier_b_needed if (oracle.get(s, 0) & 0x7FFF) != (add_path.get(s, 0) & 0x7FFF)
    ]
    diffs_oracle_vs_add_all = [
        s for s in needed if (oracle.get(s, 0) & 0x7FFF) != (add_path.get(s, 0) & 0x7FFF)
    ]

    return {
        "tier_b_threshold": TIER_B_THRESHOLD,
        "geometry_tier_b_needed": len(tier_b_needed),
        "oracle_mode": D_DECODE_XOR_TABLE,
        "disasm_add_mode": D_DECODE_ADD_TABLE,
        "tier_b_diff_vs_oracle": len(diffs_oracle_vs_add),
        "tier_b_diff_sample": diffs_oracle_vs_add[:16],
        "all_slots_diff_vs_oracle": len(diffs_oracle_vs_add_all),
        "note": (
            "``add_table`` implements ``0x29CFC`` ADD — disasm-proven for ``U``/legacy "
            "``0x029C10`` only.  Tier-B ``D`` slots diverge from xor_table oracle."
        ),
    }


def _focus_slot_trace(
    main_data: bytes,
    *,
    slot: int,
    raw_u16: int,
    g13_seed: int = 0x0700,
) -> dict[str, Any]:
    from tools.model2_palette import load_colorxlat_from_main_data

    payload = _desert_1111_payload(main_data)
    st = PaletteState()
    st._install_default_lumaram()
    load_colorxlat_from_main_data(st, main_data)
    result = replay_1111_record(st, payload, trace_slots=frozenset({slot}))
    trace_rows = [r for r in result.trace if r.get("slot") == slot]

    g13_table = g13_mask_for_slot(g13_seed, slot)
    raw = int(raw_u16) & 0xFFFF
    add_decode = (raw + g13_table) & 0x7FFF
    xor_oracle = (raw ^ g13_table) & 0x7FFF

    replay_color15: int | None = None
    if trace_rows:
        c15 = trace_rows[0].get("color15", 0)
        if isinstance(c15, str):
            replay_color15 = int(c15, 0) & 0x7FFF
        else:
            replay_color15 = int(c15) & 0x7FFF

    return {
        "slot": slot,
        "raw_u16": f"0x{raw:04x}",
        "g13_table": f"0x{g13_table:04x}",
        "disasm_29cfc_add": f"0x{add_decode:04x}",
        "oracle_xor_table": f"0x{xor_oracle:04x}",
        "replay_color15": f"0x{replay_color15:04x}" if replay_color15 is not None else None,
        "replay_trace": trace_rows,
        "format_context": trace_rows[0].get("format_frag", "") if trace_rows else "",
        "op": trace_rows[0].get("op") if trace_rows else None,
        "hardware_path": FORMAT_CHAR_PATHS.get(trace_rows[0].get("op", "D"), FORMAT_CHAR_PATHS["D"]),
        "disasm_add_matches_oracle": add_decode == xor_oracle,
        "disasm_add_matches_replay": replay_color15 == add_decode if replay_color15 is not None else False,
    }


def build_report(
    *,
    slot: int = 477,
    raw_u16: int = 0x8843,
    rom_dir: Path | None = None,
) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    payload = _desert_1111_payload(main_data)
    needed = sample_geometry_colorbases(rom_dir, max_placements=500)

    char_counts = _format_char_counts(payload)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "disasm path matrix + negative tier-B decode — no MAME",
        "format_char_paths": FORMAT_CHAR_PATHS,
        "desert_1111_format_counts": dict(sorted(char_counts.items())),
        "tier_b_analysis": _tier_b_slot_report(main_data, needed),
        "focus": _focus_slot_trace(main_data, slot=slot, raw_u16=raw_u16),
        "summary": (
            "``D`` (36 ops) → ``0x02A4E0`` merge path — decode OPEN. "
            "``U`` (33 ops) → ``0x29CFC`` ADD — disasm-proven. "
            "``#`` (8 ops) → ``0x02A258`` XOR batch — disasm-proven. "
            "Tier-B slots (>127) require ``D`` merge RE; ADD replay fails geometry."
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Disasm format-char decode matrix")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_disasm_decode_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, rom_dir=args.rom_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    tb = report["tier_b_analysis"]
    print(
        f"\nTier-B geometry slots: {tb['geometry_tier_b_needed']}  "
        f"ADD-vs-oracle diffs: {tb['tier_b_diff_vs_oracle']}"
    )

    focus = report["focus"]
    print(
        f"\nSlot {focus['slot']}: op={focus['op']} raw {focus['raw_u16']} "
        f"→ replay {focus.get('replay_color15', '?')}"
    )
    print(f"  disasm 29CFC ADD → {focus['disasm_29cfc_add']}")
    print(f"  oracle xor_table → {focus['oracle_xor_table']}")
    print(f"  hardware: {focus['hardware_path']['upload_insn']}")
    print(f"\n{report['summary']}")


if __name__ == "__main__":
    main()
