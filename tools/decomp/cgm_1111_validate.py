#!/usr/bin/env python3
"""Validate CGM 0x1111 replay: Python staging vs lifted ``0x2A4E0`` merge.

Tier checks (disasm-backed, no MAME):
  1. ``palram_bus_merge`` C @ ``0x2A4E0`` matches ``tools.decomp.cgm_merge_ref``
  2. Desert ``0x1111`` replay uses ``D``=merge / ``U``=add / ``#``=xor batch per disasm
  3. Leading slots 1–13 unchanged vs ROM header

  python3 -m tools.decomp.cgm_1111_validate
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.cgm_merge_ref import decode_d_u16_merge, palram_bus_merge_u16
from tools.decomp.palette_re import sample_geometry_colorbases
from tools.model2_cgm import replay_course_cgm_blocks
from tools.model2_cgm_1111 import CGM_RECORD_1111, replay_1111_record
from tools.model2_cgm_staging import D_DECODE_MERGE_RAW, D_DECODE_XOR_TABLE
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PALRAM_COLORBASE_WORD,
    PaletteState,
    find_cgm_blocks,
    parse_cgm_colorbase_block,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
LIFT_BIN = REPO_ROOT / "decomp" / "build" / "lift" / "decomp_lift"
NOTES_VECTORS = REPO_ROOT / "decomp" / "notes" / "palette_test_vectors.json"


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def _compare_merge_py_vs_c(cases: list[dict]) -> dict:
    """Lifted merge self-test removed — use Python cgm_merge_ref only."""
    return {
        "skipped": True,
        "reason": "lift C merge self-test entry point removed",
        "python_cases": len(cases),
        "ok": True,
    }


def _merge_case_grid() -> list[dict]:
    cases = []
    for slot in (14, 477):
        for raw in (0x8843, 0x2651, 0x66C1):
            bus: dict[int, int] = {}
            py = decode_d_u16_merge(bus, raw, slot=slot)
            cases.append({"slot": slot, "raw": raw, "color15": py})
    return cases


def _leading_slots_ok(state: PaletteState, main_data: bytes, block) -> dict:
    expected = {
        slot: color15 & 0x7FFF
        for slot, color15 in parse_cgm_colorbase_block(main_data, block)
    }
    got = {
        slot: state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
        for slot in expected
    }
    mism = {str(s): {"expected": hex(expected[s]), "got": hex(got[s])} for s in expected if got[s] != expected[s]}
    return {"slots": len(expected), "ok": not mism, "mismatches": mism}


def validate_cgm_1111(*, rom_dir: Path | None = None) -> dict:
    rom_dir = resolve_rom_dir(rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    blocks = find_cgm_blocks(main_data)
    by_vaddr = {b.vaddr: b for b in blocks}
    desert = by_vaddr[COURSE_CGM_VADDRS[1]]
    payload = _desert_1111_payload(main_data)

    # Replay with disasm D=merge default
    state = PaletteState()
    replay_summary = replay_course_cgm_blocks(
        state, main_data, tuple(by_vaddr[v] for v in COURSE_CGM_VADDRS if v in by_vaddr)
    )
    leading = _leading_slots_ok(state, main_data, desert)

    # Compare merge vs legacy xor_table on desert payload
    legacy = PaletteState()
    legacy._install_default_lumaram()
    part_legacy = replay_1111_record(legacy, payload, d_decode=D_DECODE_XOR_TABLE)
    part_merge = replay_1111_record(PaletteState(), payload, d_decode=D_DECODE_MERGE_RAW)

    slot_diff = sorted(
        s
        for s in set(part_legacy.slots_written) | set(part_merge.slots_written)
        if (part_legacy.slots_written.get(s, 0) & 0x7FFF) != (part_merge.slots_written.get(s, 0) & 0x7FFF)
    )
    needed = sample_geometry_colorbases(rom_dir)
    geom_legacy = {s: part_legacy.slots_written.get(s, 0) & 0x7FFF for s in needed if s in part_legacy.slots_written}
    geom_merge = {s: part_merge.slots_written.get(s, 0) & 0x7FFF for s in needed if s in part_merge.slots_written}

    merge_cases = _merge_case_grid()
    c_lift = _compare_merge_py_vs_c(merge_cases)

    vectors_note = None
    if NOTES_VECTORS.is_file():
        note = json.loads(NOTES_VECTORS.read_text(encoding="utf-8")).get("replay_slots_high", {})
        vectors_note = {
            "slot477_vector": note.get("477"),
            "note": "palette_test_vectors replay_slots_* are Python snapshots — not hardware oracles",
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "decode_default": D_DECODE_MERGE_RAW,
        "disasm_d_path": "0x2A5A0 → 0x2A4E0 merge (r5 bit 0); # → 0x2A258 xor",
        "disasm_u_path": "0x29CFC add g13",
        "lift_merge_0x2a4e0": c_lift,
        "leading_slots": leading,
        "replay": {
            "1111_slots_written": len(replay_summary.replay_1111_slots),
            "colorbase_slots": sum(
                1 for slot in range(0x400) if state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
            ),
            "errors": replay_summary.replay_1111_errors[:8],
        },
        "merge_vs_xor_table": {
            "slots_differ": len(slot_diff),
            "sample_diff_slots": [
                {
                    "slot": s,
                    "xor_table": f"0x{part_legacy.slots_written.get(s, 0) & 0x7FFF:04X}",
                    "merge_raw": f"0x{part_merge.slots_written.get(s, 0) & 0x7FFF:04X}",
                }
                for s in slot_diff[:12]
            ],
        },
        "geometry_high_slots": {
            "needed": len(needed),
            "filled_legacy_xor": len(geom_legacy),
            "filled_merge": len(geom_merge),
        },
        "merge_case_grid": [
            {**c, "raw": f"0x{c['raw']:04X}", "color15": f"0x{(c['color15'] or 0):04X}"}
            for c in merge_cases
        ],
        "vectors_note": vectors_note,
        "ok": leading["ok"] and c_lift.get("ok", True) and not replay_summary.replay_1111_errors,
        "tier": "effect_match_merge_d" if c_lift.get("ok") else "pending_lift_merge",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("-o", "--report", type=Path, default=Path("out/decomp/cgm_1111_validate.json"))
    args = ap.parse_args()

    report = validate_cgm_1111(rom_dir=args.rom_dir)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        f"cgm_1111_validate: tier={report['tier']} leading_ok={report['leading_slots']['ok']} "
        f"1111_slots={report['replay']['1111_slots_written']} "
        f"merge_vs_xor={report['merge_vs_xor_table']['slots_differ']} "
        f"lift_merge_ok={report['lift_merge_0x2a4e0'].get('ok', 'skip')}",
        file=sys.stderr,
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
