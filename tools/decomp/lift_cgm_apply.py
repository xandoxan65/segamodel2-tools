#!/usr/bin/env python3
"""Apply desert CGM replay into a lift palette dump (palram colorbase + lumaram).

Viewer palette state is built only from disasm-backed sources:
  - colorxlat: keep lift dump (geo_palette_lut_upload @ 0x3C80 then
    geo_lumaram_init @ 0x4350 over ROM mirror table @ 0x5A2EB4)
  - lumaram: lift RAM dump from ``geo_renderer_init`` (no synthetic fill)
  - palram colorbase: CGM replay (``tools.model2_cgm``) — 0x1111 D-path still open

Do not replace colorxlat with upload-only: lumaram_init is intentional ROM work.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.decomp.lift_palette_state import load_lift_palette_state, write_lift_palette_state
from tools.model2_cgm import replay_course_cgm_blocks
from tools.model2_palette import (
    COURSE_CGM_VADDRS_BY_ID,
    LUMARAM_BYTES,
    PALRAM_COLORBASE_WORD,
    find_cgm_blocks,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


def _apply_lumaram_from_lift_dump(state, lift_lu: bytes) -> dict:
    """Keep lumaram from decomp_lift — do not substitute heuristic defaults."""
    n = min(len(lift_lu), LUMARAM_BYTES)
    for i in range(n):
        state.lumaram[i] = lift_lu[i]
    nz = sum(1 for b in state.lumaram[:LUMARAM_BYTES] if b)
    return {"lumaram_source": "lift_dump", "nonzero_bytes": nz}


def apply_cgm_to_lift_state(state, main_data: bytes, *, course_id: str) -> dict:
    """Merge CGM colorbases into lift palette; preserve lift colorxlat/lumaram."""
    lift_lu = bytes(state.lumaram[:LUMARAM_BYTES])
    cx_nz = sum(1 for w in state.colorxlat if w & 0xFF)
    cx_info = {
        "colorxlat_source": "lift_dump",
        "colorxlat_nonzero_words": cx_nz,
        "replaced": False,
    }
    lu_info = _apply_lumaram_from_lift_dump(state, lift_lu)

    blocks = find_cgm_blocks(main_data)
    by_vaddr = {b.vaddr: b for b in blocks}
    vaddrs = COURSE_CGM_VADDRS_BY_ID.get(course_id, ())
    course_blocks = tuple(by_vaddr[v] for v in vaddrs if v in by_vaddr)
    if not course_blocks:
        return {
            "blocks": 0,
            "colorbase_slots": 0,
            **cx_info,
            **lu_info,
        }

    replay = replay_course_cgm_blocks(state, main_data, course_blocks)

    colorbase_slots = sum(
        1
        for slot in range(0x400)
        if state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
    )
    return {
        "blocks": len(course_blocks),
        "colorbase_slots": colorbase_slots,
        **cx_info,
        **lu_info,
        "replay_1111_slots": len(replay.replay_1111_slots),
        "pending_1111_bytes": replay.pending_1111_bytes,
        "replay_1111_errors": replay.replay_1111_errors[:8],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", type=Path, required=True, help="I960_PALETTE_DUMP directory")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--course", default="desert", help="course id (default desert)")
    ap.add_argument("-o", "--report", type=Path, default=None, help="optional JSON report")
    args = ap.parse_args()

    dump_dir = args.dump.resolve()
    rom_dir = resolve_rom_dir(args.rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])

    state, manifest = load_lift_palette_state(dump_dir)
    summary = apply_cgm_to_lift_state(state, main_data, course_id=args.course)
    summary["course"] = args.course
    summary["dump_dir"] = str(dump_dir)

    write_lift_palette_state(dump_dir, state, manifest)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(
        f"lift_cgm_apply: course={args.course} colorxlat={summary.get('colorxlat_source')} "
        f"lumaram={summary.get('lumaram_source')} nz={summary.get('nonzero_bytes', 0)} "
        f"blocks={summary.get('blocks', 0)} colorbase_slots={summary.get('colorbase_slots', 0)} "
        f"1111_slots={summary.get('replay_1111_slots', 0)}",
        file=sys.stderr,
    )
    if summary.get("replay_1111_errors"):
        print("1111 errors:", summary["replay_1111_errors"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
