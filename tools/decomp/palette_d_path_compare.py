#!/usr/bin/env python3
"""Compare ``D`` FIFO decode modes against geometry colorbase demand.

``0x2A258`` XOR runs only when ``g3>0`` (``#`` batch).  Single ``D`` uploads may
use ``0x29CFC`` ADD, ``0x29E48`` subtract-index, or other template-selected paths.
This tool replays desert ``0x1111`` under each candidate mode and reports slot/RGB
divergence — no MAME captures required.

  python3 -m tools.decomp.palette_d_path_compare
  python3 -m tools.decomp.palette_d_path_compare --slot 477 --raw 0x8843
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.palette_re import sample_geometry_colorbases
from tools.model2_cgm_1111 import CGM_RECORD_1111, replay_1111_record
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.model2_cgm_staging import D_DECODE_MODES, D_DECODE_XOR_TABLE
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    load_palette_from_main_data,
    rgb15,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def _replay_mode(main_data: bytes, mode: str) -> dict[int, int]:
    state = PaletteState()
    state._install_default_lumaram()
    from tools.model2_palette import load_colorxlat_from_main_data

    load_colorxlat_from_main_data(state, main_data)
    payload = _desert_1111_payload(main_data)
    result = replay_1111_record(state, payload, d_decode=mode)
    return dict(result.slots_written)


def _slot_rgb(state: PaletteState, slot: int, color15: int) -> dict:
    from tools.model2_palette import _write_colorbase

    _write_colorbase(state, slot, color15)
    unpack = rgb15(color15)
    texel_rgb = state.lookup_texel(8, slot, 128, luma=255)
    return {
        "color15": f"0x{color15:04x}",
        "rgb15_unpack": list(unpack),
        "texel8_luma128": list(texel_rgb),
    }


def compare_modes(
    main_data: bytes,
    needed: set[int],
    *,
    focus_slot: int | None = None,
    raw_u16: int | None = None,
) -> dict:
    baseline = _replay_mode(main_data, D_DECODE_XOR_TABLE)
    modes_report: dict[str, dict] = {}

    palette = load_palette_from_main_data(main_data)

    for mode in D_DECODE_MODES:
        slots = _replay_mode(main_data, mode)
        diffs = [
            slot
            for slot in needed
            if (baseline.get(slot, 0) & 0x7FFF) != (slots.get(slot, 0) & 0x7FFF)
        ]
        modes_report[mode] = {
            "slots_written": len(slots),
            "geometry_diff_vs_xor_table": len(diffs),
            "geometry_diff_slots_sample": diffs[:12],
        }

    focus: dict | None = None
    if focus_slot is not None:
        focus = {"slot": focus_slot, "modes": {}}
        for mode in D_DECODE_MODES:
            slots = _replay_mode(main_data, mode)
            c15 = slots.get(focus_slot, 0) & 0x7FFF
            focus["modes"][mode] = _slot_rgb(palette, focus_slot, c15)

        if raw_u16 is not None:
            slot = focus_slot
            seed = 14 << 7
            from tools.model2_cgm_staging import CgmStagingSim

            decodes: dict[str, str] = {}
            rgb_by_mode: dict[str, dict] = {}
            for mode in D_DECODE_MODES:
                sim = CgmStagingSim(
                    stream_cursor=slot,
                    g13_mask=seed,
                    slot_base=14,
                    d_decode=mode,
                )
                c15 = sim.decode_d_u16(raw_u16, slot=slot)
                decodes[mode] = f"0x{c15:04x}"
                rgb_by_mode[mode] = _slot_rgb(palette, slot, c15)
            focus["synthetic_raw"] = {
                "raw": f"0x{raw_u16 & 0xFFFF:04x}",
                "g13_table": f"0x{g13_mask_for_slot(seed, slot):04x}",
                "decodes": decodes,
                "rgb": rgb_by_mode,
            }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_mode": D_DECODE_XOR_TABLE,
        "modes": modes_report,
        "focus": focus,
        "disasm_note": (
            "0x2A258 XOR inner loop requires g3>0 (# batch). Single D/U call 0x02A4E0 "
            "merge @ 0x02A62C when r5 bit 0 set (@ 0x02A61C). See upload_stubs in "
            "palette_cgm_disasm.json."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare D decode modes on desert 0x1111")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_d_path_compare.json",
    )
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    needed = sample_geometry_colorbases(rom_dir, max_placements=500)

    report = compare_modes(
        main_data,
        needed,
        focus_slot=args.slot,
        raw_u16=args.raw,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    print(f"\nGeometry slot diffs vs {D_DECODE_XOR_TABLE} (of {len(needed)} needed):")
    for mode, body in report["modes"].items():
        print(f"  {mode:12s}: {body['geometry_diff_vs_xor_table']:3d} diffs")

    if report.get("focus"):
        print(f"\nSlot {args.slot} texel8/luma128 RGB by mode:")
        for mode, body in report["focus"]["modes"].items():
            rgb = body["texel8_luma128"]
            print(f"  {mode:12s}: {body['color15']} → RGB{rgb}")

    if report.get("focus", {}).get("synthetic_raw"):
        syn = report["focus"]["synthetic_raw"]
        print(f"\nSynthetic raw {syn['raw']} g13_table={syn['g13_table']}:")
        for mode, c15 in syn["decodes"].items():
            rgb = syn["rgb"][mode]["texel8_luma128"]
            print(f"  {mode:12s}: {c15} → RGB{rgb}")


if __name__ == "__main__":
    main()
