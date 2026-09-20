#!/usr/bin/env python3
"""ROM upload-cluster catalog + ``0x29EB0`` record dispatch (static RE).

Maps fixed ROM thunks @ ``0x02A200``–``0x02A740`` that compiled ``0x5CEC0`` output
calls via patched workram ``bx`` targets.  No MAME captures.

  python3 -m tools.decomp.palette_thunk_catalog
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Fixed ROM helpers (``lda g14, 0x005Cxxxx`` return stub + ``bx``).
ROM_THUNKS = (
    {
        "rom": "0x02A0F8",
        "stub": "0x005C9118",
        "name": "format_param_dispatch",
        "args": "g0 = compiled record; reads u16/u32 via +0x14[g4*2] table",
        "role": "FIFO / parameter atom fetch for compiled format program",
    },
    {
        "rom": "0x02A200",
        "stub": "via compile",
        "name": "batched_staging_xor",
        "args": "g0,g1,g2,g3,g4 — g3>0 required for inner XOR loop",
        "role": "``#`` batch only (@ ``0x02A258``); not lone ``D``",
    },
    {
        "rom": "0x02A290",
        "stub": "via compile",
        "name": "batch_cursor_seed",
        "args": "seeds ``0x20C958 = cursor<<7``, bumps ``0x20C950`` (+24 compile row)",
        "role": "Called before ``0x05CEC0`` format compile @ ``0x02A2C4``",
    },
    {
        "rom": "0x02A2E0",
        "stub": "via compile",
        "name": "merge_global_setup",
        "args": "g0,g1,g2,g3 → ``0x20C95C``–``0x20C968``; then ``0x2A3AC`` g13 table fill",
        "role": "Bounds + per-slot mask table before upload runner",
    },
    {
        "rom": "0x02A410",
        "stub": "0x005C9488",
        "name": "palram_nibble_pack",
        "args": "g0 = nibble value; uses ``0x20C958`` slot anchor",
        "role": "Direct ``0x01080000`` pack (setbit-15 loop @ ``0x02A458``)",
    },
    {
        "rom": "0x02A490",
        "stub": "0x005C94D8",
        "name": "scratch_colorbase_write",
        "args": "g0 = sub-slot, g1 = color15; base slot = ``0x20C958>>7``",
        "role": "``0x01800000`` scratch; flushed @ ``0x02A120`` → ``0x26918``",
    },
    {
        "rom": "0x02A4E0",
        "stub": "via compile",
        "name": "palram_merge",
        "args": "g0,g1 bus coords; g2 = 16-bit value to insert",
        "role": "Read-modify-write @ ``0x01080000`` using merge globals",
    },
    {
        "rom": "0x02A5A0",
        "stub": "via compile",
        "name": "fifo_upload_runner",
        "args": "g0–g5 saved → inner loops; ``r5`` bit 0 selects merge vs flag path",
        "role": "Descriptor-list driven upload (@ ``0x02A5F8`` walk ``r6`` chain)",
    },
    {
        "rom": "0x02A6D0",
        "stub": "via compile",
        "name": "upload_wrapper",
        "args": "g0–g5 permuted into four ``0x02A5A0`` calls @ ``0x02A6E8``–``0x02A73C``",
        "role": "4-wide upload dispatch for compiled dimensions",
    },
)

# ``0x02A6D0`` first ``call 0x02A5A0`` register map (disasm @ ``0x02A6D0``–``0x02A6E8``).
WRAPPER_FIRST_CALL = {
    "entry_saved": {
        "r7": "orig g0",
        "r8": "orig g1",
        "r5": "orig g2",
        "r4": "orig g3",
        "r6": "orig g4",
    },
    "at_2A5A0_entry": {
        "g0_r10": "orig g0",
        "g1_r9": "orig g1",
        "g2": "orig g0 (mov r7,g2 @ 0x02A6E4)",
        "g4_r14": "orig g4",
        "g5_r5": "orig g5",
    },
    "merge_at_2A62C": {
        "g0": "r10 = orig g0",
        "g1": "r9 = orig g1",
        "g2": "r14 = orig g4",
        "note": "Merge value is wrapper **g4**, not FIFO raw u16. ``g5`` bit 0 must be set (``D``/``U``).",
    },
}

RECORD_DISPATCH_29EB0 = {
    "rom": "0x029EB0",
    "record_entry": {
        "rom": "0x029ED8",
        "condition": "``0x20C950`` slot > 0x1FF",
        "true": "``0x02A004`` → ``0x05CEC0`` @ ``0x02A034`` → ``0x029958`` (overflow compile+run)",
        "false": "``0x029EDC`` → ``bal 0x05CE18`` header match, then inner loop",
    },
    "inner_loop": {
        "rom": "0x029F7C",
        "condition": "slot <= 0x1FF (@ ``0x029FCC`` ``cmpible g4,0x1ff``)",
        "effect": "``bal 0x02A0F8`` — dispatch via ``0x005C9118`` trampoline",
    },
    "inner_overflow": {
        "rom": "0x029FD0",
        "condition": "slot > 0x1FF during inner loop (@ ``0x029FCC`` fall-through)",
        "branch_29fe4": {
            "test": "``g5 = r11 & 7`` (``r11`` = entry ``g4`` saved @ ``0x029EB8``)",
            "cmpibl_3": "if ``(entry_g4 & 7) < 3`` → ``0x029FFC`` ret (skip ``0x029C10``)",
            "else": "``call 0x029C10`` (legacy ADD @ ``0x29CFC``)",
        },
    },
    "desert_static_path": (
        "Desert ``0x012E3C``: ROM mirror template ``CGM 1.0 `` → ``0x05CE18`` match → "
        "``0x029EF0`` stream walk (not ``0x02A01C``). "
        "``0x29F34`` ``call 0x02A050`` per node; ``0x029F7C`` inner loop; "
        "``0x29FF8`` ``call 0x029C10`` when ``(entry_g4&7)>=3`` (desert ``g4=4``). "
        "Slot 477 tier-B decode insn still OPEN."
    ),
    "2a0f8_matched_path_note": (
        "``0x02A114`` ``bx (g1)`` with ``g1=g14`` (``bal`` link @ ``0x29FA0``) returns "
        "to ``0x29FA4`` — record ``+0x14`` handler word loaded into ``g0`` but not branched"
    ),
}

UNPROVEN_D_HYPOTHESIS = {
    "label": "hypothesis — not disasm-proven",
    "steps": (
        "1. ``0x05D3DC``: setbit 0,r9 — marks D/U merge path (proven)",
        "2. ``0x05D860`` + ``0x027008``: emit descriptor bytecode (proven)",
        "3. ``0x05CEC0``: compile; ``0x029958`` run generated program (proven)",
        "4. Compiled workram handler may read FIFO u16 — **not traced in static ROM**",
        "5. Python ``xor_table`` applies ``raw ^ g13_mask_for_slot`` — geometry oracle only",
        "6. Entry ``g4`` may reach merge as ``g2=r14`` when ``g5`` bit 0 set (proven @ 0x02A628)",
        "7. ``0x02A4E0`` merge → scratch / ``0x02A120`` flush → ``0x26918`` palram",
    ),
    "python_equivalence": (
        "``decode_d_u16`` (``xor_table``) matches desert geometry in "
        "``palette_d_path_compare`` — replay convenience, not hardware proof."
    ),
    "tier_b_residual": (
        "Compiled thunk @ ``0x005C8964`` / ``0x20B1C0`` bodies, wrapper ``g0``/``g1`` "
        "bus coords, and any FIFO→``g4`` transform for slot 477."
    ),
}


def build_report() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rom_thunks": ROM_THUNKS,
        "wrapper_first_call": WRAPPER_FIRST_CALL,
        "record_dispatch_29eb0": RECORD_DISPATCH_29EB0,
        "unproven_d_hypothesis": UNPROVEN_D_HYPOTHESIS,
        "xor_in_rom_upload_cluster": (
            "Proven: ``0x02A258`` (@ ``0x02A200``, ``g3>0`` ``#`` batch only); "
            "``0x29CFC`` ADD (@ ``0x029C10``, bypassed when ``(g4&7)<3`` @ ``0x29FE4``). "
            "No ``xor g13`` / ``addo g13`` on the 0x1111 compile path in static disasm."
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="ROM upload thunk catalog")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_thunk_catalog.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(f"\nROM thunks: {len(ROM_THUNKS)}")
    for t in ROM_THUNKS:
        print(f"  {t['rom']} {t['name']}")
    print(f"\n29EB0 desert: {RECORD_DISPATCH_29EB0['desert_static_path'][:72]}…")


if __name__ == "__main__":
    main()
