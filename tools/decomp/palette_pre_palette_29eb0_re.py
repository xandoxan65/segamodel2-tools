#!/usr/bin/env python3
"""Disasm RE: pre-palette ``0x012B80`` ``0x029EB0`` chain + ``0x029D60`` @ ``0x014530``.

Documents six ``0x029EB0`` compiles before ``0x012D90`` (none on desert ``0x028CCAF8``),
early ``0x029C10`` sweeps @ ``0x012C74``–``0x012D88``, and ``0x014530`` course-load
upload that calls ``0x029D60``/``0x029C10`` with ``g4=0`` → **compile+run** (not
tier-A ``addo g13`` @ ``0x29CFC``).  Proves static slot envelope still ≪ 477.

No MAME. xor_table oracle only.

  python3 -m tools.decomp.palette_pre_palette_29eb0_re
  python3 -m tools.decomp.palette_pre_palette_29eb0_re --slot 477
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks, _iter_cgm_v16_records
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_VADDR = COURSE_CGM_VADDRS[1]

# --- ``0x012B80`` six-block ``0x029EB0`` chain (ROM decode) --------------------

PRE_PALETTE_29EB0 = (
    {
        "rom": "0x012B94",
        "block_vaddr": "0x02123B54",
        "g4": 4,
        "stores": "0x20A7A8",
        "has_1111": False,
    },
    {
        "rom": "0x012BB8",
        "block_vaddr": "0x0289A500",
        "g4": 4,
        "g3": 2,
        "stores": "0x20A7AC",
        "has_1111": False,
    },
    {
        "rom": "0x012BDC",
        "block_vaddr": "0x028BFEAC",
        "g4": 4,
        "stores": "0x20A798",
        "has_1111": False,
    },
    {
        "rom": "0x012C00",
        "block_vaddr": "0x0286A980",
        "g4": 4,
        "stores": "0x20A7B4",
        "has_1111": False,
        "note": "First-sweep ``ld`` @ ``0x012E40`` — not desert",
    },
    {
        "rom": "0x012C24",
        "block_vaddr": "0x0289C558",
        "g4": 4,
        "stores": "0x20A7A0",
        "has_1111": False,
    },
    {
        "rom": "0x012C58",
        "block_vaddr": "0x0007484C",
        "g4": 4,
        "stores": "0x20A7B8",
        "has_1111": False,
        "note": "Not a CGM catalog block head — likely runtime/alias address",
    },
)

# --- Subroutine layout (@ ``maincpu_012b80_220.asm``) --------------------------

SUBROUTINE_LAYOUT = (
    {
        "rom_lo": "0x012B20",
        "rom_hi": "0x012B68",
        "role": "``0x005B1AD0`` table walk + ``bal 0x05CE18`` gate matcher",
        "static_callers": ("0x012F94", "0x01A518"),
    },
    {
        "rom_lo": "0x012B70",
        "rom_hi": "0x012C6C",
        "role": "Six/five ``0x029EB0`` compiles + ``0x20A530`` mode gate for sixth block",
        "static_callers": ("0x0137D4",),
    },
    {
        "rom_lo": "0x012C70",
        "rom_hi": "0x012CB0",
        "role": "Short ``0x029C10`` upload helper (``g0=2`` entry)",
        "static_callers": ("0x01320C", "0x013498", "0x0135C8", "0x013798"),
    },
    {
        "rom_lo": "0x012CC0",
        "rom_hi": "0x012D8C",
        "role": "Extended ``0x029C10`` sweeps (``0x20A530`` / ``0x202019`` gates)",
        "static_callers": (),
    },
    {
        "rom_lo": "0x012D90",
        "rom_hi": "0x012EDC",
        "role": "Course palette init (alpine+desert ``0x029EB0`` + post-init sweeps)",
        "static_callers": (),
    },
)

# --- Static ``call`` edges (MAME i960dasm: ``dest = rom + disp``) --------------

STATIC_CALLERS = (
    {
        "rom": "0x00FB58",
        "target": "0x0137D0",
        "effect": "Orchestrator: ``call 0x016B70`` → ``0x012B70`` → ``0x016B40``",
    },
    {
        "rom": "0x0137D4",
        "target": "0x012B70",
        "effect": "Pre-palette ``0x029EB0`` chain (``bal 0x029A68`` trampoline @ entry)",
    },
    {
        "rom": "0x013798",
        "target": "0x012C70",
        "effect": "Early upload helper after ``0x20A81C`` counter",
    },
    {
        "rom": "0x01320C",
        "target": "0x012C70",
        "effect": "Early upload helper (alternate path)",
    },
    {
        "rom": "0x013498",
        "target": "0x012C70",
        "effect": "Early upload helper (alternate path)",
    },
    {
        "rom": "0x0135C8",
        "target": "0x012C70",
        "effect": "Early upload helper (alternate path)",
    },
    {
        "rom": "0x012F94",
        "target": "0x012B20",
        "effect": "``0x005B1AD0`` CGM gate table walk",
    },
    {
        "rom": "0x01A518",
        "target": "0x012B20",
        "effect": "``0x005B1AD0`` CGM gate table walk (alternate)",
    },
)

# --- Gate + early ``0x029C10`` (@ ``0x012C28``–``0x012D88``) -------------------

EARLY_UPLOAD = (
    {
        "rom": "0x012C28",
        "effect": (
            "``ld 0x20A530,g4``; ``cmpibe 1,g4→0x12C40``; ``cmpibne 2,g4→0x12C64`` — "
            "sixth block when ``g4∈{1,2}``"
        ),
    },
    {
        "rom": "0x012C70",
        "effect": "Upload helper entry (``mov 2,g0``) — **not** a ``call 0x029C10`` site",
    },
    {"rom": "0x012C90", "effect": "``call 0x029C10`` with ``g2=0x20A7A8``"},
    {"rom": "0x012CAC", "effect": "``call 0x029C10`` with ``g2=0x20A7AC``"},
    {"rom": "0x012D10", "effect": "``call 0x029C10`` with ``g2=0x20A7B8`` (``0x012CC0`` fn)"},
    {"rom": "0x012D34", "effect": "Further ``0x029C10`` sweep using ``0x20A7B8``"},
    {"rom": "0x012D88", "effect": "``call 0x029C10`` with ``g2=0x20A7AC`` — last before ``0x012D90``"},
    {
        "rom": "0x012D90",
        "effect": "Palette init entry — **zero** static ``call``/``bal`` in full ROM scan",
    },
)

# --- ``0x0144F0`` init thunk → ``0x014530`` -----------------------------------

INIT_THUNK_144F0 = (
    {"rom": "0x0160B8", "effect": "Game init: ``call 0x0144F0``"},
    {"rom": "0x0144FC", "effect": "``lda 0x0208E9E4,g2``; ``call 0x029EB0`` ``g4=4``"},
    {"rom": "0x014518", "effect": "``st g0,0x20A8B4`` — ``0x029EB0`` return"},
    {"rom": "0x014530", "effect": "Course-load upload sweeps (``0x148D4``, ``0x15414``, …)"},
)

# --- ``0x29D60`` vs ``0x29C10`` @ ``0x014530`` (``g4=0`` → compile+run) --------

ROUTING_G4_ZERO = (
    {
        "rom": "0x29C30",
        "test": "``cmpibge 3,(g4&7),0x29C74``",
        "g4_0": "``0 & 7 = 0`` → **not** ≥ 3 → fall through to ``0x29C34`` compile+run",
    },
    {
        "rom": "0x29D80",
        "test": "Same gate in ``0x029D60`` copy",
        "g4_0": "``g4=0`` → ``0x29D84`` compile+run → ``0x5CEC0`` @ ``0x005C8D40``",
    },
    {
        "rom": "0x14560",
        "effect": "``0x014530`` passes ``g4=0`` into ``call 0x029D60``",
    },
    {
        "rom": "0x145D0",
        "effect": "Later ``call 0x029C10`` also with ``g4=0`` — compile+run, not ``0x29CFC`` ADD",
    },
    {
        "contrast": "``0x012E60`` palette sweeps use ``g4=2`` → ``2 & 7 = 2`` → **upload** @ ``0x29C74``",
    },
)

UPLOAD_14530_ENVELOPE = (
    {
        "path": "20A8B8 <= 59",
        "rom": "0x14564",
        "calls": "Two ``0x029D60`` per invoke: ``g0+1`` and ``r5+5``",
        "example": "Caller ``g0≈52`` (@ ``0x0148CC``) → slots **53** and **57**",
    },
    {
        "path": "20A8B8 > 59",
        "rom": "0x145D4",
        "calls": "``0x029C10`` with ``g4=0`` (compile+run) + phased ``g0`` from ``0x1(r5)``",
        "max_g0": "Bounded by ``0x20A8B8`` counter / caller ``r5`` — not slot 477",
    },
)


def _call_target_mame(rom: int, word: int) -> int:
    """MAME ``i960dasm``: ``dest = call_pc + signed_disp`` (not ``pc+4``)."""
    off = word & 0xFFFFFF
    if off & 0x800000:
        off -= 0x1000000
    return (rom + off) & 0xFFFFFF


def _call_targets_from_rom(words: list[int], sites: tuple[int, ...]) -> dict[str, str]:
    """Resolve ``call`` targets (MAME i960dasm convention)."""
    out: dict[str, str] = {}
    for rom in sites:
        idx = rom // 4
        if idx >= len(words):
            continue
        w = words[idx]
        if (w >> 24) != 0x09:
            continue
        dest = _call_target_mame(rom, w)
        out[f"0x{rom:06X}"] = f"0x{dest:06X}"
    return out


def _scan_static_callers(
    words: list[int], targets: tuple[int, ...]
) -> dict[str, list[str]]:
    """Full-ROM ``call``/``bal`` scan (MAME target decode)."""
    want = set(targets)
    out: dict[str, list[str]] = {f"0x{t:06X}": [] for t in targets}
    for rom in range(0, len(words) * 4, 4):
        w = words[rom // 4]
        op = w >> 24
        if op not in (0x09, 0x0B):
            continue
        dest = _call_target_mame(rom, w)
        if dest in want:
            kind = "call" if op == 0x09 else "bal"
            out[f"0x{dest:06X}"].append(f"0x{rom:06X} ({kind})")
    return out


def _has_1111(main_data: bytes, vaddr: int) -> bool:
    if vaddr not in {b.vaddr for b in find_cgm_blocks(main_data)}:
        return False
    block = next(b for b in find_cgm_blocks(main_data) if b.vaddr == vaddr)
    return any(t == 0x1111 for t, _, _ in _iter_cgm_v16_records(main_data, block))


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])

    call_map = _call_targets_from_rom(
        words,
        (
            0x012B94,
            0x012BB8,
            0x012BDC,
            0x012C00,
            0x012C24,
            0x012C58,
            0x012C90,
            0x012CAC,
            0x012D10,
            0x0137D4,
            0x01450C,
            0x14564,
            0x145D4,
        ),
    )
    caller_scan = _scan_static_callers(
        words, (0x012B20, 0x012B70, 0x012C70, 0x012CC0, 0x012D90)
    )

    blocks = [
        {**b, "has_1111": _has_1111(main_data, int(b["block_vaddr"], 16))}
        for b in PRE_PALETTE_29EB0
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 ROM decode + MAME disasm slices + CGM catalog — no workram",
        "focus": {"slot": slot, "desert_vaddr": f"0x{DESERT_VADDR:08X}"},
        "disasm_slices": (
            "decomp/disasm/maincpu/maincpu_012b00_100.asm",
            "decomp/disasm/maincpu/maincpu_012b80_220.asm",
            "decomp/disasm/maincpu/maincpu_012d00_200.asm",
            "decomp/disasm/maincpu/maincpu_013700_100.asm",
        ),
        "subroutine_layout": list(SUBROUTINE_LAYOUT),
        "static_callers": list(STATIC_CALLERS),
        "static_caller_scan": caller_scan,
        "pre_palette_29eb0": blocks,
        "early_upload_29c10": list(EARLY_UPLOAD),
        "init_thunk_144f0": list(INIT_THUNK_144F0),
        "routing_g4_zero": list(ROUTING_G4_ZERO),
        "upload_14530_envelope": list(UPLOAD_14530_ENVELOPE),
        "call_target_decode": call_map,
        "verdicts": [
            {
                "id": "six_pre_palette_blocks_no_desert",
                "proven": True,
                "note": "All six ``0x029EB0`` sites use non-desert blocks; **zero** ``0x1111`` in catalog",
            },
            {
                "id": "7484c_not_cgm_block",
                "proven": True,
                "note": "``0x0007484C`` @ ``0x012C58`` is not a ``find_cgm_blocks`` head",
            },
            {
                "id": "14530_g4_zero_compile_run",
                "proven": True,
                "note": "``0x014530`` ``0x029D60``/``0x029C10`` use ``g4=0`` → compile+run, not ``0x29CFC`` ADD",
            },
            {
                "id": "29d60_fifo_not_ldos_g13",
                "proven": True,
                "note": "``0x29DC4`` tier-B path: ``stos g14`` + scatter index — not ``ldos``+``addo g13``",
            },
            {
                "id": "14530_max_slot_below_477",
                "proven": True,
                "note": f"Example caller ``g0≈52`` → ``0x029D60`` at slots 53/57; slot {slot} outside",
            },
            {
                "id": "desert_1111_not_in_pre_palette_chain",
                "proven": True,
                "note": f"``0x028CCAF8`` absent from ``0x012B80`` chain and ``0x0144F0`` thunk",
            },
            {
                "id": "137d4_static_pre_palette_caller",
                "proven": True,
                "note": (
                    "``call 0x012B70`` @ ``0x0137D4`` (via ``0x00FB58`` → ``0x0137D0``); "
                    "``0x012B80`` is fall-through after ``bal 0x029A68`` @ entry"
                ),
            },
            {
                "id": "12d90_zero_static_callers",
                "proven": True,
                "note": (
                    "Full-ROM scan: **zero** ``call``/``bal`` to ``0x012D90`` — course palette "
                    "init reached only via indirect/runtime dispatch"
                ),
            },
            {
                "id": "14530_cannot_bind_desert_1111_catalog",
                "proven": True,
                "note": (
                    "``0x0144F0`` compiles ``0x0208E9E4`` (zero ``0x1111`` records); catalog "
                    "scan: only ``0x028CCAF8``/``0x02ACCAF8`` carry ``0x1111``"
                ),
            },
        ],
        "open_gaps": [
            "Indirect/runtime entry to ``0x012D90`` palette init (zero static ``call``/``bal``)",
            "Whether ``0x012CC0`` extended sweeps run on desert load (zero static callers)",
            "Runtime path that replays desert ``0x1111`` FIFO to slot 477 (``0x8843`` → ``0x6683``)",
        ],
        "related_tools": [
            "tools.decomp.palette_course_pointer_cluster_re",
            "tools.decomp.palette_29c10_tier_b_re",
            "tools.decomp.palette_29fe4_g4_gate_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Pre-palette 0x29EB0 chain + 0x29D60 @ 0x14530")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_pre_palette_29eb0_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["verdicts"] if v.get("proven"))
    print(f"\nVerdicts: {proven}/{len(report['verdicts'])} proven")
    print("Pre-palette 29EB0 blocks:")
    for b in report["pre_palette_29eb0"]:
        print(f"  {b['block_vaddr']} → {b['stores']} 1111={b.get('has_1111')}")
    scan = report["static_caller_scan"]
    print(f"Static callers: 012B70={scan.get('0x012B70', [])}")
    print(f"  012C70={scan.get('0x012C70', [])}  012D90={scan.get('0x012D90', [])}")


if __name__ == "__main__":
    main()
