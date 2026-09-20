#!/usr/bin/env python3
"""Disasm trace: ``0x05CEC0`` compile → ``0x029958`` run → ``0x029C10`` upload sweeps.

Documents the **desert mismatch-compile path** (``0x02A01C``) and the palette-init
caller chain @ ``0x012D90`` that invokes it.  Workram bodies @ ``0x005C8964`` are
not in static ROM.

Does **not** infer FIFO decode or XOR.

  python3 -m tools.decomp.palette_29958_post_compile_re
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts, build_report as build_5ce18
from tools.model2_palette import COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKRAM_RUN_TRAMPOLINE = 0x005C8964  # lda @ 0x029950; bx @ 0x029960

# --- ``0x029958`` ---------------------------------------------------------------

DISASM_29958 = (
    {"rom": "0x029950", "insn": "``lda 0x005C8964,g14``"},
    {"rom": "0x029958", "insn": "``mov g14,g0`` — run entry = workram trampoline"},
    {"rom": "0x029960", "insn": "``bx (g0)`` — executes patched post-compile program"},
    {"rom": "0x029964", "insn": "``ret`` — only if trampoline returns"},
)

# Sites that ``bal/call 0x029958`` after ``0x05CEC0`` compile.
CALLERS_29958 = (
    {
        "rom": "0x02A038",
        "caller": "0x029EB0",
        "pre": "``call 0x05CEC0`` with ``g0=0x005C8E90``, ``g1=block vaddr`` (mismatch @ ``0x02A01C``)",
        "post": "``subo 1,0,g0`` @ ``0x02A03C`` → ``g0=-1`` on return to ``0x012E1C``/``0x012E48``",
    },
    {
        "rom": "0x02A034",
        "caller": "0x029EB0",
        "pre": "``call 0x05CEC0`` with ``g0=0x005C8E70`` (overflow @ ``0x02A004``)",
        "post": "same ``0x02A03C`` return convention",
    },
    {
        "rom": "0x029C68",
        "caller": "0x029C10",
        "pre": "``call 0x05CEC0`` with ``g0=0x005C8BF0`` after ``0x026FD8`` arena alloc",
        "post": "``subo 1,0,g0`` @ ``0x029C6C``",
    },
    {
        "rom": "0x029DB8",
        "caller": "0x029D60",
        "pre": "``call 0x05CEC0`` with ``g0=0x005C8D40``",
        "post": "``subo 1,0,g0`` @ ``0x029DBC``",
    },
    {
        "rom": "0x29A50",
        "caller": "0x029A30",
        "pre": "``call 0x027130`` format walk then ``bal 0x029958``",
        "post": "alternate compile/run entry (not ``0x012D90`` chain)",
    },
)

# --- ``0x012D90`` palette init (desert CGM compile) ------------------------------

PALETTE_INIT_12D90 = (
    {"rom": "0x012DD0", "effect": "``call 0x026B60`` — arena / bus setup @ ``0x01002000``"},
    {"rom": "0x012DE4", "effect": "``call 0x027260`` (g0=15,g1=30,g2=35,g3=6) — patch staging @ ``0x01000000``"},
    {"rom": "0x012DF8", "effect": "``call 0x027260`` (g0=7,g1=29,g2=55,g3=21) — second chain patch"},
    {"rom": "0x012E08", "effect": "``g2=0x028AF104`` alpine CGM block vaddr"},
    {"rom": "0x012E18", "effect": "``call 0x029EB0`` (g4=4) → ``st g0,0x20A79C`` @ ``0x012E1C``"},
    {"rom": "0x012E2C", "effect": "``g2=0x028CCAF8`` desert CGM block vaddr"},
    {"rom": "0x012E3C", "effect": "``call 0x029EB0`` (g4=4) → ``st g0,0x20A7B0`` @ ``0x012E48``"},
    {"rom": "0x012E40", "note": "``ld 0x20A7B4,g2`` + ``st g0,0x20A7B0`` — desert return stored separately from alpine"},
)

# ``0x029C10`` upload sweeps after compile (all use ``g2=ld 0x20A79C`` — alpine context).
UPLOAD_SWEEPS_29C10: tuple[dict[str, Any], ...] = (
    {"rom": "0x012E60", "g0": 20, "g1": 3, "g3": 0, "g4": 2, "g2": "0x20A79C"},
    {"rom": "0x012E7C", "g0": 7, "g1": 11, "g3": 8, "g4": 2, "g2": "0x20A79C"},
    {"rom": "0x012E98", "g0": 17, "g1": 11, "g3": 7, "g4": 2, "g2": "0x20A79C"},
    {"rom": "0x012EB4", "g0": 29, "g1": 11, "g3": 6, "g4": 2, "g2": "0x20A79C"},
    {"rom": "0x012ED4", "g0": 45, "g1": 11, "g3": 4, "g4": 2, "g2": "0x20A79C", "r11": 1},
)

DISASM_29C10_ROUTING = (
    {
        "rom": "0x029C10",
        "effect": "``cmpi g2,0; bl 0x029C34`` — **g2 < 0** (e.g. post-compile sentinel) → compile+run path",
    },
    {
        "rom": "0x029C2C",
        "effect": "``g5 = g4 & 7``; ``cmpibge 3,g5,0x29C74`` — tag path when ``g4 & 7 >= 3``",
    },
    {
        "rom": "0x029C74",
        "effect": "FIFO/add path: ``addo g0,g1<<6`` → palram bus; ``addo g13,g4`` @ ``0x29CFC`` for ``U``",
    },
    {
        "rom": "0x029C34",
        "effect": (
            "Compile+run: ``bal 0x029AE8`` slot clamp → ``call 0x05CEC0`` (``0x005C8BF0``) "
            "→ ``bal 0x029958``"
        ),
    },
)

# --- ``0x05CF50`` compile (feeds run trampoline) ---------------------------------

DISASM_5CF50_COMPILE = (
    {"rom": "0x05CF74", "effect": "Scan format string @ ``r12`` (= ``g0`` from ``lda 0x005C8E90`` on desert path)"},
    {"rom": "0x05CF94", "effect": "Digit opcodes: ``bal 0x027008`` — emit descriptor bytes @ ``0x01000000``"},
    {"rom": "0x05CFBC", "effect": "Letter opcodes: ``bx 0x005FBFD0[g4*4]`` — ``D`` @ ``0x05D3DC``, etc."},
    {"rom": "0x05D860", "effect": "``bal 0x027008`` emit loop — builds bytecode chain ``r11``"},
    {"rom": "0x05DFA4", "effect": "``stob`` emit loop fills handler blob → record ``+0x14`` for ``0x02A0F8``"},
)

WORKRAM_POINTERS = {
    "0x20A79C": {
        "writes": ["0x012E1C"],
        "reads": ["0x012E64", "0x012E80", "0x012E9C", "0x012EBC"],
        "role": "Alpine ``0x029EB0`` return; passed as ``g2`` to all post-init ``0x029C10`` sweeps",
    },
    "0x20A7B0": {
        "writes": ["0x012E48"],
        "reads": [],
        "role": "Desert ``0x029EB0`` return — **no static ROM ld sites** (OPEN: consumer path)",
    },
    "0x005C8964": {
        "writes": [],
        "reads": ["0x029950"],
        "role": "Post-compile run trampoline — patched body not in ROM",
    },
}


def build_report() -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    desert_head = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    gate = build_5ce18(block_vaddr=COURSE_CGM_VADDRS[1])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm only — no MAME, no XOR inference",
        "desert_pipeline_summary": (
            "Static ROM: desert ``0x029EB0`` takes ``0x02A01C`` mismatch compile "
            "(``0x05CE18`` vs zero ``0x005C8E60`` template), **not** ``0x029EF0`` stream walk. "
            "Compile ``0x05CEC0``/``0x05CF50`` then ``bal 0x029958`` runs patched program @ "
            f"``0x{WORKRAM_RUN_TRAMPOLINE:08X}``. Post-init slot sweeps use ``0x029C10`` with "
            "``g2=0x20A79C`` (alpine context), not ``0x20A7B0``."
        ),
        "disasm_29958": list(DISASM_29958),
        "callers_29958": list(CALLERS_29958),
        "palette_init_12d90": list(PALETTE_INIT_12D90),
        "upload_sweeps_29c10": list(UPLOAD_SWEEPS_29C10),
        "disasm_29c10_routing": list(DISASM_29C10_ROUTING),
        "disasm_5cf50_compile": list(DISASM_5CF50_COMPILE),
        "workram_pointers": WORKRAM_POINTERS,
        "desert_29eb0_gate": gate["focus_block"],
        "tier_b_note": (
            "Slot 477 is outside post-init ``0x029C10`` sweep windows (g0 max 45, g1=11). "
            "``0x029F7C``→``0x02A0F8`` is **matched-stream only** (``0x29EF0``). Desert static "
            "gate selects ``0x02A01C`` compile+run; tier-B hardware path is inside "
            "``0x005C8964`` patched runner — body OPEN."
        ),
        "upstream": "Pre-compile staging: ``palette_staging_bootstrap_re`` (@ ``0x012DE4``/``0x012DF8`` ``0x027260``)",
        "open": [
            "``0x005C8964`` patched thunk body — static ROM has zero words @ ``0x005C8964``",
            "``0x20A7B0`` desert compile return — written @ ``0x012E48``, never read in disasm",
            "``0x012E3C`` ``g0=-1`` return convention vs ``0x029C10`` ``g2<0`` routing — "
            "exact sentinel semantics not fully closed",
            "Whether ``0x029C10`` sweeps replay desert ``0x1111`` payload or only alpine "
            "compile context @ ``0x20A79C``",
            "``0x005C8E60`` template population — no ROM ``st`` sites",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x029958 post-compile chain (disasm)")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29958_post_compile_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(report["desert_pipeline_summary"])
    print(f"\nUpload sweeps: {len(UPLOAD_SWEEPS_29C10)} × 0x029C10 @ 0x012E60–0x012ED4")
    print(f"  0x20A7B0 reads in ROM: {len(WORKRAM_POINTERS['0x20A7B0']['reads'])}")


if __name__ == "__main__":
    main()
