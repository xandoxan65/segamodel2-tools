#!/usr/bin/env python3
"""Disasm trace: ``0x012D90`` init → ``0x029EB0`` compile templates → ``0x029958`` run.

Documents compile-template pointers (``0x005C8E60``/``70``/``90``/``BF0``),
``0x05CEC0`` record fields, handler-path split (``D`` vs ``0x05DE00``), and
workram arena ROM xrefs.  No XOR inference or MAME captures.

  python3 -m tools.decomp.palette_cgm_compile_path_re
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Workram compile-template pointers (single ROM ``lda`` each — zero in ``maincpu_5c8d00_200.asm``).
COMPILE_TEMPLATE_PTRS = (
    {"workram": "0x005C8E60", "rom_lda": "0x029EE0", "role": "``0x05CE18`` 8-byte compare template"},
    {"workram": "0x005C8E70", "rom_lda": "0x02A014", "role": "Overflow compile format @ ``0x02A004``"},
    {"workram": "0x005C8E90", "rom_lda": "0x02A02C", "role": "Mismatch compile format @ ``0x02A01C`` (desert)"},
    {"workram": "0x005C8BF0", "rom_lda": "0x029C5C", "role": "``0x029C10`` negative-``g2`` compile+run path"},
    {"workram": "0x005C8D40", "rom_lda": "0x029DAC", "role": "``0x029D60`` compile variant"},
)

WORKRAM_ARENA_LAYOUT = (
    {"base": "0x005C8E60", "size": 8, "role": "Compare template (gate only)"},
    {"base": "0x005C8E70", "offset": 0x10, "role": "Overflow format ptr"},
    {"base": "0x005C8E90", "offset": 0x30, "role": "Mismatch format ptr (desert compile scan @ ``0x05CF74``)"},
    {"base": "0x005C8964", "offset": 0x104, "role": "Post-compile run entry (``bx`` @ ``0x029960``)"},
    {"base": "0x005C9118", "offset": 0x2B8, "role": "``0x02A0F8`` indirect dispatch stub"},
    {"base": "0x005C9280", "offset": 0x420, "role": "Aux compile format @ ``0x02A2C4``"},
)

# --- ``0x012D90`` palette init: proven ``g4`` into ``0x05CEC0`` -------------------

PALETTE_INIT_COMPILE_CALLS = (
    {
        "rom": "0x012E14",
        "insn": "``mov 4,g4``",
        "then": "``call 0x029EB0`` alpine @ ``g2=0x028AF104``",
    },
    {
        "rom": "0x012E38",
        "insn": "``mov 4,g4``",
        "then": "``call 0x029EB0`` desert @ ``g2=0x028CCAF8``",
    },
    {
        "rom": "0x05CEE0",
        "effect": "``stq g4,0x10(g13)`` — record ``+0x10`` qword = **4** on both course inits",
    },
    {
        "rom": "0x02A108",
        "effect": (
            "Matched-stream consumer: ``ldis +0x10/+0x12`` → ``mul`` → ``lda +0x14[g4*2]`` "
            "(``0x02A0F8`` only — desert mismatch skips this)"
        ),
    },
)

# --- Handler path split in ``0x05CF50`` -----------------------------------------

HANDLER_PATHS = (
    {
        "char": "D",
        "rom_entry": "0x05D3DC",
        "path": "``setbit 0,r9`` → template row @ ``0x05D7E8`` → ``0x05D860`` → ``bal 0x027008``",
        "bytecode_store": "0x05D5AC ``st r11,(g4)``",
        "calls_5de00": False,
    },
    {
        "char": "U",
        "rom_entry": "0x05D714",
        "path": "Same emit as ``D``; runtime ADD @ ``0x029CFC`` on legacy ``0x029C10`` path only",
        "calls_5de00": False,
    },
    {
        "char": "E/f/g",
        "rom_entry": "0x05D448",
        "path": "Float/u32 arg parse → ``call 0x05DE00`` @ ``0x05D524``",
        "calls_5de00": True,
        "de00_writes": "``0x05DFA4`` emit → record ``+0x14`` handler blob; ``0x05DFEC`` link @ ``+0x8``",
    },
)

CEC0_BLOCK_LINK = {
    "rom": "0x05CEF8",
    "insn": "``st g13,(g1)``; ``st 4,0x4(g1)``",
    "effect": (
        "Compile record ``g13`` linked at **block vaddr** ``g1`` (``r4`` from ``0x029EB0`` = "
        "``0x028CCAF8`` desert). Format scan uses separate ``g0=0x005C8E90`` pointer."
    ),
}

# --- ``0x029958`` vs nearby XOR cluster ----------------------------------------

RUNNER_VS_XOR_CLUSTER = {
    "runner_29958": {
        "rom": "0x029958",
        "insns": ["``lda 0x005C8964``", "``bx (g0)``"],
        "xor_in_entry": False,
    },
    "xor_cluster_29900": {
        "rom": "0x029900",
        "insns": [
            "``xor g4,g5,g2`` @ ``0x02990C``",
            "``ld 0x005C8350[g4*4]`` @ ``0x029920``",
        ],
        "note": (
            "Separate routine in same disasm slice; **no** static ``call/bal`` sites to "
            "``0x029900`` found — likely workram ``bx`` only. Not proven on desert ``0x02A038`` path."
        ),
    },
}


def _workram_xref_table() -> list[dict[str, Any]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    rows: list[dict[str, Any]] = []
    for lo in range(0x005C8000, 0x005C9100, 4):
        refs = find_word_refs(words, lo)
        if refs:
            rows.append(
                {
                    "workram": f"0x{lo:08X}",
                    "rom_refs": [f"0x{r:08X}" for r in refs],
                    "ref_count": len(refs),
                }
            )
    return rows


def _cgm_block_heads() -> dict[str, Any]:
    md = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    blocks = {b.vaddr: b for b in find_cgm_blocks(md)}
    out: dict[str, Any] = {}
    for label, vaddr in (("alpine", COURSE_CGM_VADDRS[0]), ("desert", COURSE_CGM_VADDRS[1])):
        b = blocks[vaddr]
        head = md[b.rom_offset : b.rom_offset + 16]
        out[label] = {
            "vaddr": f"0x{vaddr:08X}",
            "rom_offset": f"0x{b.rom_offset:X}",
            "head16_hex": head.hex(),
            "word0": f"0x{int.from_bytes(head[0:4], 'little'):08X}",
            "gate_note": (
                "``0x05CE18`` compares first 8 bytes vs zero ``0x005C8E60``; "
                f"desert word0 low bytes → mismatch → ``0x02A01C``"
            ),
        }
    return out


def build_report() -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM/CGM bytes — no XOR guessing, no MAME",
        "summary": (
            "Desert palette init (@ ``0x012E3C``) calls ``0x029EB0`` with ``g4=4`` and "
            "``g2=0x028CCAF8``. Block head mismatches zero template → ``0x05CEC0`` compiles "
            "format bytes @ ``0x005C8E90`` (workram, zero in static ROM). Record ``+0x10`` "
            "stores ``g4=4`` (@ ``0x05CEE0``). ``D`` handlers emit via ``0x05D860``/``0x027008`` "
            "and store ``r11`` @ ``0x05D5AC`` — they do **not** call ``0x05DE00``. "
            "``0x029958`` ``bx`` @ ``0x005C8964``; runner body OPEN."
        ),
        "compile_template_ptrs": list(COMPILE_TEMPLATE_PTRS),
        "workram_arena_layout": list(WORKRAM_ARENA_LAYOUT),
        "workram_rom_xrefs": _workram_xref_table(),
        "palette_init_compile_calls": list(PALETTE_INIT_COMPILE_CALLS),
        "handler_paths": list(HANDLER_PATHS),
        "cec0_block_link": CEC0_BLOCK_LINK,
        "runner_vs_xor_cluster": RUNNER_VS_XOR_CLUSTER,
        "cgm_block_heads": _cgm_block_heads(),
        "open": [
            "No ROM ``st``/``stq`` to ``0x005C8E90`` (or any ``0x005C8xxx`` template body)",
            "Population of ``0x005C8E90`` format bytes before first ``0x012E3C`` desert compile",
            "``0x005C8964`` patched thunk body — links ``0x05D5AC`` bytecode to ``0x026F10``/upload cluster",
            "FIFO ``ldos``/``ldl`` on desert ``0x02A038`` compile+run path (``0x02A148`` is ``0x02A0F8``/matched path)",
            "How record ``+0x10`` ``g4=4`` reaches ``0x02A6D0`` wrapper ``g4``/``r14`` for tier-B slots",
        ],
        "related": [
            "palette_workram_runner_re",
            "palette_compile_run_re",
            "palette_5ce18_stream_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CGM compile path static RE")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_cgm_compile_path_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(report["summary"])
    desert = report["cgm_block_heads"]["desert"]
    print(f"\nDesert block head: {desert['head16_hex']} (word0 {desert['word0']})")
    print(f"Workram ROM xrefs in 5C8000–5C9100: {len(report['workram_rom_xrefs'])}")


if __name__ == "__main__":
    main()
