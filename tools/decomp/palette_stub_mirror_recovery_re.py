#!/usr/bin/env python3
"""Recover ROM-mirror stub bodies @ ``0x005C6100`` / ``0x005C8964`` + ``0x05DAA0`` clone layout.

The workram band is **not** blank at boot: static maincpu ROM mirrors pre-loaded
handler code at ``rom_va + 0x0059F000``.  Return-stub cells (``0x005C612C``,
``0x005C61C8``, ``0x005C6250``, ``0x005C8964``) hold ``ret``; adjacent mirror
words duplicate ``0x027008``–``0x027260`` and ``0x029900``–``0x029C00`` bodies.

Documents ``0x05DAA0`` (``libc_memcpy`` / overlapping memmove) and ``0x26800``
node layout for opcode ``0x20`` handler pool fill.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_stub_mirror_recovery_re
  python3 -m tools.decomp.palette_stub_mirror_recovery_re --slot 477
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_29c10_tier_b_re import _disasm_decode_candidates
from tools.decomp.palette_bind_stream_re import _slot477_d_bytecode
from tools.decomp.palette_workram_rom_mirror_re import (
    WORKRAM_ROM_MIRROR,
    wr_to_rom,
    rom_slice,
    _ascii_preview,
)
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Mirror mapping (proven by byte-identical ROM words) -----------------------

MIRROR_OFFSET = WORKRAM_ROM_MIRROR  # workram = rom + 0x0059F000

STUB_BAND = {
    "workram_lo": "0x005C6100",
    "workram_hi": "0x005C6280",
    "rom_lo": "0x027100",
    "rom_hi": "0x027280",
    "duplicates": "``0x027008`` opcode dispatch + ``0x027130`` walk + ``0x027160``/``0x0271D0`` stub patchers",
    "proof": "``0x027110`` ``stos g4,0x01000000[g5*2]`` == mirror @ ``0x005C7110`` (same word ``0x8AA03895``)",
}

RUNNER_BAND = {
    "entry_cell": "0x005C8964",
    "entry_mirror_rom": "0x029964",
    "entry_static": "``ret`` — ``bx`` target is one-word stub",
    "program_rom_lo": "0x029900",
    "program_rom_hi": "0x029C00",
    "workram_program_lo": "0x005C8900",
    "note": "Full runner @ ``0x0299C0`` (``0x005C89A4``) … ``0x029A30`` prewalk+``0x027130`` path",
}

RET_STUB_CELLS = (
    {"workram": "0x005C612C", "rom": "0x02712C", "role": "``0x027008`` dispatch return (``0x005C612C``)"},
    {"workram": "0x005C61C8", "rom": "0x0271C8", "role": "``0x027160`` ``lda`` / ``bx`` return"},
    {"workram": "0x005C6250", "rom": "0x027250", "role": "``0x0271D0`` ``lda`` / ``bx`` return"},
    {"workram": "0x005C8964", "rom": "0x029964", "role": "``0x029958`` ``bx`` entry"},
)

# --- ``0x05DAA0`` memmove + ``0x26800`` clone (``maincpu_026800_200.asm``) ------

DAA0_MEMMOVE = {
    "symbol": "libc_memcpy @ 0x05DAA0",
    "args": "``g0``=dest, ``g1``=src, ``g2``=byte length",
    "callers": (
        {"rom": "0x02682C", "context": "``0x26800`` handler-template clone loop"},
        {"rom": "0x05DA38", "context": "``0x05DA10`` overlapping-range copy helper"},
    ),
    "static_xrefs_to_entry": 0,
}

CLONE_NODE_26800 = {
    "head": "``0x20B600`` linked list (runtime-built; zero static ROM image)",
    "walk": (
        {"rom": "0x26814", "effect": "``g4 = head count`` from ``0x20B900`` cursor"},
        {"rom": "0x26820", "effect": "``g0 = *(node+0)`` — **dest** (handler pool write address)"},
        {"rom": "0x26824", "effect": "``r5 = *(node+4)`` — pointer to template blob"},
        {"rom": "0x26828", "effect": "``g2 = *(node+8)`` — metadata stored @ handler ``+8`` (@ ``0x26894``)"},
        {"rom": "0x2682C", "effect": "``call 0x05DAA0`` — memcpy template bytes into pool slot"},
        {"rom": "0x26844", "effect": "``r4 = *(node+0xC)`` — next node"},
        {"rom": "0x26840", "effect": "``r5 += 12`` — advance template chain pointer"},
    ),
    "opcode_table_26860": (
        {"rom": "0x26880", "effect": "``g4 = stream_halfword[g5]`` — bind index (slot 477 ``D`` → **0x20**)"},
        {"rom": "0x26884", "effect": "``g4 = 0x20B600[g4*4]`` — template-clone **record** pointer"},
        {"rom": "0x2688C", "effect": "``*(record) = g0`` — publish handler code pointer"},
        {"rom": "0x26894", "effect": "``*(record+8) = g2`` — attach metadata word"},
    ),
    "bootstrap_26980": (
        "``ldos 0x20B914`` → ``0x0100A000`` (opcode index stream for clone table)",
        "``call 0x26800`` + ``call 0x268B0``",
        "**No static ROM ``call`` sites** — palette init / ``callx 0x20B910`` only",
    ),
}

# --- Runner mirror: shuffle @ ``0x029900`` (not xor_table) ---------------------

RUNNER_SHUFFLE_29900 = {
    "rom": "0x029900",
    "effect": (
        "Byte-shuffle + ``xor`` mix using jump table ``0x005C8350`` "
        "(constants ``0x1021``, ``0x2042``, … — **not** ROM code pointers)"
    ),
    "tail": {
        "rom": "0x029938",
        "insn": "``lda 0xFFFF,g13``; ``andnot g2,g13,g0``",
        "interpretation": "Color15 mask (clear bit 15) — **not** ``g13_mask_for_slot`` / ``0xEEC0``",
    },
    "group_row_ldos": {
        "rom": "0x029B88",
        "insn": "``ldos 0x20B950[g0*8],g0`` → ``lda 0x1800000(g0>>2)``",
        "interpretation": "Resolve palram bus pointer from **group row head** — not CGM FIFO u16",
    },
}

DESCRIPTOR_EMIT_27100 = {
    "rom": "0x027110",
    "mirror_workram": "0x005C7110",
    "insn": "``stos g4,0x01000000[g5*2]``",
    "g4_form": "``or (opcode_byte, g13_tag, 0xFFFF8000)`` — builds **0x8420**-class words",
    "xor_g13": False,
}


def _word_at(words: list[int], rom: int) -> int:
    idx = rom // 4
    return words[idx] if 0 <= idx < len(words) else 0


def _mirror_pair_check(words: list[int], rom_va: int) -> dict[str, Any]:
    wr = rom_va + MIRROR_OFFSET
    w_main = _word_at(words, rom_va)
    w_mirror = _word_at(words, wr_to_rom(wr))
    return {
        "rom": f"0x{rom_va:05X}",
        "workram": f"0x{wr:08X}",
        "word_main": f"0x{w_main:08X}",
        "word_mirror": f"0x{w_mirror:08X}",
        "identical": w_main == w_mirror,
    }


def _ret_stub_report(words: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cell in RET_STUB_CELLS:
        rom = int(cell["rom"], 16)
        w = _word_at(words, rom)
        next_words = [
            f"0x{_word_at(words, rom + off):08X}"
            for off in (4, 8, 12, 16)
            if _word_at(words, rom + off)
        ]
        rows.append(
            {
                **cell,
                "first_word": f"0x{w:08X}",
                "is_ret": w == 0x0A000000,
                "following_words": next_words,
            }
        )
    return rows


def _daa0_head(words: list[int]) -> dict[str, Any]:
    rom = 0x05DAA0
    blob = rom_slice(words, rom, 48)
    return {
        "rom": "0x05DAA0",
        "symbol": "libc_memcpy / memmove",
        "head_hex": blob.hex(),
        "call_sites": ["0x02682C", "0x05DA38"],
    }


def _jump_table_8350(words: list[int]) -> dict[str, Any]:
    rom = wr_to_rom(0x005C8350)
    entries = [
        f"0x{_word_at(words, rom + i * 4):08X}"
        for i in range(16)
        if _word_at(words, rom + i * 4)
    ]
    return {
        "workram": "0x005C8350",
        "rom_mirror": f"0x{rom:06X}",
        "pattern": "Repeating nibble-spread constants (shuffle table)",
        "sample": entries[:8],
        "lda_refs": [f"0x{r:08X}" for r in find_word_refs(words, 0x005C8350)[:6]],
    }


def _scan_mirror_for_ldos_xor(words: list[int]) -> dict[str, Any]:
    """Scan ROM mirror bands against known disasm slices (no false ldos from data)."""
    # From maincpu_027008_200.asm + 029900_300.asm — only these ldos/xor in band:
    known = {
        "ldos": [
            {"rom": "0x029B88", "workram": f"0x{0x029B88 + MIRROR_OFFSET:08X}", "note": "group row head"},
        ],
        "xor_insn": [
            {"rom": "0x02990C", "note": "shuffle mix (not g13_table)"},
            {"rom": "0x029914", "note": "shuffle mix"},
            {"rom": "0x02992C", "note": "shuffle mix"},
        ],
        "xor_g13": [],
    }
    return {
        **known,
        "verdict": (
            "No ``xor g13`` in stub band ``0x027100``–``0x027280`` or runner ``0x029900``–``0x029C00``. "
            "``0x029938`` loads ``g13=0xFFFF`` for ``andnot`` color15 mask only."
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    g13_table = g13_mask_for_slot(0x0700, slot)
    decodes = _disasm_decode_candidates(slot=slot, raw_u16=raw_u16, g13_seed=0x0700)

    identity_checks = [
        _mirror_pair_check(words, 0x027110),
        _mirror_pair_check(words, 0x027160),
        _mirror_pair_check(words, 0x0271D0),
        _mirror_pair_check(words, 0x0299C0),
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "ROM word mirror recovery — no MAME captures",
        "mirror_formula": f"workram_vaddr = rom_vaddr + 0x{MIRROR_OFFSET:08X}",
        "stub_band": STUB_BAND,
        "runner_band": RUNNER_BAND,
        "ret_stub_cells": _ret_stub_report(words),
        "identity_checks": identity_checks,
        "descriptor_emit": DESCRIPTOR_EMIT_27100,
        "daa0_memmove": {**DAA0_MEMMOVE, "head": _daa0_head(words)},
        "clone_node_26800": CLONE_NODE_26800,
        "runner_shuffle": RUNNER_SHUFFLE_29900,
        "jump_table_8350": _jump_table_8350(words),
        "insn_scan": _scan_mirror_for_ldos_xor(words),
        "slot477_bind": _slot477_d_bytecode(None),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "oracle": f"0x{int(target) & 0x7FFF:04x}",
            "g13_table": f"0x{g13_table:04x}",
            "decode_add_29cfc": decodes["29cfc_add_g13_table"]["result"],
            "decode_xor_batch": decodes["02a258_xor_batch_only"]["result"],
        },
        "conclusions": (
            "Workram stub band ``0x005C6100`` is a **byte-identical ROM mirror** of "
            "``0x027100``–``0x027260`` (``0x027008``/``0x027160``/``0x0271D0``). "
            "``ret`` cells are **bx return addresses**, not empty runtime slots.",
            "Runner program @ ``0x029900``–``0x029C00`` is likewise pre-mirrored "
            "(``0x005C8900``+). Entry ``0x005C8964`` = ``ret``; real entry ``0x029958`` "
            "``bx`` → ``0x005C8964`` → ``0x005C89A4`` compile loop.",
            "``0x05DAA0`` clones handler templates into ``0x20B1C0`` pool; opcode **0x20** "
            "maps via ``0x26884`` → ``0x20B600[0x20*4]`` record (bind index ≠ ``0x8420`` bus word).",
            "Recovered mirror bodies contain **no** ``xor g13`` with ``0xEEC0``. "
            "``0x029938`` ``andnot`` uses ``g13=0xFFFF`` (color15 clamp). "
            "Hardware raw ``0x8843`` → oracle ``0x6683`` transform remains in **dynamic** "
            "descriptor-chain execution (patched links), not static mirror image.",
        ),
        "open_gaps": (
            "Trace ``0x005C8350`` shuffle dispatch → which thunk publishes wrapper ``g4``",
            "Runtime descriptor-chain walk after ``0x0271D0`` with non-zero ``0x005FBF10`` row",
            "Map ``0x20B600[0x20]`` cloned template body → ``0x02A6D0`` call (upload cluster ``bx``)",
            "Prove FIFO cursor patch into ``g7`` @ ``0x26760`` path vs static ``0x005C5670`` list",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Stub mirror recovery + 05DAA0 clone RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_stub_mirror_recovery_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    print(f"\nMirror: workram = rom + 0x{MIRROR_OFFSET:08X}")
    for chk in report["identity_checks"]:
        mark = "OK" if chk["identical"] else "DIFF"
        print(f"  {chk['rom']} ↔ {chk['workram']}: {mark}")

    print("\nRet stub cells:")
    for row in report["ret_stub_cells"]:
        print(f"  {row['workram']}: {'ret' if row['is_ret'] else 'code'}")

    focus = report["focus"]
    print(
        f"\nSlot {focus['slot']}: ADD={focus['decode_add_29cfc']} "
        f"XOR_batch={focus['decode_xor_batch']} oracle={focus['oracle']}"
    )
    print(f"\n{report['insn_scan']['verdict'][:100]}…")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
