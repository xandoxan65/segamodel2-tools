#!/usr/bin/env python3
"""Disasm + ROM mirror: workram ``0x005Cxxxx`` / ``0x005FCxxx`` ↔ maincpu ROM.

Model 2 palette workram cells are **not** zero in static analysis when read through
the fixed offset:

  ``rom_addr = workram_vaddr - 0x0059F000``

This explains ``0x005C8E60`` compare template bytes, format-handler jump targets
@ ``0x005FCxxx``, and why ROM scans found no ``st`` sites into those bands.

Does **not** use MAME captures.

  python3 -m tools.decomp.palette_workram_rom_mirror_re
  python3 -m tools.decomp.palette_workram_rom_mirror_re --dump-slab
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts, simulate_5ce18
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKRAM_ROM_MIRROR = 0x0059F000

# Slab cells (single ROM ``lda`` each in live code).
SLAB_CELLS: tuple[tuple[str, int, str], ...] = (
    ("compare_template", 0x005C8E60, "``0x05CE18`` 8-byte gate template"),
    ("overflow_format", 0x005C8E70, "Overflow @ ``0x02A010``"),
    ("mismatch_cell", 0x005C8E90, "Mismatch @ ``0x02A028`` (``lda`` then ``0x05CF74`` scan)"),
    ("compile_run_29c10", 0x005C8BF0, "``0x029C10`` format cell"),
    ("compile_run_entry", 0x005C8964, "``0x029958`` ``bx`` target"),
    ("dispatch_2a0f8", 0x005C9118, "``0x02A0F8`` stub"),
    ("aux_format", 0x005C9280, "``0x02A2C4`` aux format"),
)

# Format char dispatch: ``0x05CFC4`` ``ld 0x5FBFD0[g4*4]`` → ``bx`` handler.
FORMAT_TABLE_LO = 0x0005CFD0
FORMAT_TABLE_HI = 0x0005D200


def wr_to_rom(vaddr: int) -> int:
    return int(vaddr) - WORKRAM_ROM_MIRROR


def rom_slice(words: list[int], rom: int, size: int) -> bytes:
    out = bytearray()
    for off in range(0, size, 4):
        idx = (rom + off) // 4
        if idx < 0 or idx >= len(words):
            break
        out.extend(struct.pack("<I", words[idx]))
    return bytes(out[:size])


def _ascii_preview(data: bytes, limit: int = 64) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def _format_handler_table(words: list[int]) -> list[dict[str, Any]]:
    handlers: dict[int, list[str]] = {}
    for rom in range(FORMAT_TABLE_LO, FORMAT_TABLE_HI, 4):
        idx = rom // 4
        if idx >= len(words):
            break
        ptr = words[idx]
        if 0x005F0000 <= ptr <= 0x005FD000:
            ch = (rom - FORMAT_TABLE_LO) // 4
            ch_repr = chr(ch) if 32 <= ch < 127 else f"0x{ch:02x}"
            handlers.setdefault(ptr, []).append(ch_repr)
    rows: list[dict[str, Any]] = []
    for ptr in sorted(handlers):
        rom = wr_to_rom(ptr)
        first = words[rom // 4] if 0 <= rom // 4 < len(words) else 0
        rows.append(
            {
                "workram": f"0x{ptr:08X}",
                "rom_mirror": f"0x{rom:08X}",
                "chars": handlers[ptr],
                "first_insn": f"0x{first:08X}",
            }
        )
    return rows


def _slab_cell_report(words: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, vaddr, role in SLAB_CELLS:
        rom = wr_to_rom(vaddr)
        blob = rom_slice(words, rom, 64)
        refs = find_word_refs(words, vaddr)
        rows.append(
            {
                "id": name,
                "workram": f"0x{vaddr:08X}",
                "rom_mirror": f"0x{rom:08X}",
                "role": role,
                "rom_lda_count": len(refs),
                "bytes_hex": blob[:32].hex(),
                "ascii": _ascii_preview(blob, 48),
            }
        )
    return rows


def _gate_with_mirror_template(main_data: bytes, words: list[int]) -> dict[str, Any]:
    tpl = rom_slice(words, wr_to_rom(0x005C8E60), 8)
    out: dict[str, Any] = {"mirror_template_ascii": _ascii_preview(tpl, 8), "blocks": {}}
    for vaddr in COURSE_CGM_VADDRS[:2]:
        facts = cgm_block_head_facts(main_data, vaddr)
        head = bytes.fromhex(facts["head_vaddr_bytes_hex"])
        cmp_tpl = simulate_5ce18(head, tpl)
        cmp_zero = simulate_5ce18(head, bytes(8))
        out["blocks"][facts["vaddr"]] = {
            "head_ascii": facts["head_vaddr_bytes_ascii"],
            "vs_mirror_template": {"g0": cmp_tpl.g0, "reason": cmp_tpl.reason},
            "vs_zero_template": {"g0": cmp_zero.g0, "reason": cmp_zero.reason},
            "predicted_path_mirror": "matched_stream_walk @ 0x29EF0" if cmp_tpl.g0 == 0 else "mismatch @ 0x02A01C",
            "predicted_path_zero_disasm_file": "mismatch @ 0x02A01C" if cmp_zero.g0 != 0 else "matched",
        }
    return out


def build_report(*, dump_slab: bool = False) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    slab_blob = rom_slice(words, wr_to_rom(0x005C8E60), 0x430)
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "maincpu ROM mirror offset — no MAME, no XOR inference",
        "mirror_rule": {
            "formula": "rom_addr = workram_vaddr - 0x0059F000",
            "offset": f"0x{WORKRAM_ROM_MIRROR:08X}",
            "note": (
                "Disasm files ``maincpu_5c8d00_200.asm`` show zeros because they decode "
                "workram VADDRs as ROM. Handler bodies @ ``0x005FCxxx`` mirror ``0x0005Dxxx`` "
                "emit helpers (+ same offset)."
            ),
        },
        "slab_cells": _slab_cell_report(words),
        "slab_strings": [
            {"offset": off, "workram": f"0x{0x005C8E60 + off:08X}", "text": text}
            for off, text in _extract_strings(slab_blob)
        ],
        "format_handler_table": _format_handler_table(words),
        "gate_analysis": _gate_with_mirror_template(main_data, words),
        "runner_8964_mirror": {
            "workram": "0x005C8964",
            "rom_mirror": f"0x{wr_to_rom(0x005C8964):08X}",
            "first_words": [
                f"0x{words[wr_to_rom(0x005C8964) // 4 + i]:08X}" for i in range(4)
            ],
            "note": (
                "ROM mirror @ ``0x00029964`` is ``ret`` only — live runner body is still "
                "patched at runtime or reached via compile bytecode + ``0x027130``/``0x026F10``"
            ),
        },
        "compile_emit_indirect_stores": {
            "rom": "0x05D5AC",
            "insn": "``st r11,(g4)`` — bytecode chain head into block-linked arena frame",
            "frame": "``r5=g1`` block vaddr from ``0x05CF5C`` (@ ``0x05CEF8`` node link)",
            "note": "Does **not** ``st`` to ``0x005C8964`` or ``0x20B1C0`` with static immediates",
        },
        "open_gaps": [
            "Hardware alias vs explicit copy for ``0x0059F000`` mirror (arch doc not in ROM)",
            "``0x005C8E90`` ROM mirror is error string — mismatch ``0x05CF74`` scan source if gate ever mismatches",
            "``0x005C8964`` live body beyond ROM ``ret`` stub",
            "``0x20B1C0[0x20]`` fill when ``0x026980`` clone unreachable on ``0x012D90`` path",
        ],
    }
    if dump_slab:
        report["slab_blob_hex"] = slab_blob.hex()
    return report


def _extract_strings(blob: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    cur: list[str] = []
    start = 0
    for i, b in enumerate(blob):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append((start, "".join(cur)))
            cur = []
    if len(cur) >= min_len:
        out.append((start, "".join(cur)))
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump-slab", action="store_true")
    ap.add_argument(
        "-o",
        "--output",
        default=REPO_ROOT / "out/decomp/palette_workram_rom_mirror_re.json",
        type=Path,
    )
    args = ap.parse_args()
    report = build_report(dump_slab=args.dump_slab)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    gate = report["gate_analysis"]["blocks"]
    for k, v in gate.items():
        print(f"  {k}: mirror template → {v['predicted_path_mirror']}")


if __name__ == "__main__":
    main()
