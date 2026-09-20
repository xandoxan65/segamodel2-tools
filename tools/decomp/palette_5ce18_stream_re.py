#!/usr/bin/env python3
"""Disasm-backed trace: ``0x05CE18`` string gate → ``0x029EF0`` stream node reads.

Documents how ``0x029EB0`` chooses compile vs linked-stream paths and the
field layout read @ ``0x29EF4``–``0x29F64``.  Reports ROM byte facts for CGM
block heads (@ ``0x028CCAF8`` desert).  Does **not** treat marker-split
``0x1111`` segments as runtime linked-list nodes.

  python3 -m tools.decomp.palette_5ce18_stream_re
  python3 -m tools.decomp.palette_5ce18_stream_re --block 0x028CCAF8
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Workram staging (@ ``maincpu_5c8d00_200.asm`` — zero in static ROM image).
WORKRAM_TEMPLATE_8 = 0x005C8E60
WORKRAM_ROM_MIRROR = 0x0059F000
WORKRAM_DESC_OVERFLOW = 0x005C8E70  # @ ``0x02A010`` when ``0x20C954 > 0x1FF``
WORKRAM_DESC_MISMATCH = 0x005C8E90  # @ ``0x02A028`` when ``0x05CE18`` returns ``g0 != 0``

DISASM_5CE18 = (
    {"rom": "0x05CE18", "insn": "entry — save ``g14→g3`` return trampoline"},
    {"rom": "0x05CE20", "insn": "``g2`` = byte count (8 @ ``0x29EE4``); loop counter"},
    {"rom": "0x05CE30", "insn": "``ldob (g0),g5`` — chain A byte; exit if zero"},
    {"rom": "0x05CE38", "insn": "``ldob (g1),g4`` — chain B byte (@ ``0x005C8E60`` template)"},
    {"rom": "0x05CE3C", "insn": "``cmpibne g5,g4`` → mismatch exit"},
    {"rom": "0x05CE48", "insn": "``lda 0x1(g6),g6`` — advance chain A (``g6`` saved ``g0`` head)"},
    {"rom": "0x05CE4C", "insn": "``addo 1,g7,g7`` — advance chain B index"},
    {"rom": "0x05CE64", "insn": "``cmpible 0,g2`` — exhausted count → equal (``g0=0``)"},
    {"rom": "0x05CE70", "insn": "tail: lexicographic return ``0`` / ``±1`` / byte diff in ``g0``"},
)

DISASM_29EB0_BRANCH = (
    {
        "rom": "0x029ECC",
        "effect": "``g0 = lda 0(g2)`` — CGM block head dword; ``st g0,0x40(fp)`` @ ``0x29ED4``",
    },
    {
        "rom": "0x029ED8",
        "effect": "``cmpibg g4,0x1FF`` — if ``0x20C954 > 0x1FF`` → ``0x02A004`` overflow compile",
    },
    {
        "rom": "0x029EDC",
        "effect": "``g1=0x005C8E60; g2=8; bal 0x05CE18`` with ``g0`` = block head chain",
    },
    {
        "rom": "0x029EEC",
        "effect": "``cmpibne 0,g0`` — non-zero → ``0x02A01C`` mismatch compile (``0x005C8E90``)",
    },
    {
        "rom": "0x029EF0",
        "effect": "match path only: ``r5 = lda 0x40(fp)``; stream node walk @ ``0x29EF4``",
    },
    {
        "rom": "0x02A004",
        "effect": "overflow: ``lda 0x005C8E70`` → ``call 0x05CEC0`` @ ``0x02A034`` → ``bal 0x029958``",
    },
    {
        "rom": "0x02A01C",
        "effect": "mismatch: ``lda 0x005C8E90`` → ``call 0x05CEC0`` @ ``0x02A034`` → ``bal 0x029958``",
    },
)

# Inner cursor ``*(fp+0x40)`` node layout (@ ``0x29EF4``–``0x29F64``).
STREAM_NODE_FIELDS = (
    {
        "offset": 0x00,
        "size": 8,
        "rom": "0x29F00",
        "insn": "``addo g4,8,g4`` after ``ld (r5),g4`` — 8-byte prefix skipped before span",
        "role": "Header / link prefix (not further dissected in this loop)",
    },
    {
        "offset": 0x08,
        "size": 2,
        "rom": "0x29F0C",
        "insn": "``ldos (g4),r9`` then ``and r9,0xFFFF`` → ``r8``",
        "role": "u16 span added to ``0x20C950`` @ ``0x29F54``",
    },
    {
        "offset": 0x0A,
        "size": 2,
        "rom": "0x29F50",
        "insn": "``ldos (g5),r4`` — inner loop counter for ``0x029F7C``",
        "role": "``0x029FCC`` skips loop when ``r4 > 0x1FF`` (overflow tail @ ``0x29FD0``)",
    },
    {
        "offset": 0x0C,
        "size": None,
        "rom": "0x29F64",
        "insn": "``st g5,(r5)`` after ``lda 0x2(g5),g5`` — cursor past inner count",
        "role": "Payload / next fields (not read before ``0x029F7C``)",
    },
)

STREAM_CURSOR_SEMANTICS = {
    "fp_plus_40": "``0x29ED4`` stores block ``lda 0(g2)`` head; ``0x29EF0`` loads into ``r5``",
    "indirection": (
        "``ld (r5),g4`` @ ``0x29EF4`` — ``r5`` is outer pointer; ``*(r5)`` is inner stream cursor"
    ),
    "updates": (
        "``0x29F1C`` / ``0x29F64`` ``st …,(r5)`` advance inner cursor; outer ``r5`` unchanged"
    ),
    "not_marker_split": (
        "Desert ``0x1111`` marker-split binary chunks are a Python replay artifact — "
        "not asserted to equal these runtime nodes"
    ),
}


@dataclass(frozen=True)
class CompareResult:
    """Mirror ``0x05CE18`` exit semantics (static simulation)."""

    g0: int
    reason: str
    bytes_compared: int
    first_mismatch_index: int | None
    chain_a_prefix: str
    chain_b_prefix: str


def simulate_5ce18(chain_a: bytes, chain_b: bytes, *, count: int = 8) -> CompareResult:
    """Lexicographic compare of up to ``count`` bytes (null on chain A terminates early)."""
    a = bytes(chain_a)
    b = bytes(chain_b)
    g6 = 0
    g7 = 0
    remaining = count
    while remaining > 0:
        if g6 >= len(a) or a[g6] == 0:
            if remaining == count:
                return CompareResult(
                    g0=0,
                    reason="chain_a_empty_or_immediate_nul",
                    bytes_compared=0,
                    first_mismatch_index=None,
                    chain_a_prefix=a[:8].hex(),
                    chain_b_prefix=b[:8].hex(),
                )
            return CompareResult(
                g0=0,
                reason="equal_within_count",
                bytes_compared=count - remaining,
                first_mismatch_index=None,
                chain_a_prefix=a[:8].hex(),
                chain_b_prefix=b[:8].hex(),
            )
        if g7 >= len(b):
            ga = a[g6]
            return CompareResult(
                g0=ga,
                reason="chain_b_shorter",
                bytes_compared=count - remaining,
                first_mismatch_index=g6,
                chain_a_prefix=a[:8].hex(),
                chain_b_prefix=b[:8].hex(),
            )
        ga = a[g6]
        gb = b[g7]
        if ga != gb:
            if ga == 0:
                g0 = 0
            elif gb == 0:
                g0 = 1
            elif ga < gb:
                g0 = -1 & 0xFFFFFFFF
            else:
                g0 = 1
            return CompareResult(
                g0=g0,
                reason="byte_mismatch",
                bytes_compared=count - remaining,
                first_mismatch_index=g6,
                chain_a_prefix=a[:8].hex(),
                chain_b_prefix=b[:8].hex(),
            )
        g6 += 1
        g7 += 1
        remaining -= 1
    return CompareResult(
        g0=0,
        reason="equal_within_count",
        bytes_compared=count,
        first_mismatch_index=None,
        chain_a_prefix=a[:8].hex(),
        chain_b_prefix=b[:8].hex(),
    )


def _predict_29eb0_path(compare: CompareResult, *, index_20c954: int = 0) -> dict[str, Any]:
    if index_20c954 > 0x1FF:
        return {
            "path": "overflow_compile",
            "rom": "0x02A004",
            "descriptor": f"0x{WORKRAM_DESC_OVERFLOW:08X}",
            "then": "call 0x05CEC0 → bal 0x029958 → ret (no 0x29EF0 stream walk)",
        }
    if compare.g0 != 0:
        return {
            "path": "mismatch_compile",
            "rom": "0x02A01C",
            "descriptor": f"0x{WORKRAM_DESC_MISMATCH:08X}",
            "compare_g0": compare.g0,
            "compare_reason": compare.reason,
            "then": "call 0x05CEC0 with g1=block vaddr (saved r4) → bal 0x029958 → ret",
        }
    return {
        "path": "matched_stream_walk",
        "rom": "0x029EF0",
        "then": "0x29EF4 node header → 0x029F7C/0x02A0F8 inner loop (when r4<=0x1FF)",
    }


def cgm_block_head_facts(main_data: bytes, vaddr: int) -> dict[str, Any]:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}.get(vaddr)
    if block is None:
        raise SystemExit(f"no CGM block @ 0x{vaddr:08x}")
    # ``0x029ECC`` compares ``lda 0(g2)`` at block vaddr — use ``rom_offset``, not ``data_offset``.
    vaddr_base = block.rom_offset
    data_base = block.data_offset
    head_vaddr = main_data[vaddr_base : vaddr_base + 16]
    head_data = main_data[data_base : data_base + 16]
    word0 = int.from_bytes(head_vaddr[0:4], "little")
    word1 = int.from_bytes(head_vaddr[4:8], "little")
    # ROM mirror @ ``workram - 0x0059F000`` holds ``CGM 1.0 `` (see ``palette_workram_rom_mirror_re``).
    _, maincpu_words = load_maincpu_words(resolve_rom_dir())
    mirror_rom = WORKRAM_TEMPLATE_8 - WORKRAM_ROM_MIRROR
    if mirror_rom // 4 + 1 < len(maincpu_words):
        mirror_template = struct.pack(
            "<II",
            maincpu_words[mirror_rom // 4],
            maincpu_words[mirror_rom // 4 + 1],
        )
    else:
        mirror_template = bytes(8)
    static_template = bytes(8)
    compare_zero = simulate_5ce18(head_vaddr[:8], static_template)
    compare_mirror = simulate_5ce18(head_vaddr[:8], mirror_template)
    cgm8 = b"CGM 1.0 "
    compare_cgm8 = simulate_5ce18(head_vaddr[:8], cgm8)
    path_mirror = _predict_29eb0_path(compare_mirror)
    path_zero = _predict_29eb0_path(compare_zero)
    return {
        "vaddr": f"0x{vaddr:08x}",
        "rom_offset_vaddr": f"0x{vaddr_base:08x}",
        "rom_offset_data": f"0x{data_base:08x}",
        "word0_at_vaddr": f"0x{word0:08x}",
        "word1_at_vaddr": f"0x{word1:08x}",
        "head_vaddr_bytes_hex": head_vaddr[:8].hex(),
        "head_vaddr_bytes_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in head_vaddr[:8]),
        "head_data_offset_bytes_hex": head_data[:8].hex(),
        "compare_vs_rom_mirror_template": {
            "template_rom_mirror": f"0x{mirror_rom:08X}",
            "template_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in mirror_template),
            "g0": compare_mirror.g0,
            "reason": compare_mirror.reason,
            "first_mismatch_index": compare_mirror.first_mismatch_index,
        },
        "compare_vs_static_zero_template": {
            "template_vaddr": f"0x{WORKRAM_TEMPLATE_8:08X}",
            "template_note": "disasm file zeros only — use ROM mirror for hardware image",
            "g0": compare_zero.g0,
            "reason": compare_zero.reason,
            "first_mismatch_index": compare_zero.first_mismatch_index,
            "chain_a_prefix": compare_zero.chain_a_prefix,
            "chain_b_prefix": compare_zero.chain_b_prefix,
        },
        "compare_vs_cgm_header_8_bytes": {
            "template_ascii": "CGM 1.0 ",
            "g0": compare_cgm8.g0,
            "reason": compare_cgm8.reason,
            "first_mismatch_index": compare_cgm8.first_mismatch_index,
        },
        "predicted_29eb0_path": path_mirror,
        "predicted_29eb0_path_if_zero_template": path_zero,
        "stream_walk_reachable": path_mirror["path"] == "matched_stream_walk",
    }


def build_report(*, block_vaddr: int = COURSE_CGM_VADDRS[1]) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    desert = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    alpine = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[0])
    focus = cgm_block_head_facts(main_data, block_vaddr)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM CGM head bytes (no MAME, no XOR, no marker-split inference)",
        "disasm_5ce18": list(DISASM_5CE18),
        "disasm_29eb0_branch": list(DISASM_29EB0_BRANCH),
        "stream_node_fields": list(STREAM_NODE_FIELDS),
        "stream_cursor_semantics": STREAM_CURSOR_SEMANTICS,
        "workram_sites": {
            "template_8byte": f"0x{WORKRAM_TEMPLATE_8:08X}",
            "rom_mirror_template": f"0x{WORKRAM_TEMPLATE_8 - WORKRAM_ROM_MIRROR:08X}",
            "mirror_offset": f"0x{WORKRAM_ROM_MIRROR:08X}",
            "descriptor_overflow": f"0x{WORKRAM_DESC_OVERFLOW:08X}",
            "descriptor_mismatch": f"0x{WORKRAM_DESC_MISMATCH:08X}",
            "static_disasm_file": "zeros @ maincpu_5c8d00_200.asm (workram VADDR decode)",
            "rom_mirror_image": "CGM 1.0  @ rom 0x29E60 — see palette_workram_rom_mirror_re",
        },
        "cgm_blocks": {
            "alpine": alpine,
            "desert": desert,
        },
        "focus_block": focus,
        "open": [
            "ROM mirror ``workram - 0x0059F000`` — alias vs copy not proven in i960 disasm alone",
            "With mirror template ``CGM 1.0 ``, ``0x05CE18`` → ``0x029EF0`` matched stream (not ``0x02A01C``)",
            "``0x005C8964`` ROM mirror @ ``0x00029964`` is ``ret`` only — live runner body still OPEN",
            "``0x029EF0`` node link chain beyond single-node inner loop not fully traced",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x05CE18 stream gate + 0x29EF0 node layout (disasm)")
    parser.add_argument(
        "--block",
        type=lambda s: int(s, 0),
        default=COURSE_CGM_VADDRS[1],
        help="CGM block vaddr (default desert 0x028CCAF8)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_5ce18_stream_re.json",
    )
    args = parser.parse_args()

    report = build_report(block_vaddr=args.block)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    focus = report["focus_block"]
    path = focus["predicted_29eb0_path"]
    print(f"Block {focus['vaddr']} word0@ vaddr={focus['word0_at_vaddr']}")
    print(f"  5CE18 vs ROM mirror template → g0={focus.get('compare_vs_rom_mirror_template', {}).get('g0')} ({focus.get('compare_vs_rom_mirror_template', {}).get('reason')})")
    print(f"  5CE18 vs zero (disasm file) → g0={focus['compare_vs_static_zero_template']['g0']} ({focus['compare_vs_static_zero_template']['reason']})")
    print(f"  Predicted path: {path['path']} @ {path['rom']}")
    print(f"  Stream walk reachable: {focus['stream_walk_reachable']}")


if __name__ == "__main__":
    main()
