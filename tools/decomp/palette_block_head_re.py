#!/usr/bin/env python3
"""Disasm + ROM negative scan: CGM block head / ``fp+0x40`` stream root.

Documents ``0x029ECC`` / ``0x05CE18`` pointer semantics, static desert block
layout, and **zero** ROM stores into ``0x028CCAF8``.  No MAME.

  python3 -m tools.decomp.palette_block_head_re
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import simulate_5ce18
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

DISASM_HEAD_CHAIN = (
    {"rom": "0x029ECC", "effect": "``g2`` = block vaddr (@ ``0x012E2C`` ``0x028CCAF8``); ``lda 0(g2),g0``"},
    {"rom": "0x029ED4", "effect": "``st g0,0x40(fp)`` — saved stream root dword (not ``g2`` itself)"},
    {"rom": "0x029EDC", "effect": "``lda 0x005C8E60,g1`` — template cell **contents** for chain B"},
    {"rom": "0x05CE30", "effect": "``ldob (g0),g5`` — chain A dereferences **saved dword** as pointer"},
    {"rom": "0x05CE38", "effect": "``ldob (g1),g4`` — chain B dereferences template cell contents"},
    {"rom": "0x029EF0", "effect": "``r5 = lda 0x40(fp)``; ``ld (r5),g4`` — inner cursor from ``*r5``"},
    {"rom": "0x29F1C", "effect": "``st g4,(r5)`` — write inner cursor back through same ``r5`` cell"},
)

GATE_POINTER_MODEL = {
    "static_desert_word0": "``0x204D4743`` (ASCII ``CGM ``) — same first dword as ROM-mirror template",
    "static_compare": (
        "Both gate chains load **identical** pointer values → ``0x05CE18`` compares bytes at "
        "the **same** address → ``g0==0`` (matched) without requiring word0 == block vaddr"
    ),
    "stream_walk_tension": (
        "``ld (r5)`` with ``r5==0x204D4743`` is not a valid main_data offset in static files; "
        "either CPU map aliases that vaddr, word0 is patched to ``0x028CCAF8`` at runtime, "
        "or ``r5`` is repointed before ``0x29EF4`` (no static ``st`` proof)"
    ),
    "rom_store_scan": "Zero ``st``/``stq`` immediates to ``0x028CCAF8`` or ``0x028AF104`` in maincpu ROM",
}


def _scan_stores_to_vaddr(words: list[int], vaddr: int) -> list[str]:
    refs = find_word_refs(words, vaddr)
    return [f"0x{r:06X}" for r in refs]

def block_layout(main_data: bytes, vaddr: int) -> dict[str, Any]:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[vaddr]
    base = block.rom_offset
    chunk = main_data[base : base + 0x40]
    words = [struct.unpack_from("<I", chunk, o)[0] for o in range(0, 0x40, 4)]
    link_c = struct.unpack_from("<I", chunk, 0x0C)[0]
    return {
        "vaddr": f"0x{vaddr:08x}",
        "rom_offset": f"0x{base:08x}",
        "dwords_0x00_0x3c": [f"0x{w:08x}" for w in words],
        "ascii_head_8": chunk[:8].decode("latin1", errors="replace"),
        "u16_at_08_span": f"0x{struct.unpack_from('<H', chunk, 8)[0]:04x}",
        "u16_at_0a_inner": f"0x{struct.unpack_from('<H', chunk, 0xA)[0]:04x}",
        "dword_at_0c_link": f"0x{link_c:08x}",
        "cgm_record_1111_at": next(
            (f"+0x{off:02X}" for off in range(0x20, 0x40, 4) if (words[off // 4] & 0xFFFF) == 0x1111),
            None,
        ),
        "note": (
            "Static ``+0x08``/``+0x0A`` match ``0x29F0C``/``0x29F50`` layout when cursor points at "
            "``block+8``; ``fp+0x40`` still holds ``+0x00`` dword per disasm"
        ),
    }


def build_report() -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    _, words = load_maincpu_words(rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    desert = block_layout(main_data, COURSE_CGM_VADDRS[1])
    alpine = block_layout(main_data, COURSE_CGM_VADDRS[0])
    b = {x.vaddr: x for x in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    head_bytes = main_data[b.rom_offset : b.rom_offset + 8]
    mirror_rom = 0x005C8E60 - 0x0059F000
    mirror_tpl = struct.pack("<II", words[mirror_rom // 4], words[mirror_rom // 4 + 1])
    gate = simulate_5ce18(head_bytes, mirror_tpl)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM negative scan (no MAME)",
        "disasm_head_chain": list(DISASM_HEAD_CHAIN),
        "gate_pointer_model": GATE_POINTER_MODEL,
        "rom_refs": {
            "note": "``find_word_refs`` — immediate operands (``lda g2`` @ ``0x012E2C``/``0x012E08``), **not** ``st`` sites",
            "0x028CCAF8": _scan_stores_to_vaddr(words, 0x028CCAF8),
            "0x028AF104": _scan_stores_to_vaddr(words, 0x028AF104),
            "0x028CCB08_block_plus_10": _scan_stores_to_vaddr(words, 0x028CCB08),
        },
        "gate_simulation": {"g0": gate.g0, "reason": gate.reason},
        "blocks": {"alpine": alpine, "desert": desert},
        "open_gaps": [
            "No static ROM patch of block word0 to ``0x028CCAF8`` — runtime or map alias OPEN",
            "Whether ``ld (r5)`` uses inline ``block+0xC`` link — byte1 ``0x7C`` == ``block+0x7C``; full ``0x22F77C00`` OPEN (see ``palette_block_stream_link_re``)",
            "``0x012DE4`` ``0x027260`` patches ``0x01000000`` descriptor chains only — not CGM block heads",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CGM block head RE (disasm + negative scan)")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_block_head_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    refs = report["rom_refs"]
    print(f"ROM word refs (lda operands, not st): desert={len(refs['0x028CCAF8'])}")
    print(f"Gate g0={report['gate_simulation']['g0']} ({report['gate_simulation']['reason']})")
    d = report["blocks"]["desert"]
    print(f"Desert +8 span={d['u16_at_08_span']} inner={d['u16_at_0a_inner']} link@+C={d['dword_at_0c_link']}")


if __name__ == "__main__":
    main()
