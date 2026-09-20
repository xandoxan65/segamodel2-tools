#!/usr/bin/env python3
"""Disasm-only: workram slab ``0x005C8E60+`` bootstrap — negatives + ordering.

Traces why ``0x005C8E90`` format pointer and ``0x005C8964`` runner body are
zero in static ROM, documents ``0x012E18`` alpine-before-desert compile order,
``0x026E18`` counter seed (not arena fill), and embedded format ASCII @
``0x005CF10``.  No MAME captures.

  python3 -m tools.decomp.palette_workram_slab_bootstrap_re
  python3 -m tools.decomp.palette_workram_slab_bootstrap_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

SLAB_BASE = 0x005C8E60
SLAB_END = 0x005C9280 + 16
WORKRAM_BAND_LO = 0x005C5000
WORKRAM_BAND_HI = 0x005CFFFF

# ``0x012D90`` palette init compile order (@ ``0x012E18`` / ``0x012E3C``).
PALETTE_COMPILE_ORDER = (
    {
        "rom": "0x012E18",
        "block_vaddr": "0x028AF104",
        "course": "alpine",
        "effect": "``call 0x029EB0`` with ``g4=4``; return → ``0x20A79C`` (@ ``0x012E1C``)",
        "note": "Runs **before** desert compile — may side-effect workram slab if compile+run patches thunks",
    },
    {
        "rom": "0x012E3C",
        "block_vaddr": "0x028CCAF8",
        "course": "desert",
        "effect": "``call 0x029EB0`` with ``g4=4``; return → ``0x20A7B0`` (@ ``0x012E48``)",
        "note": "Tier-B slot 477 replay path: mismatch → ``0x05CEC0`` → ``0x029958``",
    },
    {
        "rom": "0x012E60",
        "effect": "Five ``call 0x029C10`` upload sweeps with ``g2=0x20A79C`` (alpine return only)",
        "note": "Max ``g0=45`` — static sweeps do **not** cover slot 477",
    },
)

# ``0x026E18`` — called @ ``0x02A024`` **before** ``lda 0x005C8E90`` on mismatch path.
COUNTER_SEED_26E18 = (
    {"rom": "0x26E20", "insn": "``st g0,0x20B1A4``"},
    {"rom": "0x26E28", "insn": "``st g0,0x20B1A8`` (width counter seed from caller ``g0=1``)"},
    {"rom": "0x26E30", "insn": "``st g1,0x20B1AC`` (slot counter seed from caller ``g1=1``)"},
    {"rom": "0x26E38", "insn": "``bx (g2)`` — return stub from caller frame"},
    {"verdict": "Does **not** touch ``0x005C8Exx`` — counter seed only"},
)

# Embedded format tables inside ``0x05CF50`` (not reached via ROM word xref).
EMBEDDED_FORMAT_ROM = (
    {
        "rom": "0x005CF10",
        "bytes_ascii": "0123456789",
        "role": "Format-scan digit row embedded in ``0x05CF50`` handler table region",
    },
    {
        "rom": "0x005CF30",
        "bytes_ascii": "0123456789ABCDEF",
        "role": "Extended hex row in same table blob",
    },
    {
        "note": (
            "``0x05CF74`` ``ldob (r12),g0`` uses **pointer** loaded from ``0x005C8E90``; "
            "these ROM strings are not statically referenced — runtime must install pointer"
        ),
    },
)

# ``0x05DAA0`` — overlap memmove (@ ``0x02682C``, ``0x05DA38``).
DAA0_MEMMOVE = (
    {"rom": "0x05DAA0", "role": "Overlapping-range ``memmove`` (``g0``=dest, ``g1``=src, ``g2``=len)"},
    {
        "rom": "0x026820",
        "effect": "``g0=*(node+0)``; ``r5=*(node+4)``; ``g1=*r5``; ``g2=*(node+8)`` → ``call 0x05DAA0``",
    },
    {
        "rom": "0x026860",
        "effect": "Opcode index → ``0x20B600[g4*4]`` record ← handler ptr; ``+8`` ← ``g2``",
    },
    {"verdict": "Clones into ``0x20B1C0`` handler pool — **not** direct writer to ``0x005C8E60`` slab"},
)

# ``0x02A6D0`` wrapper → ``0x02A5A0`` upload (merge when ``r5`` bit 0 set @ ``0x02A61C``).
WRAPPER_2A6D0 = (
    {"rom": "0x02A6D0", "insn": "Save ``g0..g4`` → ``r7,r8,r5,r4,r6``"},
    {"rom": "0x02A6E4", "insn": "``g2=r7`` — first ``call 0x02A5A0`` pass"},
    {"rom": "0x02A5B4", "insn": "``g0→r10``, ``g1→r9``, ``g2→r8``, ``g4→r14``, ``g5→r5``"},
    {
        "rom": "0x02A620",
        "insn": (
            "If ``r5`` bit 0: ``g0=r10``, ``g1=r9``, ``g2=r14`` → ``call 0x02A4E0`` merge "
            "(``g2`` = entry ``g4`` from wrapper arg)"
        ),
    },
    {
        "rom": "0x02A2E0",
        "insn": (
            "Fill ``0x20C95C``–``0x20C968`` from wrapper ``g0..g3`` "
            "(``g0/g1`` → ``<<3`` when ≤46; else defaults ``0x1EF``/``0x17F``)"
        ),
    },
    {"open": "Caller of ``0x02A6D0`` from ``0x005C8964`` patched body — not traced for slot 477"},
)


def _scan_rom_stores(lo: int, hi: int) -> list[dict[str, str]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    hits: list[dict[str, str]] = []
    for i, w in enumerate(words):
        rom = i * 4
        if rom > 0x700000:
            break
        hi_byte = (w >> 24) & 0xFF
        if hi_byte in (0x92, 0xB2, 0x9A, 0x8A, 0x82, 0x98):
            imm = w & 0xFFFFFF
            if lo <= imm <= hi:
                hits.append({"rom": f"0x{rom:08X}", "word": f"0x{w:08X}", "imm": f"0x{imm:08X}"})
    return hits


def _slab_ldas_only() -> list[dict[str, Any]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    cells = (
        0x005C8E60,
        0x005C8E70,
        0x005C8E90,
        0x005C8BF0,
        0x005C8D40,
        0x005C8964,
        0x005C9118,
        0x005C9280,
    )
    rows: list[dict[str, Any]] = []
    for addr in cells:
        refs = find_word_refs(words, addr)
        rows.append(
            {
                "vaddr": f"0x{addr:08X}",
                "offset_from_slab": addr - SLAB_BASE,
                "rom_lda_count": len(refs),
                "rom_ldas": [f"0x{r:08X}" for r in refs],
            }
        )
    return rows


def _handler_table_scan() -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    stores: list[dict[str, str]] = []
    for i, w in enumerate(words):
        rom = i * 4
        if rom > 0x700000:
            break
        hi = (w >> 24) & 0xFF
        if hi in (0x92, 0xB2, 0x9A, 0x8A, 0x82, 0x98):
            imm = w & 0xFFFFFF
            if 0x0020B100 <= imm <= 0x0020BFFF:
                stores.append({"rom": f"0x{rom:08X}", "imm": f"0x{imm:08X}"})
    refs_20b1c0 = find_word_refs(words, 0x0020B1C0)
    return {
        "rom_stores_20b100_20bfff": {"count": len(stores), "hits": stores},
        "20b1c0_lda_sites": [f"0x{r:08X}" for r in refs_20b1c0],
        "verdict": (
            "``0x20B1C0[g4*4]`` (@ ``0x026F44``) is **read-only** in ROM — "
            "``0x20B1C0[0x20]`` contents have no static ``st`` sites"
        ),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    band_stores = _scan_rom_stores(WORKRAM_BAND_LO, WORKRAM_BAND_HI)
    slab_stores = _scan_rom_stores(SLAB_BASE, SLAB_END)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM store scan — no MAME, no XOR inference",
        "slot_focus": slot,
        "summary": (
            "No ROM ``st``/``stq`` with immediate in slab ``0x005C8E60``–``0x005C9290``. "
            "``0x026E18`` seeds ``0x20B1A8``/``AC`` only. ``0x05DAA0`` clones handler pool "
            "from ``0x20B600`` — not slab bootstrap. Format pointer @ ``0x005C8E90`` and "
            "``0x005C8964`` runner remain runtime-only."
        ),
        "slab": {
            "base": f"0x{SLAB_BASE:08X}",
            "end": f"0x{SLAB_END:08X}",
            "cells": _slab_ldas_only(),
        },
        "rom_store_scan": {
            "band_5c5000_5cffff": {"count": len(band_stores), "hits": band_stores},
            "slab_only": {"count": len(slab_stores), "hits": slab_stores},
        },
        "palette_compile_order": list(PALETTE_COMPILE_ORDER),
        "counter_seed_26e18": list(COUNTER_SEED_26E18),
        "embedded_format_rom": list(EMBEDDED_FORMAT_ROM),
        "daa0_memmove": list(DAA0_MEMMOVE),
        "wrapper_2a6d0_merge": list(WRAPPER_2A6D0),
        "negative_paths": [
            {"id": "013238", "dest": "0x0100808x", "slab": False},
            {"id": "026760", "dest": "0x01800000", "slab": False},
            {"id": "0330A0", "dest": "0x0181xxxx TGP banks", "slab": False},
            {"id": "026A10", "dest": "0x0100xxxx descriptor buses", "slab": False},
            {"id": "26800", "dest": "0x20B1C0 handler pool via 0x05DAA0", "slab": False},
            {
                "id": "26700_26980_unreachable",
                "note": (
                    "**Zero** static ``call 0x026700`` / ``call 0x026980``; ``0x20B910`` "
                    "written only @ ``0x026704`` (``g14=0``). Handler clone chain not on "
                    "``0x012D90`` desert static path"
                ),
            },
        ],
        "handler_table_scan": _handler_table_scan(),
        "open_gaps": [
            "Runtime installer for ``0x005C8E90`` format pointer (must be non-zero before ``0x05CF74``)",
            "``0x005C8E60`` compare template bytes (zero → perpetual ``0x05CE18`` mismatch)",
            "``0x005C8964`` patched runner — link to ``0x02A6D0`` with ``r5`` bit 0 for merge",
            "``0x20B1C0[0x20]`` record after ``0x26800`` clone (no static ROM image @ ``0x20B600``)",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slot", type=int, default=477)
    ap.add_argument(
        "-o",
        "--output",
        default=REPO_ROOT / "out/decomp/palette_workram_slab_bootstrap_re.json",
        type=Path,
    )
    args = ap.parse_args()
    report = build_report(slot=args.slot)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Slab store hits: {report['rom_store_scan']['slab_only']['count']}")
    print(f"Band 0x5C5000 store hits: {report['rom_store_scan']['band_5c5000_5cffff']['count']}")


if __name__ == "__main__":
    main()
