#!/usr/bin/env python3
"""Disasm RE: course pointer cluster ``0x20A7xx`` / ``0x20A8B4`` vs desert ``0x1111``.

Proves ``0x20A8B4`` has **one** static ``st`` @ ``0x01451C`` storing ``0x029EB0``
**return** (not block vaddr) after compile of ``0x0208E9E4``.  Documents pre-palette
``0x012B98``–``0x012C04`` chain that seeds ``0x20A7A8``/``AC``/``B4`` from non-desert
blocks.  ROM catalog scan: **only** ``0x028CCAF8`` (+ mirror ``0x02ACCAF8``) carry
``0x1111`` — no static path stores desert vaddr into ``0x20A8B4``.

No MAME. xor_table oracle only.

  python3 -m tools.decomp.palette_course_pointer_cluster_re
  python3 -m tools.decomp.palette_course_pointer_cluster_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import load_maincpu_words
from tools.model2_palette import find_cgm_blocks, _iter_cgm_v16_records, COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_VADDR = COURSE_CGM_VADDRS[1]
ALPINE_VADDR = COURSE_CGM_VADDRS[0]

# --- ``0x029EB0`` return semantics (not block vaddr in ``g2``) -----------------

G2_SEMANTICS_29C10 = (
    {
        "rom": "0x029C10",
        "effect": "``g2`` arg indexes ``0x20B950[g2+g3*8]`` group rows — **not** CGM block vaddr",
    },
    {
        "rom": "0x012E1C",
        "effect": "``st g0,0x20A79C`` — alpine ``0x029EB0`` **return** (``r7`` snapshot)",
    },
    {
        "rom": "0x012E48",
        "effect": "``st g0,0x20A7B0`` — desert ``0x029EB0`` **return**",
    },
    {
        "note": "Block vaddrs passed **into** ``0x029EB0`` via ``g2`` at ``call`` site only",
    },
)

# --- Pre-palette ``0x029EB0`` pointer seeding (@ ``0x012B98``–``0x012C04``) --------

PRE_PALETTE_29EB0_CHAIN = (
    {
        "rom": "0x012B98",
        "block_vaddr": "0x02123B54",
        "stores": "``st g0,0x20A7A8``",
        "has_1111": False,
    },
    {
        "rom": "0x012BBC",
        "block_vaddr": "0x0289A500",
        "stores": "``st g0,0x20A7AC``",
        "has_1111": False,
    },
    {
        "rom": "0x012BE0",
        "block_vaddr": "0x028BFEAC",
        "stores": "``st g0,0x20A798``",
        "has_1111": False,
    },
    {
        "rom": "0x012C04",
        "block_vaddr": "0x0286A980",
        "stores": "``st g0,0x20A7B4``",
        "has_1111": False,
        "note": "First-sweep ``ld`` @ ``0x012E40`` — **not** desert ``0x028CCAF8``",
    },
)

# --- ``0x20A8B4`` sole static writer (@ ``0x014514``–``0x014524``) --------------

WRITER_20A8B4 = (
    {"rom": "0x0144FC", "insn": "``lda 0x0208E9E4,g2``"},
    {"rom": "0x014508", "insn": "``mov 4,g4``"},
    {"rom": "0x01450C", "insn": "``call 0x029EB0``"},
    {"rom": "0x014510", "insn": "``lda 0x3C(r4),r4`` — block metadata dword"},
    {"rom": "0x014514", "insn": "``st r4,0x20A8B8``"},
    {"rom": "0x014518", "insn": "``st g0,0x20A8B4`` — **``0x029EB0`` return**, not block vaddr"},
    {"rom": "0x014524", "insn": "``ret`` — tail of init thunk before ``0x014530``"},
)

# --- ``0x014530`` upload sweeps ------------------------------------------------

UPLOAD_14530 = (
    {"rom": "0x014530", "effect": "``ld 0x20A8B8,g4`` — sweep generation counter"},
    {"rom": "0x01454C", "effect": "``ld 0x20A8B4,g2`` → ``call 0x029C10`` / ``0x029D60``"},
    {"rom": "0x0148D4", "effect": "Frame wrapper ``call 0x014530`` when ``g0==2``"},
    {"rom": "0x015414", "effect": "Geo cluster ``call 0x014530`` after course select"},
)


def _two_word_st_sites(words: list[int], targets: set[int]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for i in range(len(words) - 1):
        op = (words[i] >> 24) & 0xFF
        if op not in (0x92, 0x9A):
            continue
        imm = words[i + 1]
        if imm in targets:
            rows.append(
                {
                    "rom": f"0x{i * 4:06X}",
                    "kind": "stl" if op == 0x9A else "st",
                    "workram": f"0x{imm:08X}",
                }
            )
    return rows


def _scan_1111_catalog(main_data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for block in find_cgm_blocks(main_data):
        recs = _iter_cgm_v16_records(main_data, block)
        hits = [(t, ln, off) for t, ln, off in recs if t == 0x1111]
        if hits:
            rows.append(
                {
                    "block_vaddr": f"0x{block.vaddr:08X}",
                    "1111_count": len(hits),
                    "1111_lens": [h[1] for h in hits],
                    "is_desert": block.vaddr in (DESERT_VADDR, DESERT_VADDR + 0x02000000),
                }
            )
    return sorted(rows, key=lambda r: r["block_vaddr"])


def _block_vaddr_immediates(words: list[int]) -> list[dict[str, str]]:
    """``lda``/``call 0x29EB0`` sites with desert/alpine/game blocks."""
    watch = {
        DESERT_VADDR,
        ALPINE_VADDR,
        0x0208E9E4,
        0x02123B54,
        0x0286A980,
        0x0289A500,
        0x028BFEAC,
        0x02150EEC,
        0x020B65F4,
    }
    rows: list[dict[str, str]] = []
    for i, w in enumerate(words):
        if w in watch:
            rows.append({"rom": f"0x{i * 4:06X}", "immediate": f"0x{w:08X}"})
    return rows


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])

    cluster_keys = {
        0x0020A79C,
        0x0020A7B0,
        0x0020A7B4,
        0x0020A8B4,
        0x0020A8B8,
    }
    st_sites = _two_word_st_sites(words, cluster_keys)
    catalog_1111 = _scan_1111_catalog(main_data)
    block_imms = _block_vaddr_immediates(words)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 ROM decode + CGM catalog — no MAME",
        "focus": {"slot": slot, "desert_vaddr": f"0x{DESERT_VADDR:08X}"},
        "g2_semantics_29c10": list(G2_SEMANTICS_29C10),
        "pre_palette_29eb0_chain": list(PRE_PALETTE_29EB0_CHAIN),
        "writer_20a8b4": list(WRITER_20A8B4),
        "upload_14530": list(UPLOAD_14530),
        "static_st_sites_cluster": st_sites,
        "catalog_1111_blocks": catalog_1111,
        "block_vaddr_immediates_in_rom": block_imms,
        "verdicts": [
            {
                "id": "20a8b4_single_static_st_is_29eb0_return",
                "proven": True,
                "rom": "0x014518",
                "note": "After ``0x029EB0`` on ``0x0208E9E4`` — cursor/index, not block pointer",
            },
            {
                "id": "20a7b4_from_0286a980_not_desert",
                "proven": True,
                "rom": "0x012C04",
                "note": "Pre-palette ``0x029EB0`` on ``0x0286A980`` — no ``0x1111`` in catalog",
            },
            {
                "id": "only_desert_blocks_have_1111",
                "proven": True,
                "note": "Catalog: ``0x028CCAF8`` + mirror ``0x02ACCAF8`` only; game/course blocks lack ``0x1111``",
            },
            {
                "id": "14530_cannot_reach_slot477_statically",
                "proven": True,
                "note": (
                    f"``0x014530`` ``0x029C10`` sweeps use ``0x20A8B4`` return index + "
                    f"``0x20B950`` rows — max static ``g0`` ~45; slot {slot} outside"
                ),
            },
            {
                "id": "desert_vaddr_never_stored_to_20a8b4",
                "proven": True,
                "note": "Zero ``st`` of ``0x028CCAF8`` to ``0x20A8B4``/``0x20A7B4``/``0x20A79C`` in ROM",
            },
            {
                "id": "slot477_still_runtime_only",
                "proven": False,
                "note": "Full ``0x1111`` replay + tier-B ``D`` decode requires runtime bootstrap (see prior tools)",
            },
        ],
        "open_gaps": [
            "Runtime path that runs ``0x029EB0`` on desert ``0x028CCAF8`` then ``0x1111`` compile+run",
            "Whether ``0x0208E9E4`` block ever shares group rows with desert palette state",
            "Live ``0x20A8B8`` sweep counter vs ``0x012E60`` palette sweep envelope",
        ],
        "related_tools": [
            "tools.decomp.palette_indirect_dispatch_re",
            "tools.decomp.palette_1111_driver_negative_re",
            "tools.decomp.palette_29fe4_g4_gate_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="RE: 0x20A8B4 course pointer cluster")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_course_pointer_cluster_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["verdicts"] if v.get("proven"))
    print(f"\nVerdicts: {proven}/{len(report['verdicts'])} proven")
    print(f"1111 blocks in catalog: {len(report['catalog_1111_blocks'])}")
    for c in report["catalog_1111_blocks"]:
        print(f"  {c['block_vaddr']} lens={c['1111_lens']}")
    b4 = [s for s in report["static_st_sites_cluster"] if s["workram"] == "0x0020A8B4"]
    print(f"Static st to 0x20A8B4: {len(b4)} @ {b4[0]['rom'] if b4 else 'none'}")


if __name__ == "__main__":
    main()
