#!/usr/bin/env python3
"""Disasm trace: pre-compile staging bootstrap @ ``0x012D90`` / ``0x027260``.

Documents ROM-visible setup of the ``0x01000000`` descriptor bus and related
regions before ``0x029EB0`` compile.  Does **not** execute workram thunks or
infer XOR decode.

  python3 -m tools.decomp.palette_staging_bootstrap_re
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

STAGING_BASE = 0x01000000
SCRATCH_BUS = 0x01008000  # merge/XOR tables (@ ``0x02A380``, ``0x29C9C``)
AUX_BUS = 0x0100A000  # ``0x26980`` copy target (when invoked)
PALRAM_STAGING = 0x01080000  # packed nibble bus (@ ``0x02A458``)

# --- ``0x027260`` (@ ``0x012DE4``, ``0x012DF8``) --------------------------------

DISASM_27260 = (
    {"rom": "0x027260", "insn": "``shlo 7,g1,g1`` — tag base = ``g1 << 7``"},
    {
        "rom": "0x02726C",
        "insn": "``lda 0x01000000(g1)[g0*2],g6`` — chain row head (byte offset ``g1 + 2*g0``)",
    },
    {
        "rom": "0x02728C",
        "insn": "``stos g14,(g5)`` × ``g2`` — write ``g14`` halfwords stepping +2",
    },
    {
        "rom": "0x0272A4",
        "insn": "``lda 0x80(g6),g6`` — next row (+0x80 bytes); outer ``g3`` iterations",
    },
)

# --- ``0x012D90`` palette init (course load) ------------------------------------

PALETTE_INIT_12D90 = (
    {
        "rom": "0x012DB0",
        "effect": "``stos g6,0x20B914`` with ``g6 = 0xC000`` (setbit 15+14) — seeds u16 stream head",
    },
    {
        "rom": "0x012DBC",
        "effect": "``stos g6,0x20B91C`` — second flag word (same ``0xC000`` pattern)",
    },
    {"rom": "0x012DD0", "effect": "``call 0x026B60`` on ``0x01002000`` — zero 511×16-byte qword rows"},
    {
        "rom": "0x012DE4",
        "effect": "``call 0x027260`` (g0=15, g1=30, g2=35, g3=6) — first descriptor chain patch",
        "callsite_g14": "``g14`` at callsite (typically 0) — value written by ``stos``",
    },
    {
        "rom": "0x012DF8",
        "effect": "``call 0x027260`` (g0=7, g1=29, g2=55, g3=21) — second chain patch",
    },
    {
        "rom": "0x012DFC",
        "effect": "``bal 0x013238`` — mirror ``0x20A790`` course id into ``0x0100808E`` / ``0x010080EE``",
    },
)

# --- ``0x026A10`` / ``0x026B60`` (cold boot bus init — not in ``0x012D90`` path) -

DISASM_26A10_BUSES = (
    {"base": "0x01000000", "rom": "0x026A58", "via": "``call 0x026B60`` — primary D/U staging"},
    {"base": "0x01002000", "rom": "0x026A64", "via": "``call 0x026B60``"},
    {"base": "0x01004000", "rom": "0x026A74", "via": "``call 0x026B60`` — XOR batch bus (@ ``0x02A20C``)"},
    {"base": "0x01006000", "rom": "0x026A84", "via": "``call 0x026B60``"},
    {"base": "0x0100C000", "rom": "0x026A90", "via": "``stq 0`` × 0xBF rows — 16-byte stride"},
    {"base": "0x0100D000", "rom": "0x026AB4", "via": "``stq 0`` × 0xBF rows"},
    {"base": "0x01008000", "rom": "0x026AD4", "via": "``stq 0`` × 47 rows — merge coefficient bus"},
    {"base": "0x01008400", "rom": "0x026AF4", "via": "``stq 0`` × 47 rows"},
    {"base": "0x01008800", "rom": "0x026B14", "via": "``stq 0`` × 47 rows"},
    {"base": "0x01008C00", "rom": "0x026B34", "via": "``stq 0`` × 47 rows"},
)

DISASM_26B60 = {
    "rom": "0x026B60",
    "effect": (
        "Zero-fill: ``stq r4,(g0)`` × 0x1FF rows, ``g0 += 0x10`` — 511 qwords per region"
    ),
}

# --- ``0x026980`` handler bootstrap (not statically called from ``0x012D90``) ----

DISASM_26980 = (
    {
        "rom": "0x026980",
        "effect": (
            "Walk u16 list @ ``0x20B914`` (linked via ``lda 0x1(g5),g5``); "
            "``stos`` into ``0x0100A000`` (≤7 halfwords)"
        ),
    },
    {"rom": "0x0269B0", "effect": "``call 0x026800`` — clone ``0x20B600`` template list via ``0x05DAA0``"},
    {"rom": "0x0269B8", "effect": "``callx (0x20B910)`` — indirect; only ``st`` site zeros @ ``0x026704``"},
    {
        "rom": "note",
        "effect": (
            "**No static ``call 0x026980``** in ROM — reachable only if ``0x20B910`` "
            "patched at runtime (cold boot @ ``0x026700`` leaves it zero)"
        ),
    },
)

DISASM_26800 = (
    {"rom": "0x026800", "effect": "Walk ``0x20B600`` nodes; ``call 0x05DAA0`` memcpy per template"},
    {"rom": "0x026860", "effect": "Opcode index → ``0x20B600[g5*4]`` record ← handler pointer"},
)


@dataclass(frozen=True)
class ChainPatch:
    callsite: str
    g0: int
    g1: int
    g2: int
    g3: int
    row0_head: int
    row_stride: int = 0x80
    total_halfwords: int = 0

    @staticmethod
    def from_args(*, callsite: str, g0: int, g1: int, g2: int, g3: int) -> ChainPatch:
        head = STAGING_BASE + (g1 << 7) + (g0 * 2)
        return ChainPatch(
            callsite=callsite,
            g0=g0,
            g1=g1,
            g2=g2,
            g3=g3,
            row0_head=head,
            total_halfwords=g2 * g3,
        )

    def to_dict(self, *, fill_value: int = 0) -> dict[str, Any]:
        rows = []
        for row in range(self.g3):
            base = self.row0_head + row * self.row_stride
            rows.append(
                {
                    "row": row,
                    "head": f"0x{base:08X}",
                    "halfwords": self.g2,
                    "span_bytes": self.g2 * 2,
                    "end_exclusive": f"0x{base + self.g2 * 2:08X}",
                }
            )
        return {
            "callsite": self.callsite,
            "args": {"g0": self.g0, "g1": self.g1, "g2": self.g2, "g3": self.g3},
            "tag_base_shl7": f"0x{self.g1 << 7:X}",
            "row0_head": f"0x{self.row0_head:08X}",
            "row_stride": f"0x{self.row_stride:X}",
            "total_halfwords": self.total_halfwords,
            "total_bytes": self.total_halfwords * 2,
            "fill_note": f"``stos g14,(g5)`` — g14 at callsite (init path typically 0x{fill_value:04X})",
            "rows": rows,
        }


# Immediate operands decoded from ``maincpu_012d00_200.asm``.
PATCH_CALLS_12D = (
    ChainPatch.from_args(callsite="0x012DE4", g0=15, g1=30, g2=35, g3=6),
    ChainPatch.from_args(callsite="0x012DF8", g0=7, g1=29, g2=55, g3=21),
)


def build_report() -> dict[str, Any]:
    patches = [p.to_dict() for p in PATCH_CALLS_12D]
    overlap = _check_row_overlap(PATCH_CALLS_12D)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm immediates + address arithmetic (no MAME)",
        "summary": (
            "Before desert ``0x029EB0`` compile: ``0x012DE4``/``0x012DF8`` patch linked "
            "halfword chains on ``0x01000000`` bus via ``0x027260``; ``0x012DB0`` seeds "
            "``0x20B914`` with ``0xC000``; ``0x013238`` mirrors course id into "
            "``0x0100808E`` merge bus. Handler clone ``0x026980`` is **not** in this static chain."
        ),
        "staging_buses": {
            "primary_d_u": f"0x{STAGING_BASE:08X}",
            "merge_coeff": f"0x{SCRATCH_BUS:08X}",
            "aux_hash": f"0x{AUX_BUS:08X}",
            "palram_pack": f"0x{PALRAM_STAGING:08X}",
        },
        "disasm_27260": list(DISASM_27260),
        "palette_init_12d90": list(PALETTE_INIT_12D90),
        "patch_calls_12d": patches,
        "patch_overlap_check": overlap,
        "patch_overlap_note": (
            "Second ``0x027260`` call (@ ``0x012DF8``, tag ``g1=29``) row heads extend into "
            "address range of first call (@ ``0x012DE4``, ``g1=30``) — overlapping tag "
            "rows on ``0x01000000`` bus (may be intentional layered chains)"
        ),
        "disasm_26a10_buses": list(DISASM_26A10_BUSES),
        "disasm_26b60": DISASM_26B60,
        "disasm_26980": list(DISASM_26980),
        "disasm_26800": list(DISASM_26800),
        "compile_consumer": {
            "rom": "0x05CF94",
            "effect": (
                "During ``0x05CF50`` compile: ``bal 0x027008`` emits halfwords into "
                "``0x01000000[g5*2]`` — same bus patched by ``0x027260``"
            ),
        },
        "downstream": (
            "After patches: ``0x012E18``/``0x012E3C`` ``0x029EB0`` → ``0x05CEC0`` → "
            "``0x029958`` (@ ``0x005C8964``). See ``palette_29958_post_compile_re``."
        ),
        "open": [
            "``g14`` value at ``0x012DE4``/``0x012DF8`` (zero-fill vs stub pointer) — "
            "depends on caller frame; static init path uses cleared ``g14``",
            "``0x026980`` / ``0x20B910`` indirect entry — no ROM caller sets ``0x20B910`` nonzero",
            "``0x05DAA0`` memcpy body not disassembled in repo slice",
            "Whether ``0x0100A000`` aux table is required for desert tier-B slot 477",
        ],
    }


def _check_row_overlap(patches: tuple[ChainPatch, ...]) -> dict[str, Any]:
    ranges: list[tuple[int, int, str]] = []
    for p in patches:
        for row in range(p.g3):
            start = p.row0_head + row * p.row_stride
            end = start + p.g2 * 2
            ranges.append((start, end, f"{p.callsite} row{row}"))
    overlaps = []
    for i, (a0, a1, la) in enumerate(ranges):
        for b0, b1, lb in ranges[i + 1 :]:
            if a0 < b1 and b0 < a1:
                overlaps.append({"a": la, "b": lb, "lo": f"0x{max(a0, b0):08X}", "hi": f"0x{min(a1, b1):08X}"})
    return {"disjoint": len(overlaps) == 0, "overlaps": overlaps}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Pre-compile staging bootstrap (disasm)")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_staging_bootstrap_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    for p in report["patch_calls_12d"]:
        print(
            f"  {p['callsite']}: row0={p['row0_head']} "
            f"{p['total_halfwords']} halfwords ({p['total_bytes']} B) in {p['args']['g3']} rows"
        )
    ov = report["patch_overlap_check"]
    print(f"  Patch regions disjoint: {ov['disjoint']} ({len(ov['overlaps'])} overlaps)")


if __name__ == "__main__":
    main()
