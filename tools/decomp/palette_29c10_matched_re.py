#!/usr/bin/env python3
"""Disasm trace: ``0x029C10`` FIFO consume on matched ``0x029EB0`` record tail.

Documents ``0x29FF8`` → ``0x029C10`` @ ``0x29CC4`` group-row walk and ``0x29CFC``
ADD path (not ``0x02A258`` XOR).  Correlates with desert ``g4=4`` init call.
No decode inference beyond disasm effects.

  python3 -m tools.decomp.palette_29c10_matched_re
  python3 -m tools.decomp.palette_29c10_matched_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

DISASM_29FF8_CALL = {
    "rom": "0x29FF8",
    "effect": "``call 0x029C10`` when ``(entry_g4 & 7) <= 3`` (@ ``0x29FE4`` ``cmpibl 3,g5`` — skip when 3 < g5)",
    "desert_init_regs": {
        "source": "0x012E3C call 0x029EB0",
        "entry_g4": 4,
        "entry_g4_and_7": 4,
        "29c10_at_record_tail": False,
        "note": "Desert ``g4=4`` → ``0x29FFC`` return without ``0x29C10`` — see ``palette_29fe4_g4_gate_re``",
    },
}

DISASM_29C10_FIFO = (
    {"rom": "0x29CBC", "effect": "``r4 = g2 + g3``; ``lda 0x20B950[r4*8],g4`` — 8-byte group row"},
    {"rom": "0x29CC4", "effect": "``g0 = ld 0x4(g4)`` — compile/stream record ptr (``st`` @ ``0x29F9C``)"},
    {"rom": "0x29CC8", "effect": "``ldos (g4),g4`` — row head u16 (``stos r10`` @ ``0x29F90``)"},
    {"rom": "0x29CD8", "effect": "``g13 |= g4`` — merge row head into running mask"},
    {"rom": "0x29CDC", "effect": "``g7 = lda 0x14(g0)`` — FIFO / parameter cursor pointer"},
    {"rom": "0x29CF8", "effect": "``ldos (g7),g4`` — **read FIFO u16**"},
    {"rom": "0x29CFC", "effect": "``addo g13,g4,g4`` — **ADD** mask into u16 (not ``xor``)"},
    {"rom": "0x29D00", "effect": "``stos g4,(g6)`` — write to ``0x01000000`` / ``0x01004000`` staging"},
    {"rom": "0x29D34", "effect": "``g0 = r4`` — return group index consumed"},
)

DISASM_29F7C_ROW_FILL = (
    {"rom": "0x29F90", "effect": "``stos r10,(g4)`` — row+0 u16 = ``0x20C950<<7`` before span add"},
    {"rom": "0x29F9C", "effect": "``st g0,0x4(g4)`` — row+4 u32 = ``fp+0x40`` block-head / record ptr"},
    {"rom": "0x29FA0", "effect": "``bal 0x02A0F8`` — reads record ``+0x14`` table; **returns** without ``bx`` to handler"},
)

OPEN_GAPS = (
    "Row ``+0x4`` record is ``fp+0x40`` dword (``0x204D4743`` static) — ``+0x14`` FIFO cursor validity OPEN",
    "``0x29CFC`` ADD path proven in disasm; ``xor_table`` Python replay **not** this insn sequence",
    "Mapping ``0x20C954`` index → slot 477 at ``0x29FF8`` requires full matched-stream walk (OPEN)",
    "``0x012E60`` upload sweeps use ``g2=0x20A79C`` (alpine saved ptr) — separate from per-record ``0x29FF8``",
    "Tier-B ``D`` merge via ``0x02A4E0`` / ``0x02A5A0`` not reached from ``0x29CFC`` ADD loop alone",
)


def build_report(*, slot: int = 477, raw_u16: int = 0x8843) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm only — no MAME, no xor_table inference",
        "call_29ff8": DISASM_29FF8_CALL,
        "disasm_29c10_fifo": list(DISASM_29C10_FIFO),
        "disasm_29f7c_row_fill": list(DISASM_29F7C_ROW_FILL),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "cgm_fifo_offset": "fifo+0x3a6 in marker-split replay (format-walk order, not ``0x29CC4`` index)",
        },
        "path_summary": (
            "Matched record end: ``0x29F7C`` rows → ``0x29FE4`` gate — desert ``g4=4`` **skips** "
            "``0x29FF8`` ``0x029C10`` (@ ``0x29FFC`` return). Post-init sweeps @ ``0x012E60`` "
            "cover slots ≤55 only."
        ),
        "open_gaps": list(OPEN_GAPS),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x029C10 matched-path FIFO RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29c10_matched_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    d = report["call_29ff8"]["desert_init_regs"]
    print(
        f"Desert 29FF8→29C10: entry g4={d['entry_g4']} "
        f"(g4&7={d['entry_g4_and_7']}) tail_call={d['29c10_at_record_tail']}"
    )
    print(f"FIFO consume: 0x29CF8 ldos → 0x29CFC addo g13 (not xor)")
    for g in OPEN_GAPS[:3]:
        print(f"  OPEN: {g}")


if __name__ == "__main__":
    main()
