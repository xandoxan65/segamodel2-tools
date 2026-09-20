#!/usr/bin/env python3
"""Disasm RE: ``0x29FE4`` ``g4 & 7`` gate skips ``0x29C10`` for desert ``g4=4``.

Proves matched ``0x029EB0`` record tail @ ``0x29FD0`` **does not** ``call 0x029C10``
when entry ``g4=4`` (@ ``0x012E3C``).  Documents post-init ``0x012E60``–``0x012ED4``
upload sweeps (``g4=2`` → ``0x29C74`` ADD path, slots ≤55).  Contrasts with
``0x1111`` replay slot 477 — outside all static disasm upload windows.

No MAME.  No XOR inference.

  python3 -m tools.decomp.palette_29fe4_g4_gate_re
  python3 -m tools.decomp.palette_29fe4_g4_gate_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- ``0x29FE4`` tail gate (@ ``maincpu_029eb0_600.asm``) -------------------

TAIL_GATE_29FE4 = (
    {"rom": "0x29FD0", "effect": "Patch ``0x20B950[r7*8]`` row (@ ``r7`` snapshot @ ``0x29F44``)"},
    {"rom": "0x29FDC", "effect": "``g5 = r11 & 7`` — entry ``g4`` low bits"},
    {
        "rom": "0x29FE4",
        "insn": "``cmpibl 3,g5,0x29FFC``",
        "semantics": "Branch to ``0x29FFC`` (**skip** ``0x29C10``) when **3 < (g4 & 7)**",
    },
    {
        "rom": "0x29FF8",
        "effect": "``call 0x029C10`` — only when ``(g4 & 7) <= 3``",
        "args": "``g2=r7`` (``0x29F44`` snapshot, 0 on first node); ``g3=r14``; ``g4=r11``",
    },
    {"rom": "0x29FFC", "effect": "``g0=r7``; ``ret`` @ ``0x02A000`` — desert ``g4=4`` lands here"},
)

G4_TAIL_MATRIX = tuple(
    {
        "entry_g4": v,
        "g4_and_7": v & 7,
        "cmpibl_3_lt_g5": 3 < (v & 7),
        "calls_29c10_at_29ff8": (v & 7) <= 3,
    }
    for v in range(9)
)

# --- ``0x012E60`` post-init ``0x029C10`` sweeps (@ ``maincpu_012d00_200.asm``) ---

INIT_29EB0 = (
    {"rom": "0x012E18", "effect": "Alpine ``0x029EB0`` → ``st g0,0x20A79C``"},
    {"rom": "0x012E3C", "effect": "Desert ``0x029EB0`` ``g4=4`` → matched path → **no** ``0x29C10`` tail"},
    {"rom": "0x012E40", "effect": "``ld 0x20A7B4,g2`` — overwrites ``g2`` before first sweep"},
    {"rom": "0x012E48", "effect": "``st g0,0x20A7B0`` — desert return (zero static ``ld`` consumers)"},
)

UPLOAD_SWEEPS = (
    {
        "rom": "0x012E60",
        "g0": 20,
        "g1": 3,
        "g3": 0,
        "g4": 2,
        "g2_source": "``0x20A7B4`` (not ``0x20A79C``)",
        "slot_range": "20–22",
        "29c30_path": "``g4&7=2`` → ``cmpibge 3,2`` → ``0x29C74`` ADD upload",
    },
    {
        "rom": "0x012E7C",
        "g0": 7,
        "g1": 11,
        "g3": 8,
        "g4": 2,
        "g2_source": "``0x20A79C``",
        "slot_range": "7–17",
        "29c30_path": "``0x29C74`` ADD",
    },
    {
        "rom": "0x012E98",
        "g0": 17,
        "g1": 11,
        "g3": 7,
        "g4": 2,
        "g2_source": "``0x20A79C``",
        "slot_range": "17–27",
        "29c30_path": "``0x29C74`` ADD",
    },
    {
        "rom": "0x012EB4",
        "g0": 29,
        "g1": 11,
        "g3": 6,
        "g4": 2,
        "g2_source": "``0x20A79C``",
        "slot_range": "29–39",
        "29c30_path": "``0x29C74`` ADD",
    },
    {
        "rom": "0x012ED4",
        "g0": 45,
        "g1": 11,
        "g3": 4,
        "g4": 2,
        "g2_source": "``0x20A79C``",
        "slot_range": "45–55",
        "29c30_path": "``0x29C74`` ADD",
    },
)

# --- ``0x29C10`` routing (@ ``maincpu_029c10_300.asm``) ----------------------

ROUTING_29C10 = (
    {"rom": "0x29C10", "test": "``cmpi g2,0``", "branch": "``bl 0x29C34`` compile+run when ``g2 < 0``"},
    {"rom": "0x29C30", "test": "``cmpibge 3,(g4&7),0x29C74``", "branch": "Upload when **3 >= (g4&7)**"},
    {"rom": "0x29C34", "branch": "Compile+run → ``0x05CEC0`` @ ``0x005C8BF0`` → ``0x029958``"},
    {"rom": "0x29C74", "branch": "FIFO ``ldos`` + ``addo g13`` @ ``0x29CFC`` (tier-A ADD)"},
)

# --- Static ``0x1111`` body driver (negative) ---------------------------------

NEGATIVE_1111_DRIVER = (
    "Zero maincpu ``call``/``bal`` sites pass desert ``0x1111`` payload address as format string",
    "``0x029EB0`` matched path reads ``block+0x08`` node only — does not walk ``0x1111`` record @ ``+0x2C``",
    "``0x005C8964`` runner formats are ``%-11s:%-8d`` / ``CgmPut ERROR`` — not marker-split ``0x1111`` body",
    "``0x012E3C`` desert ``g4=4`` → ``0x29FFC`` without ``0x29C10`` — prefix group rows only via ``0x29F7C``",
    "Slot 477 tier-B ``D`` decode has **no** static disasm consumer on desert init path",
)


def build_report(*, slot: int = 477) -> dict[str, Any]:
    max_sweep_end = 55
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm only — no MAME, no xor_table proof",
        "focus": {"slot": slot, "desert_entry_g4": 4},
        "tail_gate_29fe4": list(TAIL_GATE_29FE4),
        "g4_tail_matrix": list(G4_TAIL_MATRIX),
        "desert_012e3c_verdict": {
            "entry_g4": 4,
            "g4_and_7": 4,
            "calls_29c10_at_29ff8": False,
            "return_g0": "``r7`` snapshot (=0 first node) via ``0x29FFC``",
            "inner_29f7c_iters": "Up to 512× ``bal 0x02A0F8`` — fills ``0x20B950`` rows, no FIFO ``ldos``",
            "20c950_after_span": 30,
        },
        "init_29eb0": list(INIT_29EB0),
        "upload_sweeps_29c10": list(UPLOAD_SWEEPS),
        "max_static_sweep_slot": max_sweep_end,
        "slot_in_sweep_windows": slot <= max_sweep_end,
        "routing_29c10": list(ROUTING_29C10),
        "negative_1111_driver": list(NEGATIVE_1111_DRIVER),
        "replay_contrast": {
            "replay_slot": slot,
            "replay_fifo_8843": "0x3A6",
            "replay_path": "Marker-split ``0x1111`` format walk + ``decode_d_u16`` (Python oracle)",
            "hardware_equivalent": "OPEN — no static ``0x029958`` / ``0x1111`` body link on desert ``0x012E3C`` path",
        },
        "conclusions": (
            "``0x29FE4`` ``cmpibl 3,g5``: desert ``g4=4`` → **skip** ``0x29FF8`` ``call 0x029C10`` entirely.",
            "Prior notes claiming ``0x29FF8`` tier-A ADD for desert ``g4=4`` were **incorrect**.",
            "Post-init ``0x012E60`` sweeps cover slots 7–55 via ``g4=2`` ``0x29C74`` ADD — not slot 477.",
            "``0x29F7C`` inner loop (512×) sets up group rows only; ``0x02A0F8`` returns without handler ``bx``.",
            f"Slot {slot} / ``0x8843`` / oracle ``0x6683`` require non-static driver (``0x1111`` replay OPEN in disasm).",
        ),
        "open_gaps": (
            "Runtime trigger for ``0x1111`` payload (``0x029958`` / repeated ``0x029EB0`` / other course hook)",
            "``block+0 = block_vaddr`` self-pointer fixup writer",
            "Tier-B ``D`` merge @ ``0x02A4E0`` via ``0x20B1C0[0x20]`` cloned handler body",
            "Whether ``0x20A7B4`` first-sweep ``g2`` points at compile record chain",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="29FE4 g4 gate + init upload sweep RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29fe4_g4_gate_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    d = report["desert_012e3c_verdict"]
    print(f"Desert g4=4 calls 29C10 @ 29FF8: {d['calls_29c10_at_29ff8']}")
    print(f"Max static sweep slot: {report['max_static_sweep_slot']}  focus {args.slot} in window: {report['slot_in_sweep_windows']}")


if __name__ == "__main__":
    main()
