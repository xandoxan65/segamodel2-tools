#!/usr/bin/env python3
"""Disasm-backed layout: ``0x05CEC0`` compile record → ``0x02A0F8`` dispatch.

Documents field offsets proven in ROM disasm.  Handler table bytes are built in
workram (@ ``0x05DE00``); static ROM has no image.

  python3 -m tools.decomp.palette_compile_record_re
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- ``0x05CEC0`` output @ ``g13`` ------------------------------------------------

CEC0_OUTPUT_FIELDS = (
    {
        "offset": 0x00,
        "size": 8,
        "rom_write": "0x05CEE4",
        "insn": "stq g0,(g13)",
        "role": "Format / stream head (caller ``g0``)",
    },
    {
        "offset": 0x10,
        "size": 8,
        "rom_write": "0x05CEE0",
        "insn": "stq g4,0x10(g13)",
        "role": "``ldis`` pair source for ``0x02A108`` mul (@ ``0x02A100``/``0x02A104``)",
    },
    {
        "offset": 0x20,
        "size": 8,
        "rom_write": "0x05CEF0",
        "insn": "stq g8,0x20(g13)",
        "role": "Auxiliary qword (saved ``g8`` from caller frame)",
    },
)

CEC0_NODE_LINK = {
    "rom": "0x05CEF8",
        "note": "``st g13,(g1)``; ``st 4,0x4(g1)`` — record linked at block vaddr head (``g1`` = ``0x028CCAF8`` desert)",
    "then": "``call 0x05CF50`` format-string bytecode emit",
}

# --- ``0x02A0F8`` reads (consumer) ----------------------------------------------

DISPATCH_2A0F8 = {
    "record_ptr": "``g0`` = ``lda 0x40(fp)`` block head dword (@ ``0x029F84`` — same chain as ``0x29ED4``)",
    "fields": (
        {"offset": 0x10, "insn": "ldis 0x10(g0),g4", "role": "mul operand A"},
        {"offset": 0x12, "insn": "ldis 0x12(g0),g5", "role": "mul operand B"},
        {
            "offset": 0x14,
            "insn": "lda 0x14(g0)[g4*2],g0",
            "role": "Handler u16 table; index = A×B (@ ``0x02A108``)",
        },
    ),
    "trampoline": "0x005C9118 (@ ``0x02A0F0`` lda → ``0x02A114`` bx)",
    "matched_path_29fa0": (
        "``bal 0x02A0F8`` @ ``0x29FA0`` skips ``0x02A0F0``; ``g1=g14`` return link → "
        "``bx (g1)`` @ ``0x02A114`` returns to ``0x29FA4`` without calling handler in ``g0``"
    ),
}

# --- ``0x05DE00`` float/format emit (feeds handler blob) -----------------------

DE00_WRITES = (
    {
        "rom": "0x05DFA4",
        "insn": "stob g4,(g6)",
        "role": "Emit loop: store scaled byte into output buffer ``g6``",
    },
    {
        "rom": "0x05DFC8",
        "insn": "stq r8,(g8)",
        "role": "Finalize chunk pointer into compile output chain",
    },
    {
        "rom": "0x05DFEC",
        "insn": "stl g10,0x8(g12)",
        "role": "Store link field on compile node ``g12``",
    },
)

# --- ``0x29C10`` also uses ``+0x14`` (different read) ---------------------------

ADD_PATH_29CDC = {
    "rom": "0x29CDC",
    "insn": "lda 0x14(g0),g7",
    "role": "FIFO parameter pointer for ``addo g13,g4`` @ ``0x29CFC`` (legacy ``0x29C10`` path)",
    "note": "Same ``+0x14`` offset name; ``0x02A0F8`` uses it as handler table, ``0x29CFC`` as FIFO cursor",
}

OPEN = (
    "No ``st``/``stq`` to ``record+0x14`` in ``0x05CEC0``–``0x05CF50`` — table filled by ``0x05DE00`` emit loop (``E/f/g`` path @ ``0x05D524`` only)",
    "``+0x10`` qword: ``0x012E38`` ``mov 4,g4`` → ``0x05CEE0`` ``stq g4,0x10(g13)`` on desert init (proven)",
    "``0x005C9118`` thunk bodies not in static ROM",
)


def build_report() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm only",
        "cec0_output_fields": list(CEC0_OUTPUT_FIELDS),
        "cec0_node_link": CEC0_NODE_LINK,
        "dispatch_2a0f8": DISPATCH_2A0F8,
        "de00_emit_writes": list(DE00_WRITES),
        "add_path_29cdc": ADD_PATH_29CDC,
        "open": list(OPEN),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Compile record layout (disasm)")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_compile_record_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    for line in OPEN:
        print(f"  OPEN: {line}")


if __name__ == "__main__":
    main()
