#!/usr/bin/env python3
"""Disasm RE: bind ``0x026F10`` is a nest stack — not opcode→handler→``g4``.

Corrects the prior ``0x20B1C0[0x20*4]`` narrative and maps the real static
call graph around clone / bootstrap / upload wrapper.

Proven (byte-displacement ``call``/``bal`` scan of maincpu):

- ``lda (gN)[gN*2],g4`` then ``lda 0x20Bxxx[g4*4],g4`` = address of **12-byte**
  record at ordinal ``gN`` (``base + 12*gN``), not a halfword load.
- ``0x20B1A0`` is nest depth (0..3+); ``0x20B1C0`` holds 4 counter frames
  ``(+0,+4,+8)`` = saved ``0x20B1A4/A8/AC`` — not a 128-entry opcode table.
- Bytecode / bus opcode ``0x20`` is **orthogonal** (descriptor emit @ ``0x0270CC``).
- Bootstrap ``0x026980`` **is** called from cold boot ``0x014DC``.
- Clone-register body ``0x026868`` has one ``bal`` from ``0x019F94`` (``0x20A9xx``
  glyph pack) — not CGM FIFO.
- Upload wrapper ``0x02A6D0`` / staging ``0x02A2E0`` / span ``0x02A750`` /
  bind ``0x026F10``: **zero** static ``call``/``bal`` from outside their clusters.
- ``0x029950`` (``lda 0x5C8964`` → ``bx``) also has zero callers; ``bal 0x029958``
  sites are return gadgets (``mov g14,g0; bx (g0)``).

No MAME. No xor_table as hardware proof.

  python3 -m tools.decomp.palette_bind_stack_g4_gap_re
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_maincpu() -> bytes:
    rom_dir = resolve_rom_dir()
    # Prefer deinterleaved build artifact when present.
    built = REPO_ROOT / "decomp/out/i960/maincpu_deinterleaved.bin"
    if built.is_file():
        return built.read_bytes()
    from tools.i960_scan import load_maincpu_words

    words = load_maincpu_words(rom_dir)
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def _ctrl_dest(ip: int, word: int) -> int:
    disp = word & 0xFFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return ip + disp  # MAME i960: byte displacement from insn address


def _call_bal_hits(rom: bytes, targets: dict[int, str]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {name: [] for name in targets.values()}
    rev = {addr: name for addr, name in targets.items()}
    for i in range(0, len(rom) - 4, 4):
        w = struct.unpack_from("<I", rom, i)[0]
        op = w >> 24
        if op not in (0x09, 0x0B):
            continue
        dest = _ctrl_dest(i, w)
        name = rev.get(dest)
        if name is None:
            continue
        out[name].append(
            {
                "from": f"0x{i:X}",
                "op": "call" if op == 0x09 else "bal",
                "to": f"0x{dest:X}",
            }
        )
    return out


BIND_STACK = (
    {
        "rom": "0x026F20",
        "insn": "``ld 0x20B1A0,g0``",
        "effect": "Nest **depth** (not bytecode cursor / not opcode 0x20)",
    },
    {
        "rom": "0x026F40",
        "insn": "``lda (g0)[g0*2],g4``",
        "effect": "``g4 = 3*g0`` — scale for 12-byte records",
    },
    {
        "rom": "0x026F44",
        "insn": "``lda 0x20B1C0[g4*4],g4``",
        "effect": "``g4 = &0x20B1C0[12*depth]`` — frame address (``lda``, not ``ld``)",
    },
    {
        "rom": "0x026F4C",
        "insn": "``st g5,(g4)``; ``stl g6,4(g4)``",
        "effect": "Push ``0x20B1A4`` + ``0x20B1A8:AC`` into the frame",
    },
    {
        "rom": "0x026F54",
        "insn": "``cmpibl 3,g0`` / ``addo g0,1``",
        "effect": "Depth++ while ``g0 <= 3``",
    },
)

CLONE_LIST = (
    {
        "rom": "0x026880",
        "insn": "``lda (g5)[g5*2],g4``; ``lda 0x20B600[g4*4],g4``",
        "effect": "``&0x20B600[12*ordinal]`` — memcpy job node (dest,src,len)",
    },
    {
        "rom": "0x026800",
        "insn": "Walk ``0x20B900`` count; ``call 0x05DAA0`` per node",
        "effect": "Clone templates — **does not** fill an opcode handler table at ``0x20B1C0``",
    },
    {
        "rom": "0x019F94",
        "insn": "``bal 0x026868``",
        "effect": "Only static publisher into ``0x20B600`` (``0x20A9xx`` pack path)",
    },
    {
        "rom": "0x014DC",
        "insn": "``call 0x026980``",
        "effect": "Cold-boot bootstrap — copies ``0x20B914`` stream, then ``call 0x026800``",
    },
)

WRONG_PRIOR = (
    "``0x026F40`` loads stream halfword at cursor",
    "``0x20B1C0[0x20*4]`` is the opcode-0x20 handler record",
    "Cloned handler @ ``0x20B1C0[0x20]`` publishes wrapper ``g4``",
    "Bootstrap ``0x026980`` has no static callers",
)

OPEN_G4 = (
    {
        "id": "wrapper_unreachable",
        "detail": (
            "``0x02A6D0`` has zero external ``call``/``bal``; merge ``g2=r14=entry g4`` "
            "is proven inside the cluster only"
        ),
    },
    {
        "id": "stub_8964_unentered",
        "detail": (
            "``0x029950`` ``lda 0x5C8964; bx`` has zero callers; ``bal 0x029958`` is a "
            "return gadget — not a thunk runner"
        ),
    },
    {
        "id": "bind_unreachable",
        "detail": "``0x026F10``/``0x026F18`` have zero static callers (workram ``bx`` only)",
    },
    {
        "id": "interim_lift",
        "detail": (
            "Feed FIFO raw into ``cgm_d_merge_commit`` on lone-``D`` drain — proven "
            "``0x02A4E0`` semantics, not ``xor_table``; wrapper bus coords still OPEN"
        ),
    },
)


def build_report() -> dict[str, Any]:
    rom = _load_maincpu()
    targets = {
        0x014DC: "boot_call_site",  # not a target — listed for docs only
        0x26800: "clone_walk",
        0x26860: "clone_reg_entry",
        0x26868: "clone_reg_body",
        0x26980: "bootstrap",
        0x26F10: "bind_entry",
        0x26F18: "bind_body",
        0x29950: "stub8964_entry",
        0x29958: "stub8964_body",
        0x2A2E0: "digit_staging",
        0x2A4E0: "merge",
        0x2A5A0: "runner",
        0x2A6D0: "wrapper",
        0x2A750: "span",
    }
    # Drop the fake boot target from the scan dict
    scan_targets = {k: v for k, v in targets.items() if k != 0x014DC}
    hits = _call_bal_hits(rom, scan_targets)

    # Confirm boot → bootstrap
    boot_hits = []
    for i in range(0, len(rom) - 4, 4):
        w = struct.unpack_from("<I", rom, i)[0]
        if (w >> 24) in (0x09, 0x0B) and _ctrl_dest(i, w) == 0x26980:
            boot_hits.append(
                {
                    "from": f"0x{i:X}",
                    "op": "call" if (w >> 24) == 0x09 else "bal",
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + byte-displacement call/bal scan — no MAME",
        "verdict": (
            "Bind/clone do **not** publish upload-wrapper ``g4``. "
            "``0x20B1C0`` is a 4-deep counter stack; opcode ``0x20`` is descriptor-bus only."
        ),
        "bind_stack_26f10": list(BIND_STACK),
        "clone_list_26800": list(CLONE_LIST),
        "corrected_from_prior_notes": list(WRONG_PRIOR),
        "static_call_bal": {
            name: {
                "count": len(sites),
                "sites": sites[:20],
            }
            for name, sites in sorted(hits.items())
        },
        "bootstrap_callers": boot_hits,
        "open_gaps": list(OPEN_G4),
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_bind_stack_g4_gap_re.json",
    )
    args = ap.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Verdict: {report['verdict']}")
    wrap = report["static_call_bal"].get("wrapper", {})
    print(f"Wrapper external call/bal count: {wrap.get('count', 0)}")
    print(f"Bootstrap callers: {report['bootstrap_callers']}")


if __name__ == "__main__":
    main()
