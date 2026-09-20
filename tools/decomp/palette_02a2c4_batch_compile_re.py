#!/usr/bin/env python3
"""Disasm RE: ``0x02A290`` batch boundary → ``0x02A2C4`` ``0x05CEC0`` compile.

Traces the aux format cell @ ``0x005C9280`` (ROM mirror ``0x02A280`` = ``FBT Error!``),
``0x29AA8`` slot clamp, and how chunk-87 slot 477 crosses the ``+24`` batch gate.
Maps compile output to upload cluster ``0x02A6D0``/``0x02A5A0``/``0x02A4E0`` (static ROM only).

No MAME. No xor_table as hardware proof.

  python3 -m tools.decomp.palette_02a2c4_batch_compile_re
  python3 -m tools.decomp.palette_02a2c4_batch_compile_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_29c10_tier_b_re import _disasm_decode_candidates
import struct

from tools.decomp.palette_workram_rom_mirror_re import SLAB_CELLS, wr_to_rom, _ascii_preview, rom_slice
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"
BATCH_GATE_ADD = 24
BATCH_CLAMP = 0x7F

# --- ``0x02A290``–``0x02A2D4`` (maincpu_02a0f8_400.asm) ----------------------

BATCH_COMPILE_CHAIN = (
    {"rom": "0x02A290", "effect": "``ld 0x20C958,g4`` — batch colorbase scratch (``slot<<7`` cache)"},
    {
        "rom": "0x02A298",
        "effect": (
            "``cmpibne 0,g4,0x2A2C4`` — if ``0x20C958 != 0``, skip slot walk → "
            "**direct** ``0x02A2C4`` compile"
        ),
    },
    {"rom": "0x02A29C", "effect": "``ld 0x20C950,g0`` — colorbase **slot** cursor"},
    {"rom": "0x02A2A4", "effect": "``shlo 7,g0,g4``; ``st g4,0x20C958`` — publish ``slot<<7`` row head"},
    {"rom": "0x02A2B0", "effect": f"``addo g0,{BATCH_GATE_ADD},g0`` — batch boundary probe"},
    {"rom": "0x02A2B4", "effect": "``bal 0x29AA8`` — slot clamp / decrement helper"},
    {
        "rom": "0x02A2B8",
        "effect": (
            "``cmpibne 0,g0,0x2A2C4`` — if ``g0 != 0`` after helper → ``ret`` "
            "(no compile this visit)"
        ),
    },
    {
        "rom": "0x02A2C4",
        "effect": "``lda 0x005C9280,g0`` → ``call 0x05CEC0`` — aux format compile on batch close",
    },
    {"rom": "0x02A2D0", "effect": "``subo 1,0,g0``; ``ret``"},
)

SLOT_CLAMP_29AA8 = (
    {"rom": "0x29AA8", "effect": "``mov g14,g1``; ``g14=0`` — return via saved ``bx`` target"},
    {
        "rom": "0x29AB4",
        "effect": (
            f"``cmpibg g0,{BATCH_CLAMP:#x}`` — if ``g0 > {BATCH_CLAMP}``: "
            "``st g0,0x20C950``; ``g0=0``; ``bx (g1)``"
        ),
    },
    {"rom": "0x29AC8", "effect": "else: ``g0--``; ``bx (g1)`` — single decrement per ``bal``"},
)

UPLOAD_STATIC_CHAIN = (
    {"rom": "0x05D3DC", "role": "``D`` compile — ``setbit 0,r9`` → ``0x05D860`` emit"},
    {"rom": "0x05CEC0", "role": "Format compile — link record @ block vaddr; ``call 0x05CF50``"},
    {"rom": "0x02A0F8", "role": "Matched stream dispatch — ``bx 0x005C9118`` (workram OPEN)"},
    {"rom": "0x02A120", "role": "Record-end flush — FIFO ``ldos`` @ ``0x02A148`` (no ``xor g13``)"},
    {"rom": "0x02A6D0", "role": "Upload wrapper — four ``call 0x02A5A0`` permutations"},
    {"rom": "0x02A61C", "role": "``bbc 0,r5`` → ``call 0x02A4E0`` when ``r5`` bit 0 (``D``/``U`` setbit)"},
    {"rom": "0x02A4E0", "role": "Palram bus merge — ``g2`` wrapper arg, **not** FIFO ``ldos``"},
)

AUX_FORMAT_MIRROR = 0x005C9280
DISPATCH_MIRROR = 0x005C9118


def _simulate_batch_gate(slot: int) -> dict[str, Any]:
    """Predict ``0x02A2B8`` outcome after one ``0x29AA8`` visit."""
    g0 = int(slot) + BATCH_GATE_ADD
    path: list[str] = []
    if g0 > BATCH_CLAMP:
        path.append(f"g0={g0} > 0x7F → st 0x20C950={g0}; g0=0")
        g0_after = 0
        triggers_compile = True
    elif g0 > 0:
        g0_after = g0 - 1
        path.append(f"g0={g0} → decrement → g0={g0_after}")
        triggers_compile = g0_after == 0
    else:
        g0_after = g0
        path.append("g0 already 0")
        triggers_compile = True

    return {
        "slot": slot,
        "g0_before_29aa8": g0,
        "g0_after_29aa8": g0_after,
        "path": path,
        "triggers_02a2c4_compile": triggers_compile,
        "note": (
            "One ``bal 0x29AA8`` per ``0x02A2B4`` visit — not a loop. "
            "Compile fires when ``g0==0`` after helper (``0x02A2B8`` fall-through)."
        ),
    }


def _mirror_cell(words: list[int], vaddr: int) -> dict[str, Any]:
    rom = wr_to_rom(vaddr)
    blob = rom_slice(words, rom, 64)
    first = words[rom // 4] if 0 <= rom // 4 < len(words) else 0
    return {
        "rom_hex": f"0x{rom:06X}",
        "ascii_preview": _ascii_preview(blob, 48),
        "first_word": f"0x{first:08X}",
    }


def _aux_format_mirror_facts() -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    cell = _mirror_cell(words, AUX_FORMAT_MIRROR)
    refs = find_word_refs(words, AUX_FORMAT_MIRROR)
    return {
        "workram": f"0x{AUX_FORMAT_MIRROR:08X}",
        "rom_mirror": cell.get("rom_hex"),
        "ascii_preview": cell.get("ascii_preview"),
        "first_word": cell.get("first_word"),
        "static_lda_refs": [f"0x{r:05X}" for r in refs],
        "interpretation": (
            "ROM mirror @ ``0x02A280`` is the string ``FBT Error! \\n`` — compile-time "
            "error format passed to ``0x05CEC0`` on batch boundary, **not** ``0x1111`` payload bytes."
        ),
    }


def _dispatch_mirror_facts() -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    cell = _mirror_cell(words, DISPATCH_MIRROR)
    refs = find_word_refs(words, DISPATCH_MIRROR)
    return {
        "workram": f"0x{DISPATCH_MIRROR:08X}",
        "rom_mirror": cell.get("rom_hex"),
        "first_insn": cell.get("ascii_preview") or cell.get("first_word"),
        "static_lda_refs": [f"0x{r:05X}" for r in refs],
        "interpretation": (
            "Static mirror = ``ret`` @ ``0x02A118``. Upload thunks patched at runtime; "
            "``0x02A120`` reachable only via ``bx (0x005C9118)`` — zero static ``call``/``bal``."
        ),
    }


def _fragment_compile_summary(format_frag: str) -> dict[str, Any]:
    events = compile_format_fragment(format_frag)
    ops = [e.get("op") for e in events]
    d_events = [e for e in events if e.get("op") == "D"]
    u_events = [e for e in events if e.get("op") == "U"]
    return {
        "format_frag": format_frag,
        "op_sequence": ops,
        "d_count": len(d_events),
        "u_count": len(u_events),
        "last_d_r9": f"0x{int(d_events[-1].get('r9', 0)):02x}" if d_events else None,
        "last_d_bytecode_len": len(d_events[-1].get("bytecode", [])) if d_events else 0,
    }


def build_report(
    *,
    slot: int = 477,
    raw_u16: int = 0x8843,
    target_color15: int = 0x6683,
    g13_seed: int = 0x0700,
) -> dict[str, Any]:
    g13_table = g13_mask_for_slot(g13_seed, slot)
    decodes = _disasm_decode_candidates(slot=slot, raw_u16=raw_u16, g13_seed=g13_seed)
    oracle_xor = (int(raw_u16) & 0xFFFF) ^ (g13_table & 0xFFFF)

    matches = [
        n
        for n, b in decodes.items()
        if int(b["result"], 16) == (target_color15 & 0x7FFF)
        and b.get("proven_for_single_d") is not False
    ]
    misleading = [
        n
        for n, b in decodes.items()
        if int(b["result"], 16) == (target_color15 & 0x7FFF)
        and b.get("proven_for_single_d") is False
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM mirror — no MAME, xor_table labeled oracle only",
        "batch_compile_chain": BATCH_COMPILE_CHAIN,
        "slot_clamp_29aa8": SLOT_CLAMP_29AA8,
        "upload_static_chain": UPLOAD_STATIC_CHAIN,
        "workram_slab_cells": [{"name": n, "vaddr": f"0x{v:08X}", "role": r} for n, v, r in SLAB_CELLS],
        "aux_format_mirror": _aux_format_mirror_facts(),
        "dispatch_mirror": _dispatch_mirror_facts(),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "g13_table": f"0x{g13_table:04x}",
            "oracle_target": f"0x{int(target_color15) & 0x7FFF:04x}",
            "oracle_xor_decode": f"0x{oracle_xor & 0x7FFF:04x}",
            "format_frag": SLOT477_FRAG,
            "batch_gate_sim": _simulate_batch_gate(slot),
            "fragment_compile": _fragment_compile_summary(SLOT477_FRAG),
            "disasm_decode_candidates": decodes,
            "disasm_matches_target": matches,
            "misleading_xor_batch_match": misleading,
        },
        "conclusions": (
            f"Slot {slot}: ``0x02A2B0`` computes ``g0={slot}+{BATCH_GATE_ADD}={slot + BATCH_GATE_ADD}``; "
            f"``0x29AA8`` clamps → ``g0=0`` → **triggers** ``0x02A2C4`` ``0x05CEC0`` compile.",
            "``0x005C9280`` aux format is ``FBT Error!`` string mirror — batch compile uses "
            "error/reporting template, not desert ``0x1111`` binary payload.",
            "Static upload path ``0x05D860`` → patched ``0x005C8964`` → ``0x02A6D0`` → ``0x02A4E0`` "
            "never ``xor g13`` on lone ``D``; merge ``g2`` = wrapper ``g4``, not FIFO u16.",
            "No disasm-backed single-u16 transform matches oracle except misapplied ``#`` batch "
            "XOR (@ ``0x02A258``, ``proven_for_single_d=False``). ADD @ ``0x29CFC`` → ``0x7703`` ≠ oracle.",
        ),
        "open_gaps": (
            "Runtime ``0x005C9118`` patched body for chunk-87 ``D`` run → ``0x02A6D0`` args",
            "``fp+0x40`` stream root fixup @ ``0x29EF4`` — static ``0x204D4743`` not a pointer",
            "Hardware FIFO→``g4`` before ``0x02A62C`` merge (workram thunks only)",
            "Whether ``0x02A2C4`` batch compile emits handler linking to upload vs error-only path",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x02A2C4 batch compile + upload chain RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_02a2c4_batch_compile_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target_color15=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    focus = report["focus"]
    gate = focus["batch_gate_sim"]
    print(f"\nSlot {focus['slot']}: batch gate → compile={gate['triggers_02a2c4_compile']}")
    for step in gate["path"]:
        print(f"  {step}")

    print(f"\nAux format @ 0x005C9280: {report['aux_format_mirror']['ascii_preview']!r}")
    print(f"Dispatch @ 0x005C9118: {report['dispatch_mirror']['first_insn']!r}")

    print(f"\nDecode: raw {focus['raw_u16']} oracle {focus['oracle_target']} xor_oracle {focus['oracle_xor_decode']}")
    for name, body in focus["disasm_decode_candidates"].items():
        mark = " MATCH" if name in focus["disasm_matches_target"] else ""
        mis = " (misleading # batch)" if name in focus["misleading_xor_batch_match"] else ""
        print(f"  {name:36s} → {body['result']}{mark}{mis}")

    if focus["misleading_xor_batch_match"]:
        print("\nXOR @ 0x02A258 matches oracle but is NOT proven for lone D.")
    if not focus["disasm_matches_target"]:
        print("No hardware-proven single-op decode matches oracle.")

    for line in report["conclusions"][:3]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
