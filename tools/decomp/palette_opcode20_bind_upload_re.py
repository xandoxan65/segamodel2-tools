#!/usr/bin/env python3
"""Disasm RE: bind opcode ``0x20`` → handler clone → upload ``g4`` chain.

Traces slot-477 ``D`` bytecode ``[0x20,0x00,…]`` through ``0x026F44`` bind,
``0x26800`` clone pool, ``0x027160``/``0x0271D0`` stub patches, and the only
static ``ldos`` in the handler mirror band (@ ``0x26780``).  Proves that path
copies halfwords **without** ``xor g13`` — FIFO→``g4`` for ``0x02A62C`` merge
must live in patched ``0x005C8964`` / ``0x005C61C8`` bodies.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_opcode20_bind_upload_re
  python3 -m tools.decomp.palette_opcode20_bind_upload_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_29c10_tier_b_re import _disasm_decode_candidates
from tools.decomp.palette_bind_stream_re import DISASM_BIND_26F10, SLOT477_FRAG, _slot477_d_bytecode
from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom, _ascii_preview, rom_slice
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment, decode_bytecode_stream
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Bind → clone → stub-patch → run (disasm-proven) -------------------------

OPCODE_20_CHAIN = (
    {
        "phase": "emit",
        "rom": "0x05D8AC",
        "effect": "When ``r9`` bit 5 (digits): ``g0=32`` → ``0x027008`` primer",
    },
    {
        "phase": "emit",
        "rom": "0x027110",
        "effect": "Descriptor bus @ ``0x01000000[idx]`` = ``0x8420`` (tag|opcode 0x20)",
    },
    {
        "phase": "bytecode",
        "effect": "Chain head LE halfword ``0x0020`` — **bind index**, not bus word ``0x8420``",
    },
    {
        "phase": "bind",
        "rom": "0x026F44",
        "effect": "``g4 = 0x20B1C0[0x20*4]`` — handler record pointer from clone pool",
    },
    {
        "phase": "bind",
        "rom": "0x026F4C",
        "effect": "``st g5,(g4)``; ``stl g6,4(g4)`` — attach slot/width counters from ``0x20B1A4/A8``",
    },
    {
        "phase": "bind",
        "rom": "0x026F64",
        "effect": "``bx (0x005C5F68)`` — continue in patched workram stub chain",
    },
    {
        "phase": "clone",
        "rom": "0x26800",
        "effect": "``0x20B600`` list → ``call 0x05DAA0`` memcpy template into ``0x20B1C0`` pool",
    },
    {
        "phase": "stub_patch",
        "rom": "0x027160",
        "effect": "Patch ``0x005C61C8`` return addr into ``0x01000000[g4*2]`` descriptor slots",
    },
    {
        "phase": "stub_patch",
        "rom": "0x0271D0",
        "effect": "For each non-zero template byte: patch ``0x005C6250`` stub @ descriptor slot",
    },
    {
        "phase": "run",
        "rom": "0x029958",
        "effect": "``bx 0x005C8964`` — execute patched bytecode program",
    },
    {
        "phase": "upload",
        "rom": "0x02A6D0",
        "effect": "Four ``call 0x02A5A0``; saved ``g4`` → ``r14`` → merge ``g2`` @ ``0x02A62C``",
    },
)

# Only ``ldos`` in handler mirror band — identity copy, no transform.
LDOS_26780 = {
    "rom": "0x26780",
    "routine": "0x26750",
    "insn": "``ldos (g7),g4``",
    "g7_source": "``lda 0x005C5670,g7`` @ ``0x26760`` — ROM mirror embeds template @ ``0x26670``",
    "dest": "``stos g4,(g5)`` → ``0x01800000`` scratch (10× halfword metadata copy)",
    "transform": "none — raw halfword copy",
    "xor_g13": False,
    "fifo_proven": False,
    "note": (
        "This ``ldos`` reads a **static template list**, not CGM FIFO @ fifo+0x3A6. "
        "Runtime FIFO cursor would require ``g7`` patched away from ``0x005C5670``."
    ),
}

BOOTSTRAP_26980 = {
    "rom": "0x26980",
    "steps": (
        "``ldos 0x20B914`` → ``0x0100A000`` (u16 opcode index stream)",
        "``call 0x26800`` — clone handler templates",
        "``call 0x268B0`` — scratch flush",
        "``callx 0x20B910`` if non-zero",
    ),
    "static_callers": 0,
    "invoked_from": "Palette init @ ``0x012DE4`` chain (disasm xref only)",
}

STUB_CELLS = (
    ("bind_return", 0x005C5F68, "0x026F10"),
    ("restore_return", 0x005C5FCC, "0x026F70"),
    ("desc_patch_return", 0x005C61C8, "0x027160"),
    ("template_emit_return", 0x005C6250, "0x0271D0"),
    ("clone_bind_return", 0x005C58A4, "0x026860"),
    ("handler_list", 0x005C5670, "0x026760"),
    ("runner_entry", 0x005C8964, "0x029958"),
    ("dispatch_2a0f8", 0x005C9118, "0x02A0F8"),
)


def _mirror_stub(words: list[int], vaddr: int) -> dict[str, Any]:
    rom = wr_to_rom(vaddr)
    blob = rom_slice(words, rom, 32)
    first = words[rom // 4] if 0 <= rom // 4 < len(words) else 0
    is_ret = first == 0x0A000000
    is_code = not is_ret and (first & 0xFF000000) in (0x8C000000, 0x90000000, 0x09000000, 0x84000000)
    return {
        "workram": f"0x{vaddr:08X}",
        "rom_mirror": f"0x{rom:06X}",
        "first_word": f"0x{first:08X}",
        "kind": "ret_stub" if is_ret else ("rom_code" if is_code else "data_or_pattern"),
        "ascii": _ascii_preview(blob, 24),
        "lda_refs": len(find_word_refs(words, vaddr)),
    }


def _bytecode_bind_sim() -> dict[str, Any]:
    events = compile_format_fragment(SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    if not d_events:
        return {"error": "no D in fragment"}
    last = d_events[-1]
    bc = [int(x, 16) for x in last.get("bytecode", [])]
    state = bind_and_run(bc)
    hw0 = bc[0] | (bc[1] << 8) if len(bc) >= 2 else 0
    return {
        "fragment": SLOT477_FRAG,
        "last_d_repeat": last.get("repeat"),
        "bytecode_hex": bytes(bc).hex(),
        "bytecode_decoded": decode_bytecode_stream(bc),
        "bind_index_le": f"0x{hw0:04x}",
        "bind_table_slot": f"0x20B1C0[{hw0}*4]",
        "descriptor_bus_idx0": f"0x{state.descriptors.get(0, 0):04x}",
        "stub_patches": len(state.stub_patches),
        "counters_after_walk": {
            "slot": state.counters.slot,
            "width": state.counters.width,
        },
        "distinction": (
            "Bind halfword 0x0020 indexes handler pool slot 32. "
            "Descriptor bus word 0x8420 is separate emit metadata."
        ),
    }


def build_report(
    *,
    slot: int = 477,
    raw_u16: int = 0x8843,
    target_color15: int = 0x6683,
    g13_seed: int = 0x0700,
) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    g13_table = g13_mask_for_slot(g13_seed, slot)
    decodes = _disasm_decode_candidates(slot=slot, raw_u16=raw_u16, g13_seed=g13_seed)
    bind_sim = _bytecode_bind_sim()
    slot477_bc = _slot477_d_bytecode(None)

    misleading = [
        n
        for n, b in decodes.items()
        if int(b["result"], 16) == (target_color15 & 0x7FFF)
        and b.get("proven_for_single_d") is False
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + bytecode sim — no MAME, no xor_table as hardware proof",
        "opcode_20_chain": OPCODE_20_CHAIN,
        "disasm_bind_26f10": list(DISASM_BIND_26F10),
        "ldos_26780": LDOS_26780,
        "bootstrap_26980": BOOTSTRAP_26980,
        "workram_stub_mirrors": [
            {"name": n, "caller": caller, **_mirror_stub(words, va)} for n, va, caller in STUB_CELLS
        ],
        "bytecode_bind_sim": bind_sim,
        "slot477_bind_facts": slot477_bc,
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "oracle_target": f"0x{int(target_color15) & 0x7FFF:04x}",
            "g13_table": f"0x{g13_table:04x}",
            "oracle_xor": f"0x{(int(raw_u16) ^ g13_table) & 0x7FFF:04x}",
            "disasm_decodes": decodes,
            "misleading_xor_batch": misleading,
        },
        "conclusions": (
            "Slot-477 ``D`` bytecode binds opcode index **0x20** via ``0x026F44`` — "
            "distinct from descriptor-bus word **0x8420**.",
            "Static handler mirror ``0x26780`` ``ldos`` is identity copy from ``0x005C5670`` "
            "template list → ``0x01800000`` scratch — **no** ``xor g13``, **not** FIFO fifo+0x3A6.",
            "Upload merge @ ``0x02A62C`` uses ``g2=r14=wrapper g4``. Transform from raw ``0x8843`` "
            "to oracle ``0x6683`` must occur inside patched ``0x005C8964`` / ``0x005C61C8`` "
            "stub bodies — not in static ROM handler templates or ``0x02A4E0`` cluster.",
            "Only disasm decode matching oracle is ``#``-batch XOR @ ``0x02A258`` (misleading for lone ``D``). "
            "ADD @ ``0x29CFC`` yields ``0x7703``.",
        ),
        "open_gaps": (
            "Disassemble runtime ``0x005C61C8`` / ``0x005C6250`` after ``0x027130`` walk for slot-477 ``D``",
            "Map which cloned handler @ ``0x20B1C0[0x20]`` publishes ``g4`` for ``0x02A6D0`` wrapper",
            "Runtime fill of ``0x005C6250``/``0x005C8964`` bodies (``palette_271d0_stub_upload_trace_re``)",
            "Prove ``g7`` repoint from ``0x005C5670`` to live FIFO cursor on tier-B run",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Opcode 0x20 bind → upload chain RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_opcode20_bind_upload_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target_color15=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    sim = report["bytecode_bind_sim"]
    print(f"\nBind index: {sim.get('bind_index_le')} → {sim.get('bind_table_slot')}")
    print(f"Descriptor bus[0]: {sim.get('descriptor_bus_idx0')}")

    print("\nWorkram stub mirrors:")
    for row in report["workram_stub_mirrors"]:
        print(f"  {row['name']:22s} {row['workram']} → {row['kind']:12s} refs={row['lda_refs']}")

    focus = report["focus"]
    print(f"\nSlot {focus['slot']}: raw {focus['raw_u16']} oracle {focus['oracle_target']} xor_oracle {focus['oracle_xor']}")
    if focus["misleading_xor_batch"]:
        print(f"  Misleading match: {', '.join(focus['misleading_xor_batch'])}")

    print(f"\n{report['ldos_26780']['insn']} @ {report['ldos_26780']['rom']}: {report['ldos_26780']['transform']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
