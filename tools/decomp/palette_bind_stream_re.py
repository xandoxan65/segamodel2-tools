#!/usr/bin/env python3
"""Disasm + bytecode sim: ``0x026F44`` bind index vs descriptor bus word.

Proves the **bind stream halfword** (bytecode chain @ ``r11`` / ``0x20B1A0`` cursor)
is **not** the same as the **descriptor bus word** @ ``0x01000000`` written by
``0x027008``.  Resolves tier-B slot 477 ``0x8420`` vs ``0x0020`` confusion.

  python3 -m tools.decomp.palette_bind_stream_re
  python3 -m tools.decomp.palette_bind_stream_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_cgm_1111 import _is_format_chunk, _split_inner_chunks
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks, _iter_cgm_v16_records
from tools.model2_cgm_1111 import CGM_RECORD_1111
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

DISASM_BIND_26F10 = (
    {
        "rom": "0x026F20",
        "insn": "``g0 = ld 0x20B1A0`` — nest **depth** (not bytecode cursor)",
    },
    {
        "rom": "0x026F40",
        "insn": "``g4 = lda (g0)[g0*2]`` — ``g4 = 3*depth`` (12-byte stride scale)",
    },
    {
        "rom": "0x026F44",
        "insn": "``g4 = lda 0x20B1C0[g4*4]`` — ``&frame[depth]`` at ``0x20B1C0+12*depth``",
    },
    {
        "rom": "0x026F4C",
        "insn": "``st g5,(g4)``; ``stl g6,4(g4)`` — push ``0x20B1A4`` + ``A8:AC`` counters",
    },
)

DISASM_CLONE_26860 = (
    {
        "rom": "0x26880",
        "insn": "``g4 = lda (g5)[g5*2]`` — ``g4 = 3*ordinal``",
    },
    {
        "rom": "0x26884",
        "insn": "``g4 = lda 0x20B600[g4*4]`` — ``&node[ordinal]`` (dest/src/len job)",
    },
    {
        "rom": "0x2687C",
        "insn": "``cmpibg g5,0x3f`` — clone list capped at 63 entries",
    },
)

DISASM_EMIT_27008 = (
    {
        "rom": "0x027110",
        "insn": "``stos g4,0x01000000[g5*2]`` — **descriptor bus** word (tag | opcode byte)",
    },
    {
        "rom": "0x05D8AC",
        "insn": "``g0 = 32`` (``31+1``); ``bal 0x027008`` — D digit primer when ``r9`` bit 5",
    },
    {
        "rom": "0x05D5AC",
        "insn": "``st r11,(g4)`` — store **bytecode chain head** into compile arena (D/U path)",
    },
)

# ``E``/``f``/``g`` use ``0x05DE00`` → record ``+0x14``; ``D``/``U`` do not.
PATH_SPLIT = (
    {
        "letters": "D, U",
        "handler_rom": "0x05D3DC / 0x05D714",
        "emit": "0x05D860 → 0x027008",
        "record_plus_14": False,
        "bytecode_store": "0x05D5AC ``st r11,(g4)``",
        "run_dispatch": "0x029958 @ 0x005C8964 (desert omits 0x027130 pre-walk)",
    },
    {
        "letters": "E, f, g, …",
        "handler_rom": "0x05D524 ``call 0x05DE00``",
        "emit": "0x05DFA4 ``stob`` into record ``+0x14`` blob",
        "record_plus_14": True,
        "bytecode_store": "handler u16 table indexed @ 0x02A108",
        "run_dispatch": "0x02A0F8 ``bx`` via 0x005C9118 + record ``+0x14`` (matched stream)",
    },
)


def _halfword_at(data: bytes, byte_off: int) -> int:
    if byte_off >= len(data):
        return 0
    lo = data[byte_off]
    hi = data[byte_off + 1] if byte_off + 1 < len(data) else 0
    return lo | (hi << 8)


def _slot477_d_bytecode(main_data: bytes | None = None) -> dict[str, Any]:
    frags = [SLOT477_FRAG]
    if main_data is not None:
        block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
        for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
            if rec_type == CGM_RECORD_1111:
                payload = main_data[off : off + rec_len]
                frags = [
                    c.decode("latin1", errors="replace")
                    for c in _split_inner_chunks(payload)
                    if c and _is_format_chunk(c)
                ]
                break
    events = compile_format_fragment(SLOT477_FRAG)
    for frag in frags:
        if "D" in frag or "d" in frag:
            events = compile_format_fragment(frag)
            break
    d_events = [e for e in events if e.get("op") == "D"]
    if not d_events:
        return {"error": "no D events"}
    last = d_events[-1]
    bc = [int(x, 16) for x in last.get("bytecode", [])]
    raw = bytes(bc)
    state = bind_and_run(bc)
    return {
        "format_frag": last.get("fragment", SLOT477_FRAG)[:80],
        "bytecode_hex": raw.hex(),
        "bytecode_len": len(raw),
        "bind_stream_halfwords": [
            {
                "byte_off": i,
                "halfword": f"0x{_halfword_at(raw, i):04x}",
                "table_index": _halfword_at(raw, i),
                "within_0x3f": _halfword_at(raw, i) <= 0x3F,
            }
            for i in range(0, min(len(raw), 8), 2)
        ],
        "descriptor_bus": {
            str(k): f"0x{v:04x}" for k, v in sorted(state.descriptors.items())
        },
        "distinction": (
            "Bytecode / emit halfword 0x0020 is the **descriptor opcode** byte "
            "fed to 0x027008 (bus word @ idx0 becomes 0x8420 = "
            "0xFFFF8000 | tag 0x400 | opcode 0x20). It does **not** index "
            "0x20B1C0 — that table is a 4-deep counter nest stack."
        ),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    sim = _slot477_d_bytecode(main_data)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + bytecode emit sim — no MAME, no XOR inference",
        "slot": slot,
        "proven": (
            "Descriptor bus word 0x8420 (tag|opcode 0x20) is **not** a bind-table index. "
            "0x026F44 addresses a 12-byte nest frame at 0x20B1C0+12*depth; "
            "0x26884 addresses a 12-byte clone-list node the same way. See "
            "palette_bind_stack_g4_gap_re for the corrected call graph."
        ),
        "disasm_bind_26f10": list(DISASM_BIND_26F10),
        "disasm_clone_26860": list(DISASM_CLONE_26860),
        "disasm_emit_27008": list(DISASM_EMIT_27008),
        "path_split_d_vs_e": list(PATH_SPLIT),
        "slot477_d_sim": sim,
        "open_gaps": [
            "0x02A6D0 wrapper still has zero static callers — g4 publish path OPEN",
            "0x029950 (lda 0x5C8964; bx) has zero callers; bal 0x029958 is a return gadget",
            "Population of 0x005C8E90 format pointer before 0x05CF50 scan",
            "Wrapper g0/g1 bus coords for tier-B slot 477 (merge globals @ 0x02A2E0)",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slot", type=int, default=477)
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_bind_stream_re.json",
    )
    args = ap.parse_args()
    report = build_report(slot=args.slot)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    sim = report.get("slot477_d_sim", {})
    if "bind_stream_halfwords" in sim:
        hw0 = sim["bind_stream_halfwords"][0]
        desc = sim.get("descriptor_bus", {}).get("0", "?")
        print(f"Bind index {hw0['halfword']} vs descriptor bus {desc}")


if __name__ == "__main__":
    main()
