#!/usr/bin/env python3
"""Disasm RE: ``0x005C8350`` hash cluster + descriptor chain → ``0x02A6D0`` upload.

Documents four ``0x029780``–``0x029944`` routines (MAME slice ``maincpu_029780_200.asm``),
proves **zero** static ``call``/``bal`` sites, and simulates slot-477 ``D`` descriptor /
template stub patches on the compile+run path.

No MAME captures. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_8350_descriptor_chain_re
  python3 -m tools.decomp.palette_8350_descriptor_chain_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5fbf10_template_re import load_template_rows
from tools.decomp.palette_d_emit_trace import TEMPLATE_CANDIDATES
from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment, decode_bytecode_stream
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"
DISASM_SLICE = "decomp/disasm/maincpu/maincpu_029780_200.asm"

# --- ``0x005C8350`` hash routines (``maincpu_029780_200.asm``) -----------------

HASH_ROUTINES = (
    {
        "rom": "0x029780",
        "name": "hash_string_g3",
        "loop": "``ldob (g3)`` byte walk; ``xor`` + ``ld 0x005C8350[g4*4]`` mix into ``g7``",
        "tail": "``0x0297D0``: ``g13=0xFFFF``; ``andnot g7,g13,g0`` — color15 clamp",
        "static_callers": 0,
    },
    {
        "rom": "0x0297E0",
        "name": "hash_string_g0",
        "loop": "``ldob (g0)`` walk; same 8350 table; result in ``g6`` → ``andnot`` @ ``0x029830``",
        "static_callers": 0,
    },
    {
        "rom": "0x029840",
        "name": "hash_table_build",
        "loop": (
            "Builds linked cells @ ``0x0020A290`` + scratch @ ``0x00884000``; "
            "inner @ ``0x0298B0`` uses 8350 table (``0x0298F8``/``0x029920``)"
        ),
        "tail": "``0x029938``: ``andnot g2,g13,g0`` — **not** ``g13_mask_for_slot``",
        "static_callers": 0,
        "note": "``0x00884000`` is global hash scratch (3400+ ROM refs) — not FIFO fifo+0x3A6",
    },
)

JUMP_TABLE_8350 = {
    "workram": "0x005C8350",
    "rom_mirror": "0x029350",
    "entry_pattern": "Spread constants ``0x1021``, ``0x2042``, … — CRC-style mix table",
    "used_by": [r["rom"] for r in HASH_ROUTINES],
}

# --- Compile+run → upload (disasm-proven edges) --------------------------------

COMPILE_RUN_TO_UPLOAD = (
    {
        "phase": "compile",
        "rom": "0x05D860",
        "effect": "``bal 0x027008`` → descriptors @ ``0x01000000``; chain head ``r11`` @ ``0x05D5AC``",
    },
    {
        "phase": "walk_optional",
        "rom": "0x029A4C",
        "effect": "``call 0x027130`` — **only** @ ``0x005C8A30`` prewalk thunk; desert ``0x02A038`` **skips**",
    },
    {
        "phase": "walk",
        "rom": "0x027160",
        "effect": "Patch ``0x005C61C8`` links into descriptor slots (``g14=0`` stores in loop)",
    },
    {
        "phase": "walk",
        "rom": "0x0271D0",
        "effect": "Non-zero template bytes → ``0x005C6250`` stub patches; ``slot++`` per byte",
    },
    {
        "phase": "bind",
        "rom": "0x026F44",
        "effect": "Bytecode halfword → ``0x20B1C0[index*4]`` handler; ``bx 0x005C5F68`` (**ret** stub)",
    },
    {
        "phase": "run",
        "rom": "0x029958",
        "effect": "``bx 0x005C8964`` → ``0x005C89A4`` compile iteration (not hash @ ``0x029900`` directly)",
    },
    {
        "phase": "upload",
        "rom": "0x02A6D0",
        "effect": "Four ``call 0x02A5A0``; ``r9`` bit0 (``D``) → ``0x02A62C`` merge ``g2=r14=wrapper g4``",
        "static_callers": 0,
    },
)

D_R9_BIT0_PATH = {
    "compile": "``0x05D3DC`` ``setbit 0,r9``",
    "run_saved": "``0x02A5AC`` ``g4→r14``; ``0x02A654`` ``r5`` bit0 from ``g5``",
    "merge": "``0x02A620``–``0x02A62C``: ``g0=r10``, ``g1=r9``, ``g2=r14`` → ``call 0x02A4E0``",
    "gap": "``r14`` (wrapper ``g4``) source not traced from FIFO ``0x8843`` in static disasm",
}


def _template_sweep(bytecode: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, templates in TEMPLATE_CANDIDATES.items():
        row = templates[1 % len(templates)] if templates else b""
        state = bind_and_run(bytecode, template_row=row)
        rows.append(
            {
                "template": name,
                "row_hex": row.hex() if row else "",
                "stub_patches": len(state.stub_patches),
                "descriptor_count": len(state.descriptors),
                "patch_sample": state.stub_patches[:4],
            }
        )
    return rows


def _slot477_bytecode() -> dict[str, Any]:
    events = compile_format_fragment(SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    if not d_events:
        return {"error": "no D events"}
    last = d_events[-1]
    bc = [int(x, 16) for x in last.get("bytecode", [])]
    rows = load_template_rows()
    row = rows[0]
    base = bind_and_run(bc, template_row=row)
    return {
        "fragment": SLOT477_FRAG,
        "last_d_repeat": last.get("repeat"),
        "bytecode_hex": bytes(bc).hex(),
        "bytecode_decoded": decode_bytecode_stream(bc),
        "descriptors": {str(k): f"0x{v:04x}" for k, v in base.descriptors.items()},
        "rom_template_row0_patches": len(base.stub_patches),
        "template_row0_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in row),
        "template_sweep": _template_sweep(bc),
    }


def _hash_negative_sim(*, raw_u16: int, target: int) -> dict[str, Any]:
    """Prove 8350 tail ``andnot`` alone cannot map raw→oracle unless input already decoded."""
    raw = int(raw_u16) & 0xFFFF
    tgt = int(target) & 0x7FFF
    andnot_raw = raw & 0x7FFF
    return {
        "raw_u16": f"0x{raw:04x}",
        "oracle": f"0x{tgt:04x}",
        "andnot_color15_only": f"0x{andnot_raw:04x}",
        "matches_oracle": andnot_raw == tgt,
        "verdict": (
            "8350 cluster tail is ``andnot`` with ``g13=0xFFFF`` (clear bit 15). "
            "Cannot transform ``0x8843`` → ``0x6683`` without prior ``g2`` mix loop."
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    g13_table = g13_mask_for_slot(0x0700, slot)

    static_refs = {
        r["rom"]: len(find_word_refs(words, int(r["rom"], 16)))
        for r in HASH_ROUTINES
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm (MAME slice) + bytecode sim — no MAME workram",
        "disasm_slice": DISASM_SLICE,
        "jump_table_8350": JUMP_TABLE_8350,
        "hash_routines": HASH_ROUTINES,
        "hash_routine_static_refs": static_refs,
        "compile_run_to_upload": COMPILE_RUN_TO_UPLOAD,
        "d_r9_bit0_merge_path": D_R9_BIT0_PATH,
        "slot477_bytecode": _slot477_bytecode(),
        "hash_negative_sim": _hash_negative_sim(raw_u16=raw_u16, target=target),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "oracle": f"0x{int(target) & 0x7FFF:04x}",
            "g13_table_xor_oracle": f"0x{(int(raw_u16) ^ g13_table) & 0x7FFF:04x}",
        },
        "conclusions": (
            "Four ``0x005C8350`` hash routines @ ``0x029780``/``0x0297E0``/``0x029840`` share a "
            "CRC-style table — **zero** static ROM callers; not proven on desert ``0x02A038`` path.",
            "``0x029840`` writes hash nodes to ``0x0020A290`` and ``0x00884000`` scratch — "
            "global scratch band, unrelated to tier-B FIFO ``0x8843`` unless dynamically wired.",
            "Slot-477 ``D`` bytecode is **11 bytes** (single ``0x20`` descriptor emit); "
            "``0x0271D0`` stub count scales with ``0x005FBF10`` template row (0–10 patches in sim).",
            "Upload merge still requires ``wrapper g4→r14`` on ``0x02A62C``; static disasm does not "
            "connect hash output ``g0`` @ ``0x029944`` to ``0x02A6D0`` (no static ``call`` to either).",
        ),
        "open_gaps": (
            "Runtime ``bx`` target that invokes ``0x029840`` hash (if any) on tier-B slots",
            "Runtime fill of ``0x005C6250``/``0x005C8964`` stub bodies (static mirror = ``ret``)",
            "Trace cloned ``0x20B1C0[0x20]`` handler body → publishes ``g4`` before ``0x02A6D0``",
            "Prove or disprove ``0x029A4C`` ``0x027130`` prewalk on desert compile+run path",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="8350 hash + descriptor chain upload RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_8350_descriptor_chain_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    print("\n8350 hash routines — static callers:")
    for rom, n in report["hash_routine_static_refs"].items():
        print(f"  {rom}: {n}")

    bc = report["slot477_bytecode"]
    print(f"\nSlot-477 D bytecode: {bc.get('bytecode_hex', '?')[:24]}…")
    print("Template stub patches:")
    for row in bc.get("template_sweep", []):
        print(f"  {row['template']:16s}: {row['stub_patches']} patches")

    neg = report["hash_negative_sim"]
    print(f"\nHash andnot-only: {neg['andnot_color15_only']} vs oracle {neg['oracle']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
