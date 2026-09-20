#!/usr/bin/env python3
"""Disasm trace: ``0x05CF50`` compile → ``0x027130`` walk → ``0x029958`` run.

Documents the **desert mismatch-compile path** end-to-end: format dispatch
(``0x05FBFD0``), bytecode emit (``0x05D860``/``0x027008``), descriptor walk
(``0x027130``/``0x027160``), and post-compile runner @ ``0x005C8964``.

Correlates static facts for tier-B slot 477 (``raw 0x8843``) without XOR
inference or MAME captures.

  python3 -m tools.decomp.palette_compile_run_re
  python3 -m tools.decomp.palette_compile_run_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import build_report as build_5ce18
from tools.decomp.palette_cgm_stubs import (
    COMPILE_TO_RUN_CHAIN,
    ROM_UPLOAD_HANDLERS,
    WORKRAM_TRAMPOLINES,
)
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_d_emit, compile_format_fragment
from tools.model2_cgm_format_table import (
    TABLE_ROM,
    TABLE_RUNTIME,
    resolve_format_char,
    report_desert_format_table,
)
from tools.model2_palette import COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKRAM_RUN = 0x005C8964

# --- Compile phase (``0x05CEC0`` → ``0x05CF50``) --------------------------------

COMPILE_PHASE = (
    {
        "step": 1,
        "rom": "0x05CEC0",
        "insn": "``call 0x05CF50`` after linking compile record @ ``g13``",
        "effect": "Record fields @ +0x00/+0x10/+0x20; ``g1`` = block vaddr from caller",
    },
    {
        "step": 2,
        "rom": "0x05CF74",
        "insn": "``ldob (r12),g0`` — scan format string",
        "effect": "Digits ``<=31``: ``bal 0x027008`` (@ ``0x05CF94``); letters: char dispatch",
    },
    {
        "step": 3,
        "rom": "0x05CFC4",
        "insn": "``ld 0x5fbfd0[g4*4],g4``; ``bx (g4)``",
        "effect": "121-entry jump table; ``D`` → ``0x005FC3DC`` (impl ``0x05D3DC``)",
    },
    {
        "step": 4,
        "rom": "0x05D3DC",
        "insn": "``setbit 0,r9``; ``g6=10`` → ``0x05D7E8`` template copy",
        "effect": "``r9`` bit 0 → ``0x02A61C`` merge branch when ``r5`` bit 0 set at run time",
    },
    {
        "step": 5,
        "rom": "0x05D860",
        "insn": "``bal 0x027008`` per template/primer byte",
        "effect": "Builds bytecode chain in ``r11``; descriptors @ ``0x01000000``",
    },
    {
        "step": 6,
        "rom": "0x05DFA4",
        "insn": "``stob`` emit loop → record ``+0x14`` handler u16 table",
        "effect": "**E/f/g only** (``0x05D524`` ``call 0x05DE00``). ``D``/``U`` skip this — use ``0x05D5AC`` bytecode chain instead",
    },
)

# --- Walk phase (``0x027130`` before or inside ``0x005C8964`` body) --------------

WALK_PHASE = (
    {
        "rom": "0x027130",
        "insn": "``ldob (g0),g4`` loop; ``bal 0x027008`` per bytecode byte",
        "effect": "Replay emit ops: slot/width counters @ ``0x20B1A8``/``AC``/``B0``",
    },
    {
        "rom": "0x027160",
        "insn": "``lda 0x005C61C8,g14``; patch stub into descriptor chain",
        "effect": "``count`` descriptors starting @ ``(width<<6)+slot`` on staging bus",
    },
    {
        "rom": "0x0271D0",
        "insn": "``lda 0x005C6250,g14``; template-byte emit into descriptors",
        "effect": "Non-zero template rows patch return stubs per descriptor slot",
    },
    {
        "rom": "0x027008",
        "insn": "``g5>31``: ``stos g4,0x01000000[g5*2]`` — descriptor tag emit",
        "effect": "Tag byte in high bits; slot index from ``0x20B1A8`` + ``(width<<6)``",
    },
)

# --- Run phase (desert ``0x029EB0`` mismatch @ ``0x02A038``) --------------------

RUN_PHASE = (
    {
        "rom": "0x02A01C",
        "gate": "``0x05CE18`` mismatch (desert head vs zero ``0x005C8E60`` template)",
        "effect": "``g0=0x005C8E90`` → ``call 0x05CEC0`` @ ``0x02A034``",
    },
    {
        "rom": "0x02A038",
        "gate": "after compile returns",
        "effect": "``bal 0x029958`` — **not** ``0x029EF0`` stream walk",
    },
    {
        "rom": "0x029958",
        "insn": "``mov g14,g0``; ``bx (g0)`` where ``g14=0x005C8964``",
        "effect": "Execute patched post-compile program in workram",
    },
)

# Desert format chars used in slot-477 fragment (static CGM bytes).
DESERT_SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

# Post-init sweeps do not cover slot 477.
UPLOAD_SWEEP_SLOTS = (
    {"rom": "0x012E60", "g0": 20, "g1": 3, "slots": "20–22"},
    {"rom": "0x012E7C", "g0": 7, "g1": 11, "slots": "7–17"},
    {"rom": "0x012E98", "g0": 17, "g1": 11, "slots": "17–27"},
    {"rom": "0x012EB4", "g0": 29, "g1": 11, "slots": "29–39"},
    {"rom": "0x012ED4", "g0": 45, "g1": 11, "slots": "45–55"},
)


def _desert_format_dispatch(rom_dir: Path | None) -> list[dict[str, Any]]:
    report = report_desert_format_table(rom_dir=rom_dir)
    rows: list[dict[str, Any]] = []
    for char in sorted(set(DESERT_SLOT477_FRAG)):
        entry = resolve_format_char(char, None)
        rows.append(
            {
                "char": char,
                "code": entry.code,
                "handler": f"0x{entry.handler:06x}",
                "impl": f"0x{entry.impl:06x}" if entry.impl is not None else None,
                "name": entry.info.get("name"),
                "fifo": entry.info.get("fifo"),
                "r9_bits": entry.info.get("r9_bits"),
            }
        )
    rows.append(
        {
            "note": "full desert char set",
            "chars": report["desert_chars"],
            "table_rom": report["table_rom"],
            "table_runtime": report["table_runtime"],
        }
    )
    return rows


def _slot_d_compile_facts(*, slot: int) -> dict[str, Any]:
    """Static ``D`` emit from desert format fragment containing slot (CGM replay)."""
    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    last_d = d_events[-1] if d_events else None
    if last_d:
        bc = [int(x, 16) for x in last_d.get("bytecode", [])]
        bind = bind_and_run(bc)
        d_facts = {
            "format_frag": DESERT_SLOT477_FRAG,
            "d_event_count": len(d_events),
            "last_d_repeat": last_d.get("repeat"),
            "bytecode": last_d.get("bytecode", [])[:16],
            "bytecode_len": len(bc),
            "decoded_head": last_d.get("bytecode_decoded", [])[:4],
            "descriptors": {str(k): f"0x{v:04x}" for k, v in bind.descriptors.items()},
            "stub_patches": len(bind.stub_patches),
            "note": (
                "Last ``D`` in slot-477 fragment: first byte ``0x20`` is descriptor tag "
                "emit from prior digit ``r9`` state; **0** ``0x027160`` stub patches with "
                "zero template row"
            ),
        }
    else:
        sim = compile_d_emit(repeat=1)
        bind = bind_and_run(sim.bytecode)
        d_facts = {
            "bytecode": [f"0x{b:02x}" for b in sim.bytecode],
            "bytecode_len": len(sim.bytecode),
            "descriptors": {str(k): f"0x{v:04x}" for k, v in bind.descriptors.items()},
            "stub_patches": len(bind.stub_patches),
        }
    return {
        "slot": slot,
        "format_frag_near_slot": DESERT_SLOT477_FRAG,
        "last_d_in_frag": d_facts,
        "upload_sweep_covers_slot": any(
            s["g0"] <= slot < s["g0"] + int(s["g1"]) for s in UPLOAD_SWEEP_SLOTS
        ),
        "tier_b_path": (
            f"Slot {slot} not in post-init ``0x029C10`` sweep windows (max g0=45, g1=11). "
            f"Hardware replay expected inside ``0x{WORKRAM_RUN:08X}`` patched runner after "
            "``0x02A038`` desert compile, not ``0x029F7C``→``0x02A0F8`` matched-stream walk."
        ),
    }


def _bytecode_to_upload_map() -> list[dict[str, str]]:
    """Link compile emit classes to ROM upload cluster (disasm-backed)."""
    return [
        {
            "bytecode_class": "tag > 31 (@ 0x027008)",
            "staging": "``stos`` descriptor @ ``0x01000000[(width<<6)+slot]``",
            "run_time": "``0x027160`` may patch ``0x005C61C8`` stub; thunk → upload cluster",
        },
        {
            "bytecode_class": "opcode 8/9/10",
            "staging": "slot/width counter updates @ ``0x20B1A8``/``AC``",
            "run_time": "Indirect — sets bus coords for ``0x02A4E0`` merge",
        },
        {
            "bytecode_class": "``D`` / ``U`` (``r9`` bit 0)",
            "staging": "compile only — FIFO consumed in run thunk",
            "run_time": "``0x02A61C``: ``r5`` bit 0 → ``0x02A4E0`` merge; else ``0x02A648`` flags",
        },
        {
            "bytecode_class": "``#`` (``r9`` bit 3)",
            "staging": "batch width emit",
            "run_time": "``0x02A258`` XOR when ``g3>0`` — not lone ``D``",
        },
    ]


def build_report(*, slot: int = 477) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    gate = build_5ce18(block_vaddr=COURSE_CGM_VADDRS[1])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM/CGM bytes only — no MAME, no XOR inference",
        "summary": (
            "Desert static: ``0x05CE18`` mismatch → ``0x02A01C`` → ``0x05CEC0``/``0x05CF50`` "
            f"compile → ``0x029958`` run @ ``0x{WORKRAM_RUN:08X}``. Format chars dispatch through "
            f"``0x{TABLE_RUNTIME:06X}`` (ROM image ``0x{TABLE_ROM:06X}``). Bytecode walk "
            "``0x027130`` patches staging descriptors then executes workram thunks into "
            "``0x02A4E0``–``0x02A740`` upload cluster. ``0x029F7C``→``0x02A0F8`` is "
            "**matched-stream only** (``0x05CE18`` g0==0)."
        ),
        "compile_phase": list(COMPILE_PHASE),
        "walk_phase": list(WALK_PHASE),
        "run_phase": list(RUN_PHASE),
        "format_dispatch_slot477_frag": _desert_format_dispatch(rom_dir),
        "bytecode_to_upload": _bytecode_to_upload_map(),
        "workram_trampolines": list(WORKRAM_TRAMPOLINES),
        "rom_upload_handlers": list(ROM_UPLOAD_HANDLERS),
        "compile_to_run_chain": list(COMPILE_TO_RUN_CHAIN),
        "upload_sweeps": list(UPLOAD_SWEEP_SLOTS),
        "desert_29eb0_gate": gate["focus_block"],
        "slot_facts": _slot_d_compile_facts(slot=slot),
        "open": [
            f"``0x{WORKRAM_RUN:08X}`` patched body — zero words in static ROM",
            "Link compile record ``+0x10``/``+0x14`` mul index → wrapper ``r10``/``r9`` bus coords",
            "FIFO u16 → ``g4`` transform for lone ``D`` on compile path (no ``0x02A258`` when g3==0)",
            "``0x20A7B0`` desert compile return — written @ ``0x012E48``, no static ld sites",
            "Whether ``0x005C8964`` body is copied from ``0x027130`` walk or separate ``0x05DE00`` blob",
        ],
        "upstream_tools": [
            "palette_staging_bootstrap_re (0x027260 pre-compile patches)",
            "palette_29958_post_compile_re (0x012D90 init + upload sweeps)",
            "palette_d_emit_trace (slot 477 CGM replay correlation)",
            "palette_cgm_stubs (upload cluster ROM handlers)",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x05CF50 compile → 0x029958 run (disasm)")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_compile_run_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(report["summary"])
    facts = report["slot_facts"]["last_d_in_frag"]
    print(
        f"\nSlot {args.slot} last-D in frag: "
        f"bytecode_len={facts['bytecode_len']} stub_patches={facts['stub_patches']}"
    )
    print(f"  descriptors: {facts['descriptors']}")
    print(f"  {report['slot_facts']['tier_b_path']}")


if __name__ == "__main__":
    main()
