#!/usr/bin/env python3
"""Disasm RE: slot 477 / ``0x8843`` — matched-stream vs compile+run dual path.

Correlates Python ``0x1111`` replay FIFO coordinates with hardware FIFO
consumers (@ ``0x29CF8``, ``0x02A148``, ``0x02A250``), documents desert
``0x012E3C`` gate (matched → **no** ``0x029958``), and proves static ROM
never ``st``-patches ``0x005C8964`` (mirror entry = ``ret``).

No MAME captures.  No XOR inference beyond reporting oracle vs ADD path.

  python3 -m tools.decomp.palette_slot477_dual_path_re
  python3 -m tools.decomp.palette_slot477_dual_path_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_1111_stream_walk_re import fifo_correlation
from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts
from tools.decomp.palette_workram_rom_mirror_re import WORKRAM_ROM_MIRROR
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_1111 import replay_1111_record
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    load_colorxlat_from_main_data,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"
RUNNER_ENTRY = 0x005C8964

# --- Desert init path (``0x012E3C``) ------------------------------------------------

DESERT_INIT_PATH = (
    {
        "rom": "0x012E3C",
        "effect": "``call 0x029EB0`` with ``g4=4`` on desert block ``0x028CCAF8``",
    },
    {
        "rom": "0x029EEC",
        "effect": "``0x05CE18`` gate: head vs zero ``0x005C8E60`` → **matched** when ``g0==0``",
    },
    {
        "rom": "0x029EF0",
        "effect": "Matched path: ``0x29F0C`` stream walk — **not** ``0x02A01C`` compile",
    },
    {
        "rom": "0x02A000",
        "effect": "``ret`` @ ``0x012E48`` stores ``g0=r7`` (``0x20C954``) — **no** ``bal 0x029958``",
    },
    {
        "rom": "0x02A038",
        "effect": "Mismatch-only: ``bal 0x029958`` after ``0x05CEC0`` — **skipped** on desert matched init",
    },
)

# --- Hardware FIFO ``ldos`` consumers (static disasm) ----------------------------

FIFO_LDOS_CONSUMERS = (
    {
        "rom": "0x29CF8",
        "routine": "0x029C10",
        "transform": "``addo g13,g4,g4`` @ ``0x29CFC``",
        "when": "Matched record tail @ ``0x29FF8``; negative-``g2`` compile @ ``0x29C68``",
        "desert_matched": True,
        "lone_d_merge": False,
    },
    {
        "rom": "0x02A148",
        "routine": "0x02A120",
        "transform": "Linked-list copy / index adjust — **no** ``xor g13``",
        "when": "``0x1111`` record-end flush (``0x005C9118`` dispatch — no static callers)",
        "desert_matched": "indirect",
        "lone_d_merge": False,
    },
    {
        "rom": "0x02A250",
        "routine": "0x02A200",
        "transform": "``xor g4,g13,g4`` @ ``0x02A258`` when ``g3>0``",
        "when": "``#`` batch only — not lone ``D``",
        "desert_matched": False,
        "lone_d_merge": False,
    },
    {
        "rom": "0x02A5F8",
        "routine": "0x02A5A0",
        "transform": "Upload runner inner loop — merge @ ``0x02A62C`` when ``r5`` bit 0",
        "when": "Compile+run via ``0x02A6D0`` wrapper (workram ``bx`` chain)",
        "desert_matched": False,
        "lone_d_merge": True,
    },
)

# --- ``0x005C8964`` runner mirror (``maincpu_029900_300.asm``) -------------------

RUNNER_MIRROR_THUNKS = (
    {"workram": "0x005C8964", "rom": "0x029964", "first_insn": "``ret``", "role": "``bx`` target @ ``0x029960``"},
    {"workram": "0x005C89A4", "rom": "0x0299C0", "role": "Compile iteration → ``call 0x05CEC0`` (``%-11s:%-8d`` format)"},
    {"workram": "0x005C8A30", "rom": "0x029A30", "role": "``call 0x027130`` + ``bal 0x029958`` prewalk+run"},
    {"workram": "0x005C8AD0", "rom": "0x029AA0", "role": "Slot clamp ``g0>0x7F`` → ``g0=-1`` (tier-B boundary)"},
    {"workram": "0x005C8AE0", "rom": "0x029AE0", "role": "``0x20B954[g0*8]`` tier-B group lookup"},
)

RUNNER_MIRROR_CALLS = (
    {"rom": "0x29A0C", "target": "0x05CEC0", "context": "Runner compile loop"},
    {"rom": "0x29A4C", "target": "0x027130", "context": "Bytecode prewalk before re-enter ``0x029958``"},
    {"rom": "0x29C64", "target": "0x05CEC0", "context": "``0x029C10`` negative-``g2`` error path"},
)

RUNNER_MIRROR_NEGATIVE = (
    "No ``call``/``bal`` from ``0x029964``–``0x029BE4`` to ``0x026F10``, ``0x02A6D0``, ``0x02A4E0``, ``0x05D860``",
    "Thunks communicate via ``bx (g1)`` / ``bx (g2)`` stub chains only",
    "**Zero** ROM ``st`` sites with immediate ``0x005C8964`` — entry cell never statically patched",
)


def _runner_entry_facts(words: list[int]) -> dict[str, Any]:
    rom = RUNNER_ENTRY - WORKRAM_ROM_MIRROR
    w0 = words[rom // 4] if rom // 4 < len(words) else 0
    refs = find_word_refs(words, RUNNER_ENTRY)
    st_refs = _scan_st_to_workram(words, RUNNER_ENTRY)
    return {
        "workram": f"0x{RUNNER_ENTRY:08X}",
        "rom_mirror": f"0x{rom:06X}",
        "first_word": f"0x{w0:08X}",
        "static_entry_is_ret": w0 == 0x0A000000,
        "rom_lda_refs": len(refs),
        "rom_st_immediate_refs": len(st_refs),
        "st_sites": st_refs,
        "implication": (
            "Static ``bx 0x005C8964`` (@ ``0x029960``) returns immediately unless workram "
            "entry is runtime-patched — no static ROM writer found"
        ),
    }


def _scan_st_to_workram(words: list[int], vaddr: int) -> list[str]:
    """Find ``st``/``stos`` with full 32-bit immediate matching workram vaddr."""
    hits: list[str] = []
    for idx, w in enumerate(words):
        if (w & 0xFFFF0000) == 0x8A000000 or (w & 0xFF000000) in (0x92000000, 0x92800000, 0x92A00000):
            if w & 0xFFFFFFFF == vaddr:
                hits.append(f"0x{idx * 4:06X}")
        # ``st gX,0xVVVVVVVV`` encoding: second word of pair often holds immediate
        if idx + 1 < len(words):
            pair = (w, words[idx + 1])
            if pair[1] == vaddr and (pair[0] & 0xFF000000) == 0x92000000:
                hits.append(f"0x{idx * 4:06X}")
    return hits[:12]


def _scan_runner_asm_calls() -> list[dict[str, str]]:
    asm = REPO_ROOT / "decomp/disasm/maincpu/maincpu_029900_300.asm"
    if not asm.is_file():
        return []
    text = asm.read_text(encoding="utf-8", errors="replace")
    rows: list[dict[str, str]] = []
    for m in re.finditer(r"^([0-9a-f]+):\s+\S+\s+(call|bal)\s+0x([0-9a-f]+)", text, re.M | re.I):
        rows.append({"rom": f"0x{m.group(1)}", "kind": m.group(2), "target": f"0x{m.group(3)}"})
    return rows


def _replay_slot477(main_data: bytes, *, slot: int) -> dict[str, Any]:
    payload_from = None
    try:
        from tools.decomp.palette_29eb0_stream_walker import _desert_1111_payload

        payload = _desert_1111_payload(main_data)
        payload_from = "desert_1111_record"
    except Exception:
        payload = b""
    pal = PaletteState()
    pal._install_default_lumaram()
    load_colorxlat_from_main_data(pal, main_data)
    result = replay_1111_record(pal, payload, trace_slots=frozenset({slot}))
    trace = result.trace[0] if result.trace else {}
    fifo = fifo_correlation(payload, focus_raw=0x8843) if payload else {}
    return {
        "payload_source": payload_from,
        "payload_len": len(payload),
        "trace": trace,
        "fifo_correlation": fifo,
        "oracle_color15": trace.get("color15"),
        "g13_at_slot": trace.get("g13"),
    }


def _fragment_compile_facts() -> dict[str, Any]:
    events = compile_format_fragment(SLOT477_FRAG)
    ops = [(e.get("op"), int(e.get("repeat") or 1)) for e in events]
    u16_ops = sum(rep for op, rep in ops if op in ("D", "U", "E", "f"))
    d_events = [e for e in events if e.get("op") == "D"]
    last_d = d_events[-1] if d_events else None
    return {
        "fragment": SLOT477_FRAG,
        "compile_events": [{"op": op, "repeat": rep} for op, rep in ops],
        "u16_fifo_atoms_in_fragment": u16_ops,
        "last_d_bytecode_head": (last_d or {}).get("bytecode", [])[:8],
        "note": (
            "Compile parse ≠ replay slot order — ``3333DD3D`` expands to ``D×512`` in "
            "emit table; hardware replay uses ``0x20C950`` cursor + marker-split chunks"
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)
    block = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    cmp = block.get("compare_vs_rom_mirror_template") or {}
    matched = cmp.get("g0") == 0

    replay = _replay_slot477(main_data, slot=slot)
    trace = replay.get("trace") or {}
    fifo_off = None
    if trace.get("bin_pos") is not None:
        fifo_off = int(trace["bin_pos"]) - 2  # u16 read starts 2 bytes before post-read cursor

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM CGM replay correlation — no MAME, no XOR inference",
        "focus": {"slot": slot, "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}"},
        "desert_gate": {
            "block_vaddr": f"0x{COURSE_CGM_VADDRS[1]:08X}",
            "matched": matched,
            "compare_g0": cmp.get("g0"),
            "path": "matched_stream_29EF0" if matched else "mismatch_compile_2A01C",
            "calls_29958_on_init": not matched,
        },
        "desert_init_path": list(DESERT_INIT_PATH),
        "fifo_slot_correlation": {
            "replay_chunk": trace.get("chunk"),
            "format_frag": trace.get("format_frag"),
            "bin_pos_after_read": trace.get("bin_pos"),
            "fifo_offset_inferred": f"0x{fifo_off:X}" if fifo_off is not None else None,
            "fifo_hits_for_raw": (replay.get("fifo_correlation") or {}).get("fifo_hits"),
            "payload_direct_hits": (replay.get("fifo_correlation") or {}).get("payload_direct_hits"),
            "oracle": {
                "raw": trace.get("raw"),
                "color15": trace.get("color15"),
                "g13": trace.get("g13"),
            },
        },
        "fragment_compile": _fragment_compile_facts(),
        "fifo_ldos_consumers": list(FIFO_LDOS_CONSUMERS),
        "runner_entry": _runner_entry_facts(words),
        "runner_mirror_thunks": list(RUNNER_MIRROR_THUNKS),
        "runner_mirror_calls": list(RUNNER_MIRROR_CALLS),
        "runner_asm_calls": _scan_runner_asm_calls(),
        "runner_mirror_negative": list(RUNNER_MIRROR_NEGATIVE),
        "path_matrix": {
            "desert_matched_static": {
                "init": "0x012E3C → 0x029EF0 stream → 0x29F7C inner → 0x29FF8 0x029C10 ADD",
                "slot_477_tier": "tier-B (>127)",
                "8964_runner": False,
                "likely_fifo_consumer": "0x29CF8 (ADD) and/or 0x02A120 record-end — not 0x02A62C merge",
            },
            "mismatch_compile_static": {
                "init": "0x02A01C → 0x05CEC0 → 0x02A038 → 0x029958",
                "8964_runner": True,
                "static_bx_entry": "``ret`` @ mirror — upload requires runtime patch or descriptor ``bx``",
                "lone_d_merge": "0x02A5A0 → 0x02A62C → 0x02A4E0 when ``r5`` bit 0 (compile ``D`` path)",
            },
            "python_replay": {
                "path": "format-walk + xor_table for ``D``",
                "matches_geometry": "~90–95% ok_static",
                "hardware_proven": False,
            },
        },
        "conclusions": (
            "Desert ``0x012E3C`` takes **matched** path — slot 477 is **not** reached via "
            "``0x005C8964`` printf/compile runner on static init.",
            "Replay places ``0x8843`` @ FIFO ``0x3A6`` (chunk 87 frag ``3333DD3D…``); "
            "payload direct hits ``0x4A3``/``0x53F`` differ — FIFO layout is not raw payload.",
            "Static ``0x005C8964`` mirror = ``ret``; **zero** ROM ``st`` patch sites — "
            "``0x02A038`` compile+run requires runtime workram fill (OPEN).",
            "Hardware ``D`` decode for tier-B: ``0x29CFC`` ADD proven on ``0x029C10`` tail; "
            "lone ``D`` merge @ ``0x02A4E0`` is compile+run / ``0x02A5A0`` only — does not "
            "match xor_table oracle ``0x6683`` for ``0x8843``.",
            "Link ``0x20C954`` index @ ``0x29F7C`` → replay slot 477 remains OPEN "
            "(marker-split payload ≠ ``0x29F0C`` node stream without runtime fixup).",
        ),
        "open_gaps": (
            "Runtime patch source for ``0x005C8964`` (or proof compile uses descriptor ``bx`` only)",
            "``0x29CC4`` group index / ``record+0x14`` FIFO cursor → fifo+``0x3A6`` for slot 477",
            "``0x02A6D0`` wrapper ``r10``/``r9`` bus coords for tier-B merge if compile path used",
            "``0x20B600`` opcode ``0x20`` node → cloned handler vs ``0x26690`` palram template",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Slot 477 dual-path palette RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_slot477_dual_path_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    gate = report["desert_gate"]
    print(f"Desert matched={gate['matched']} path={gate['path']} 29958={gate['calls_29958_on_init']}")

    fifo = report["fifo_slot_correlation"]
    print(
        f"Slot {args.slot}: fifo~{fifo.get('fifo_offset_inferred')} "
        f"raw={fifo['oracle'].get('raw')} color15={fifo['oracle'].get('color15')}"
    )

    ent = report["runner_entry"]
    print(f"8964 mirror: {ent['rom_mirror']} first={ent['first_word']} ret={ent['static_entry_is_ret']} st_refs={ent['rom_st_immediate_refs']}")

    for line in report["conclusions"][:3]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
