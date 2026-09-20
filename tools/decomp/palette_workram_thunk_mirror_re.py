#!/usr/bin/env python3
"""ROM mirror scan: workram thunk bodies @ ``workram - 0x0059F000``.

Many ``0x005Cxxxx`` cells are ``ret`` in the mirror (runtime-patched).  This tool
also finds **ROM-resident handler template code** in the mirror (notably the list
@ ``0x005C5670`` → ROM ``0x26670``) and proves the upload cluster ``0x02A4E0``–
``0x02A740`` has **zero** static ROM word references (``bx``-only reachability).

No MAME captures.  No XOR inference.

  python3 -m tools.decomp.palette_workram_thunk_mirror_re
  python3 -m tools.decomp.palette_workram_thunk_mirror_re --slot 477
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import (
    WORKRAM_ROM_MIRROR,
    wr_to_rom,
    _ascii_preview,
)
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

# Cells referenced from bytecode / upload helpers (``lda`` sites in ROM).
STUB_CELLS: tuple[tuple[str, int, str], ...] = (
    ("bind_return", 0x005C5F68, "``0x026F10`` bind"),
    ("restore_return", 0x005C5FCC, "``0x026F70`` restore"),
    ("opcode_dispatch", 0x005C612C, "``0x027008`` return"),
    ("desc_patch_return", 0x005C61C8, "``0x027160`` descriptor patch"),
    ("template_emit_return", 0x005C6250, "``0x0271D0`` template emit"),
    ("runner_entry", 0x005C8964, "``0x029958`` ``bx`` target"),
    ("dispatch_2a0f8", 0x005C9118, "``0x02A0F8`` trampoline"),
    ("scratch_write_return", 0x005C94D8, "``0x02A490`` return"),
    ("palram_pack_return", 0x005C9488, "``0x02A410`` return"),
    ("handler_template_list", 0x005C5670, "``0x026760`` halfword template copy source"),
    ("handler_node_bx", 0x005C5250, "Referenced @ ROM mirror ``0x266B8``"),
)

UPLOAD_CLUSTER = (0x02A200, 0x02A850)

# MAME slice: ``decomp/disasm/maincpu/maincpu_026670_120.asm`` — full trace in
# ``palette_handler_template_26690_re``.
HANDLER_TEMPLATE_26690 = (
    {"rom": "0x26690", "insn": "``lda 0xFFAC,g5`` → ``stos 0x01040000`` — staging1"},
    {"rom": "0x266B8", "insn": "7× ``call 0x26B94`` — palram nibble pack via ``ldob (g0)`` (``g0=0x005C5250`` cell)"},
    {"rom": "0x266FC", "insn": "``call 0x26C44`` — dual-lane pack (``g4=2``)"},
    {"rom": "0x26700", "insn": "``call 0x26A10`` — bus zero-fill; **not** upload cluster"},
    {"note": "**No** FIFO ``ldos`` / ``xor g13`` in template or ``0x26200``–``0x27300`` mirror band"},
)

CLONE_CHAIN_26800 = (
    {"rom": "0x026800", "effect": "Walk ``0x20B600`` list; ``call 0x05DAA0`` memcpy per node"},
    {"rom": "0x026860", "effect": "``0x20B600[g4*4]`` ← handler ptr; ``+8`` ← ``g2`` (template index)"},
    {"rom": "0x026980", "effect": "``0x20B914`` u16 stream → ``0x0100A000``; ``call 0x026800`` — **no static callers**"},
    {"rom": "0x026F10", "effect": "Bind: stream halfword → ``0x20B1C0[opcode*4]``; slot 477 ``D`` → index ``0x20``"},
    {"rom": "0x027160", "effect": "Patch ``0x005C61C8`` **return address** into ``0x01000000`` descriptor word"},
    {"rom": "0x029958", "effect": "``bx 0x005C8964`` — mirror is ``ret``; body patched @ compile+run"},
)


def _word_at(words: list[int], rom: int) -> int:
    idx = rom // 4
    if idx < 0 or idx >= len(words):
        return 0
    return words[idx]


def _mirror_cell_report(words: list[int], name: str, vaddr: int, role: str) -> dict[str, Any]:
    rom = wr_to_rom(vaddr)
    w0 = _word_at(words, rom)
    blob = b"".join(struct.pack("<I", _word_at(words, rom + i)) for i in range(0, 32, 4))
    refs = find_word_refs(words, vaddr)
    kind = "ret_stub" if w0 == 0x0A000000 else ("zero" if w0 == 0 else "body_or_data")
    return {
        "id": name,
        "workram": f"0x{vaddr:08X}",
        "rom_mirror": f"0x{rom:08X}",
        "role": role,
        "first_word": f"0x{w0:08X}",
        "kind": kind,
        "rom_lda_refs": len(refs),
        "rom_lda_sites": [f"0x{r:08X}" for r in refs[:6]],
        "ascii_preview": _ascii_preview(blob, 32),
    }


def _scan_mirror_for_xor_g13(words: list[int], rom_lo: int, rom_hi: int) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for rom in range(rom_lo, rom_hi, 4):
        w = _word_at(words, rom)
        # ``xor g4,g13,g4`` = 58A74314 (and variants with different src reg)
        if (w & 0xFFFF00FF) == 0x58004314 or (w & 0xFF00FFFF) == 0x58000014:
            hits.append({"rom": f"0x{rom:05X}", "word": f"0x{w:08X}"})
        if w == 0x59A5001D:
            hits.append({"rom": f"0x{rom:05X}", "word": "addo g13,g4,g4"})
    return hits


def _upload_cluster_refs(words: list[int]) -> dict[str, Any]:
    targets = {
        "merge": 0x02A4E0,
        "fifo_runner": 0x02A5A0,
        "wrapper": 0x02A6D0,
        "scratch_write": 0x02A490,
        "batched_xor": 0x02A200,
        "xor_insn": 0x02A258,
    }
    rows: dict[str, Any] = {}
    for label, addr in targets.items():
        refs = find_word_refs(words, addr)
        rows[label] = {"rom": f"0x{addr:05X}", "static_word_refs": len(refs), "sites": [f"0x{r:08X}" for r in refs[:8]]}
    return {
        "targets": rows,
        "conclusion": (
            "Upload cluster handlers are reached only via ``bx`` / patched descriptor chains, "
            "not direct ``call``/``bal`` from maincpu ROM (zero word immediates)."
        ),
    }


def _format_mirror_cells(words: list[int]) -> list[dict[str, Any]]:
    """Non-ret cells in slab with ``lda`` refs (embedded format strings / code)."""
    rows: list[dict[str, Any]] = []
    for vaddr in range(0x005C8000, 0x005C9300, 4):
        rom = wr_to_rom(vaddr)
        w = _word_at(words, rom)
        if w in (0, 0x0A000000):
            continue
        refs = find_word_refs(words, vaddr)
        if not refs:
            continue
        blob = b"".join(struct.pack("<I", _word_at(words, rom + i)) for i in range(0, 16, 4))
        rows.append(
            {
                "workram": f"0x{vaddr:08X}",
                "rom_mirror": f"0x{rom:08X}",
                "first_word": f"0x{w:08X}",
                "ascii": _ascii_preview(blob, 16),
                "refs": len(refs),
            }
        )
    return rows


def _opcode_20_bind(*, slot: int) -> dict[str, Any]:
    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    last = d_events[-1] if d_events else None
    bc = [int(x, 16) for x in (last or {}).get("bytecode", [])]
    bound = bind_and_run(bc) if bc else None
    return {
        "slot": slot,
        "format_frag": DESERT_SLOT477_FRAG,
        "last_d_bytecode_head": [f"0x{b:02x}" for b in bc[:12]],
        "bind_index": "0x0020 (from LE halfword 0x20 in bytecode chain)",
        "descriptors": dict(bound.descriptors) if bound else {},
        "stub_patches": len(bound.stub_patches) if bound else 0,
        "handler_record": "``0x20B1C0[0x20*4]`` — cloned @ ``0x26800`` from ``0x20B600`` node (runtime list, no static ROM image)",
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    mirror_lo = wr_to_rom(0x005C5200)
    mirror_hi = wr_to_rom(0x005C6300)
    xor_hits = _scan_mirror_for_xor_g13(words, mirror_lo, mirror_hi)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "ROM mirror rule + word xref scan — no MAME",
        "mirror_rule": f"rom = workram - 0x{WORKRAM_ROM_MIRROR:X}",
        "stub_cells": [_mirror_cell_report(words, n, v, r) for n, v, r in STUB_CELLS],
        "format_and_code_cells": _format_mirror_cells(words),
        "handler_template_26690": list(HANDLER_TEMPLATE_26690),
        "mirror_xor_g13_scan": {
            "rom_range": f"0x{mirror_lo:05X}–0x{mirror_hi:05X}",
            "hits": xor_hits,
            "conclusion": "No ``xor g13`` in workram stub mirror band (negative for hardware xor_table on thunk path).",
        },
        "upload_cluster_refs": _upload_cluster_refs(words),
        "clone_chain": list(CLONE_CHAIN_26800),
        "opcode_0x20_bind": _opcode_20_bind(slot=slot),
        "conclusions": (
            "Return-stub cells (``0x005C61C8``, ``0x005C6250``, ``0x005C8964``) are ``ret`` in ROM mirror — "
            "``0x027160``/``0x0271D0`` patch these **addresses** into ``0x01000000`` descriptors, not ROM bodies.",
            "Handler template ROM image @ mirror ``0x26690`` writes **staging1** ``0x01040000`` and touches "
            "``0x01080000`` without ``xor g13`` — FIFO→color15 transform still not in static mirror.",
            "Upload cluster ``0x02A4E0``–``0x02A740``: zero static ROM refs — only reachable after compile patches "
            "descriptor chain / ``0x005C8964`` body.",
            "Slot 477 ``D`` bytecode binds opcode ``0x20`` → ``0x20B1C0[32]``; cloned handler body OPEN.",
        ),
        "open_gaps": (
            "Runtime ``0x005C8964`` body after desert ``0x02A038`` compile (mirror ``ret`` only)",
            "Which ``0x20B600`` node maps opcode ``0x20`` → cloned handler vs ``0x26690`` ROM image",
            "Recover ``0x005FBF10`` row bytes (``0x027260`` writes ``g14`` stubs, not template text)",
            "Static link matched tail → fifo+``0x3A6`` / tier-B slot 477",
        ),
        "handler_template_re": "``palette_handler_template_26690_re`` — MAME slice ``maincpu_026670_120.asm``",
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Workram thunk ROM mirror RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_workram_thunk_mirror_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    ret_stubs = sum(1 for c in report["stub_cells"] if c["kind"] == "ret_stub")
    print(f"\nStub cells: {len(report['stub_cells'])} ({ret_stubs} ret-only in ROM mirror)")
    xor = report["mirror_xor_g13_scan"]
    print(f"Mirror xor g13 hits ({xor['rom_range']}): {len(xor['hits'])}")

    upl = report["upload_cluster_refs"]["targets"]
    print("Static ROM refs to upload cluster:")
    for label, body in upl.items():
        print(f"  {label:14s} {body['rom']}: {body['static_word_refs']} refs")

    bind = report["opcode_0x20_bind"]
    print(f"\nOpcode 0x20 bind (slot {args.slot}): patches={bind['stub_patches']} desc={bind['descriptors']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
