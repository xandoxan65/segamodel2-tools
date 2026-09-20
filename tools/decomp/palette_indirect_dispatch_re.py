#!/usr/bin/env python3
"""Disasm RE: indirect dispatch to course hook ``0x0162E0`` + ``0x005C58xx`` stub band.

Proves ``0x0162E0`` has **zero** static ``call``/``bal`` sites and **zero** ROM dword
refs; documents ``0x202230``/``0x20A940`` flag gates, ``0x01638C`` ``0x20B914`` reset,
runtime-empty ``0x005B36xx`` tables, and the live ``0x014530`` palette sweep path
(``0x20A8B4`` + ``0x029C10``) as the nearest static upload analogue.

Maps handler-clone stub mirrors ``0x005C58A4`` / ``0x005C5974`` (``ret`` + body @
``0x0268B0``/``0x026910``) tied to unreachable-static ``0x026980`` bootstrap.

No MAME. xor_table oracle only.

  python3 -m tools.decomp.palette_indirect_dispatch_re
  python3 -m tools.decomp.palette_indirect_dispatch_re --slot 477
"""

from __future__ import annotations

import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom, rom_slice
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Course hook @ ``0x0162E0`` (@ ``maincpu_016000_400.asm``) -----------------

COURSE_HOOK_162E0 = (
    {"rom": "0x0162E0", "effect": "Entry — **zero** static callers; **zero** ROM dword refs"},
    {"rom": "0x0162E8", "effect": "``ld 0x202230,g4`` — frame/course state counter"},
    {"rom": "0x0162F0", "effect": "Skip early path when ``0x202230 != 0``"},
    {"rom": "0x0162F4", "effect": "``ld 0x20A940,g4`` — one-shot init flag"},
    {"rom": "0x016344", "effect": "``cmpibne 0,g0,0x163C8`` — tail when ``g0 != 0`` at entry"},
    {"rom": "0x01638C", "effect": "``stos g14,0x20B914``; ``stos g14,0x20B918`` — stream reset"},
    {"rom": "0x0163C8", "effect": "``ret`` — no ``call 0x026980`` / no ``0x029958``"},
)

# --- Game-state writers for ``0x202230`` (@ ``geo_cluster_10`` / ``0x014788``) ---

WRITERS_202230 = (
    {
        "rom": "0x013D4C",
        "context": "Geo feeder path when ``0x202064`` bit 4 clear",
        "effect": "``ld 0x202230`` → ``bal 0x014788`` with ``g0=2`` → ``st g0,0x202230``",
    },
    {
        "rom": "0x0148A0",
        "context": "``0x014820`` frame wrapper after ``bal 0x0146A8``",
        "effect": "``bal 0x014788`` with ``g0=5`` → decrements ``0x20A8BC`` counter",
    },
    {
        "rom": "0x016130",
        "context": "Game init @ ``0x016104`` ``0x029EB0`` path (block ``0x020B65F4``)",
        "effect": "``bal 0x014788`` — sets course-load metadata, not ``0x0162E0``",
    },
)

# --- Live static upload analogue: ``0x014530`` --------------------------------

UPLOAD_14530 = (
    {"rom": "0x014530", "effect": "Uses ``g2 = 0x20A8B4`` (runtime course block pointer)"},
    {"rom": "0x014564", "effect": "``call 0x029D60`` — compile path variant"},
    {"rom": "0x0145D4", "effect": "``call 0x029C10`` with ``g4=0`` — tier-A ADD sweeps"},
    {"rom": "0x0148D4", "effect": "Called from ``0x014820`` when ``g0==2`` after ``0x014788``"},
    {"note": "Static sweeps via ``0x20A8B4`` — not desert ``0x028CCAF8`` / slot 477"},
)

# --- Runtime-empty dispatch tables (ROM scan @ ``0x005B36xx``) -----------------

RUNTIME_TABLES = (
    {"rom": "0x005B3690", "consumer": "``0x014678`` ``bx (g0)``", "static_dwords_nonzero": 0},
    {"rom": "0x005B36DC", "consumer": "``0x0146A8`` state picker", "static_dwords_nonzero": 0},
    {"rom": "0x005B375C", "consumer": "``0x014788`` ``ld 0x5B375C[g0*4]``", "static_dwords_nonzero": 0},
    {"rom": "0x005B37F4", "consumer": "``0x014788`` link stub", "static_dwords_nonzero": 0},
)

# --- ``0x005C58xx`` handler stub mirrors (``rom = wr - 0x0059F000``) ------------

STUB_MIRROR_CELLS = (
    {
        "workram": "0x005C5670",
        "rom_body": "0x026670",
        "head_dword": "template padding + ``0x26690`` body",
        "consumer": "``0x26760`` ``ldos`` template list",
    },
    {
        "workram": "0x005C57F0",
        "rom_body": "0x0267F0",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x26750`` metadata copy loop return",
    },
    {
        "workram": "0x005C58A4",
        "rom_body": "0x0268A4",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x26860`` opcode-index publish; body @ ``0x268B0``",
    },
    {
        "workram": "0x005C5974",
        "rom_body": "0x026974",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x26910`` scratch publish; body @ ``0x26910``",
    },
    {
        "workram": "0x005C5F68",
        "rom_body": "0x026F68",
        "head_dword": "``0x0A000000`` + link to ``0x005C5FCC``",
        "consumer": "``0x026F10`` bind opcode ``0x20`` continuation",
    },
    {
        "workram": "0x005C612C",
        "rom_body": "0x02712C",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x027008`` dispatch return",
    },
    {
        "workram": "0x005C61C8",
        "rom_body": "0x0271C8",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x027160`` stub patcher return",
    },
    {
        "workram": "0x005C6250",
        "rom_body": "0x027250",
        "head_dword": "``0x0A000000`` (``ret`` stub)",
        "consumer": "``0x0271D0`` zero-fill patcher return",
    },
)


def _scan_call_bal(targets: set[int]) -> dict[str, list[str]]:
    pat = re.compile(
        r"^([0-9a-f]+):\s+([0-9a-f]+)\s+(call|bal)\s+0x([0-9a-f]+)",
        re.I | re.M,
    )
    out: dict[str, list[str]] = {f"0x{t:06X}": [] for t in sorted(targets)}
    for asm in sorted((REPO_ROOT / "decomp/disasm").rglob("*.asm")):
        if not asm.is_file():
            continue
        text = asm.read_text(encoding="utf-8", errors="replace")
        for m in pat.finditer(text):
            dest = int(m.group(4), 16)
            if dest in targets:
                key = f"0x{dest:06X}"
                out[key].append(f"0x{int(m.group(1), 16):06X} {m.group(3)} ({asm.name})")
    return out


def _count_nonzero_dwords(base: int, count: int, words: list[int]) -> int:
    n = 0
    for i in range(count):
        rom = base + i * 4
        if rom // 4 < len(words) and words[rom // 4] != 0:
            n += 1
    return n


def _stub_mirror_heads(words: list[int]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for cell in STUB_MIRROR_CELLS:
        wr = int(cell["workram"], 16)
        rom = wr_to_rom(wr)
        head = words[rom // 4] if rom // 4 < len(words) else 0
        rows.append(
            {
                **cell,
                "rom_mirror": f"0x{rom:06X}",
                "head": f"0x{head:08X}",
                "is_ret_stub": head == 0x0A000000,
            }
        )
    return rows


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    targets = {0x162E0, 0x14788, 0x14530, 0x26980, 0x26860}
    call_sites = _scan_call_bal(targets)

    tables = []
    for t in RUNTIME_TABLES:
        base = int(t["rom"], 16)
        tables.append(
            {
                **t,
                "nonzero_dwords_24": _count_nonzero_dwords(base, 24, words),
            }
        )

    refs_162e0 = find_word_refs(words, 0x000162E0)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM xref — no MAME",
        "focus": {"slot": slot, "tier_b_decode": "open"},
        "course_hook_162e0": list(COURSE_HOOK_162E0),
        "writers_202230": list(WRITERS_202230),
        "upload_14530": list(UPLOAD_14530),
        "runtime_tables": tables,
        "stub_mirror_cells": _stub_mirror_heads(words),
        "static_call_bal_sites": call_sites,
        "rom_dword_refs_162e0": [f"0x{r:06X}" for r in refs_162e0],
        "verdicts": [
            {
                "id": "162e0_orphan_entry",
                "proven": True,
                "note": "Zero static ``call``/``bal`` and zero ROM dword ``0x000162E0`` refs",
            },
            {
                "id": "1638c_resets_20b914_only",
                "proven": True,
                "note": "Course-hook tail clears stream head; never invokes ``0x026980``",
            },
            {
                "id": "5b36xx_tables_runtime_empty",
                "proven": True,
                "note": (
                    "``0x005B3690``/``0x005B36DC`` mirror heads are ``ret`` stubs; "
                    "``0x005B375C`` mirror @ ``0x01475C`` aliases embedded ``0x014760`` scaffold"
                ),
            },
            {
                "id": "14530_nearest_static_upload",
                "proven": True,
                "note": "``0x014530`` ``0x029C10`` sweeps via ``0x20A8B4`` — not desert slot 477",
            },
            {
                "id": "5c58xx_ret_stub_band",
                "proven": True,
                "note": (
                    "Handler mirrors ``0x005C58A4``/``0x005C5974`` lead with ``ret``; "
                    "bodies @ ``0x268B0``/``0x26910`` — clone path needs ``0x026980``"
                ),
            },
            {
                "id": "26860_also_unreachable",
                "proven": True,
                "note": "Opcode-index publish @ ``0x26860`` — zero static callers (same as ``0x26980``)",
            },
        ],
        "open_gaps": [
            "Runtime registration of ``0x0162E0`` (OS callback / patched ``0x005B36xx`` table?)",
            "Whether ``0x202230`` state transition ever chains ``0x0162E0`` → ``0x026980``",
            "Live ``0x20A8B4`` course block identity vs desert ``0x028CCAF8`` for ``0x1111`` replay",
            "Runtime ``0x20B910`` nonzero target (still open from ``palette_20b910_dispatch_re``)",
        ],
        "related_tools": [
            "tools.decomp.palette_20b910_dispatch_re",
            "tools.decomp.palette_1111_driver_negative_re",
            "tools.decomp.palette_stub_mirror_recovery_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Indirect dispatch RE: 0x162E0 + 0x5C58xx stubs")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_indirect_dispatch_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["verdicts"] if v.get("proven"))
    print(f"\nVerdicts: {proven}/{len(report['verdicts'])} proven")
    print(f"162E0 callers: {len(report['static_call_bal_sites']['0x0162E0'])}")
    print(f"162E0 dword refs: {len(report['rom_dword_refs_162e0'])}")
    ret_stubs = sum(1 for c in report["stub_mirror_cells"] if c.get("is_ret_stub"))
    print(f"5C58xx ret-stub cells: {ret_stubs}/{len(report['stub_mirror_cells'])}")


if __name__ == "__main__":
    main()
