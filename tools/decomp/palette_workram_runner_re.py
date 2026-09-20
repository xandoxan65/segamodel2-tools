#!/usr/bin/env python3
"""Disasm-only trace: workram compile templates → ``0x029958`` runner @ ``0x005C8964``.

Documents ROM-visible xrefs, desert ``0x05CE18`` gate, ``0x05D5AC`` bytecode store,
``0x026F10`` handler bind, and ``0x026800`` handler clone — without XOR inference,
MAME captures, or merge oracle search.

  python3 -m tools.decomp.palette_workram_runner_re
  python3 -m tools.decomp.palette_workram_runner_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_cgm_bytecode import bind_and_run
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

DESERT_SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

# Workram addresses with **exactly one** ROM immediate (``find_word_refs``).
WORKRAM_ROM_XREFS: tuple[dict[str, Any], ...] = (
    {
        "workram": "0x005C8E60",
        "rom_lda": "0x029EE0",
        "role": "``0x05CE18`` compare template (8 bytes) — zero in static ROM dump",
    },
    {
        "workram": "0x005C8E70",
        "rom_lda": "0x02A014",
        "role": "Overflow compile format ptr (@ ``0x02A004`` when ``0x20C954 > 0x1FF``)",
    },
    {
        "workram": "0x005C8E90",
        "rom_lda": "0x02A02C",
        "role": "Desert mismatch compile format ptr (@ ``0x02A01C`` gate)",
    },
    {
        "workram": "0x005C8964",
        "rom_lda": "0x029954",
        "role": "Post-compile run entry — ``bx`` @ ``0x029960`` only",
    },
    {
        "workram": "0x005C89B0",
        "rom_lda": "0x029A00",
        "role": "Alternate ``0x029AE8`` compile wrapper (not ``0x012D90`` desert path)",
    },
    {
        "workram": "0x005C5F68",
        "rom_lda": "0x026F14",
        "role": "``0x026F10`` bind helper return stub",
    },
)

# --- ``0x029EB0`` desert gate → compile+run (static path) ----------------------

DESERT_GATE_29EB0 = (
    {
        "rom": "0x029ECC",
        "insn": "``g0 = lda 0(g2)`` — first qword of CGM block head (desert ``0x028CCAF8``)",
    },
    {
        "rom": "0x029EDC",
        "insn": "``g1 = lda 0x005C8E60`` — zeroed compare template",
    },
    {
        "rom": "0x029EE8",
        "insn": "``bal 0x05CE18`` with ``g2=8`` — lexicographic 8-byte compare",
    },
    {
        "rom": "0x029EEC",
        "insn": "``cmpibne 0,g0,0x2A01C`` — **nonzero → mismatch** (desert head vs zero template)",
    },
    {
        "rom": "0x029EF0",
        "note": "``g0==0`` match path only — stream walk + ``0x029F7C`` → ``0x02A0F8``",
    },
)

DESERT_MISMATCH_COMPILE = (
    {
        "rom": "0x02A01C",
        "insn": "``mov 1,g0``; ``mov 1,g1``; ``bal 0x026E18`` — seed ``0x20B1A8/AC`` counters",
    },
    {
        "rom": "0x02A028",
        "insn": "``g0 = lda 0x005C8E90`` — format string for ``0x05CEC0``/``0x05CF50`` (workram, not CGM bytes)",
    },
    {
        "rom": "0x02A034",
        "insn": "``call 0x05CEC0`` with ``g1=r4`` (block vaddr link from ``0x029EB0`` caller)",
    },
    {
        "rom": "0x02A038",
        "insn": "``bal 0x029958`` — run **without** prior ``call 0x027130`` (contrast ``0x29A4C``)",
    },
    {
        "rom": "0x02A03C",
        "insn": "``subo 1,0,g0`` — return ``g0=-1`` to ``0x012E48`` desert init",
    },
)

# --- ``0x05CEC0`` / ``0x05CF50`` compile output ---------------------------------

CEC0_RECORD_FIELDS = (
    {"offset": 0x00, "rom": "0x05CEE4", "insn": "``stq g0,(g13)`` — caller ``g0`` (= ``0x005C8E90`` on desert path)"},
    {"offset": 0x10, "rom": "0x05CEE0", "insn": "``stq g4,0x10(g13)`` — ``ldis`` pair for ``0x02A108`` mul"},
    {"offset": 0x20, "rom": "0x05CEF0", "insn": "``stq g8,0x20(g13)`` — saved ``g8``"},
)

BYTECODE_STORE_5D5AC = {
    "rom": "0x05D5AC",
    "insn": "``st r11,(g4)`` — store bytecode-chain head/count into arena frame buffer",
    "alt": "0x05D5B8 ``stos r11,(g4)`` when ``r9`` bit 2 set",
    "context": (
        "Reached from ``D``/``U`` handler epilogue after ``0x05D860`` emit; "
        "``r11`` incremented per ``0x027008`` emit during ``0x05D860`` loops"
    ),
    "note": "No static ROM ``st`` to ``0x005C8964`` — runner body populated separately (OPEN)",
}

# --- Handler bind / clone (ROM-visible helpers) ---------------------------------

BIND_26F10 = (
    {
        "rom": "0x026F20",
        "insn": "``ld 0x20B1A0,g0`` — opcode-stream cursor / pointer",
    },
    {
        "rom": "0x026F40",
        "insn": "``lda (g0)[g0*2],g4`` — fetch stream halfword (descriptor tag)",
    },
    {
        "rom": "0x026F44",
        "insn": "``ld 0x20B1C0[g4*4],g4`` — handler record pointer (runtime table)",
    },
    {
        "rom": "0x026F4C",
        "insn": "``st g5,(g4)``; ``stl g6,4(g4)`` — bind width/slot counters into handler record",
    },
)

RESTORE_26F70 = (
    {"rom": "0x026F94", "insn": "``ld 0x20B1C0[g4*4],g4`` — pop handler record"},
    {"rom": "0x026F9C", "insn": "``ld (g4),g5``; ``ld 4(g4),g6``; ``ld 8(g4),g4`` — restore counters"},
    {"rom": "0x026FC8", "insn": "``bx (g0)`` — dispatch cloned workram thunk"},
)

HANDLER_CLONE_26800 = (
    {"rom": "0x026800", "insn": "Walk ``0x20B900`` count; nodes @ ``0x20B600`` linked list"},
    {"rom": "0x02682C", "insn": "``call 0x05DAA0`` — template memcpy into handler pool (no ROM word ref to ``0x05DAA0``)"},
    {"rom": "0x026860", "insn": "``0x20B600[g4*4]`` record ← ``g0``; ``+8`` ← ``g2`` (opcode index from stream halfword)"},
    {"rom": "0x026980", "insn": "Copy ``0x20B914`` u16 stream → ``0x0100A000``; then ``call 0x26800`` + ``0x268B0``"},
    {"rom": "0x0269C4", "insn": "``callx (0x20B910)`` if non-zero — **zeroed @ ``0x26704`` in static init**"},
)

# --- ``0x029958`` and alternate pre-walk path ---------------------------------

RUNNER_29958 = (
    {"rom": "0x029950", "insn": "``lda 0x005C8964,g14``"},
    {"rom": "0x029958", "insn": "``mov g14,g0``; ``bx (g0)``"},
)

ALT_PREWALK_29A30 = (
    {"rom": "0x29A3C", "insn": "``bal 0x026E18`` with ``g0=g1=20``"},
    {"rom": "0x29A44", "insn": "``bal 0x026FD8`` with ``g0=8`` — ``0x20B1B0 = 8<<7``"},
    {"rom": "0x29A4C", "insn": "``call 0x027130`` — walk bytecode **before** run"},
    {"rom": "0x29A50", "insn": "``bal 0x029958``"},
    {
        "note": (
            "Desert ``0x02A038`` omits ``0x027130`` — ``0x005C8964`` body must walk/bind "
            "internally (OPEN)"
        ),
    },
)

# --- Upload cluster (merge path — disasm only) ---------------------------------

MERGE_PATH_2A61C = (
    {"rom": "0x02A5AC", "insn": "``mov g4,r14`` — save wrapper ``g4`` before inner loops"},
    {"rom": "0x02A61C", "insn": "``bbc 0,r5,0x2A630`` — **r5 bit 0** selects merge vs flag path"},
    {"rom": "0x02A62C", "insn": "``call 0x02A4E0`` with ``g0=r10``, ``g1=r9``, ``g2=r14``"},
    {"rom": "0x05D3DC", "insn": "``setbit 0,r9`` on ``D`` — propagates to ``r5`` bit 0 via compiled thunk"},
)


def _scan_workram_xrefs() -> list[dict[str, Any]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    rows: list[dict[str, Any]] = []
    for entry in WORKRAM_ROM_XREFS:
        addr = int(entry["workram"], 16)
        refs = find_word_refs(words, addr)
        rows.append(
            {
                **entry,
                "rom_ref_count": len(refs),
                "rom_refs": [f"0x{r:08X}" for r in refs],
            }
        )
    return rows


def _slot477_compile_static() -> dict[str, Any]:
    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    last = d_events[-1] if d_events else None
    if not last:
        return {"error": "no D events in fragment"}
    bc = [int(x, 16) for x in last.get("bytecode", [])]
    bound = bind_and_run(bc)
    return {
        "format_frag": DESERT_SLOT477_FRAG,
        "last_d_repeat": last.get("repeat"),
        "bytecode_head": last.get("bytecode", [])[:12],
        "descriptor_idx0": bound.descriptors.get(0),
        "descriptor_idx0_hex": f"0x{bound.descriptors[0]:04x}" if 0 in bound.descriptors else None,
        "stub_patches_27160": len(bound.stub_patches),
        "disasm_note": (
            "Bind stream LE halfword ``0x0020`` (bytecode ``[0x20,0x00]``) indexes "
            "``0x20B1C0[0x20*4]`` @ ``0x026F44``. Descriptor bus word ``0x8420`` @ "
            "``0x01000000`` is a separate namespace (see ``palette_bind_stream_re``)."
        ),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + maincpu ROM word xrefs only — no XOR, no MAME, no merge oracle",
        "summary": (
            "Desert ``0x029EB0``: ``0x05CE18`` compares block head vs zero ``0x005C8E60`` → "
            "``0x02A01C`` compile using workram format @ ``0x005C8E90`` (single ROM ``lda``), "
            "then ``0x029958`` ``bx`` @ ``0x005C8964`` (single ROM ``lda``). "
            "Bytecode chain ``r11`` stored @ ``0x05D5AC`` during ``0x05CF50``; handler records "
            "cloned @ ``0x026800``/``0x05DAA0`` into ``0x20B1C0`` table. "
            "Tier-B slot replay is **inside** ``0x005C8964`` patched body — not ``0x029F7C``."
        ),
        "workram_rom_xrefs": _scan_workram_xrefs(),
        "desert_gate_29eb0": list(DESERT_GATE_29EB0),
        "desert_mismatch_compile": list(DESERT_MISMATCH_COMPILE),
        "cec0_record_fields": list(CEC0_RECORD_FIELDS),
        "bytecode_store_5d5ac": BYTECODE_STORE_5D5AC,
        "bind_26f10": list(BIND_26F10),
        "restore_26f70": list(RESTORE_26F70),
        "handler_clone_26800": list(HANDLER_CLONE_26800),
        "runner_29958": list(RUNNER_29958),
        "alt_prewalk_29a30": ALT_PREWALK_29A30,
        "merge_path_2a61c": list(MERGE_PATH_2A61C),
        "slot_static": _slot477_compile_static() if slot == 477 else {"slot": slot},
        "proven_vs_open": {
            "proven": [
                "Single ROM xref each for ``0x005C8E60``/``70``/``90``/``8964`` — all workram-only bodies",
                "Desert gate ``0x029EEC`` branches to ``0x02A01C`` on first-byte mismatch",
                "``0x05D5AC`` persists ``r11`` bytecode chain into compile arena frame",
                "``0x026F10`` binds ``0x20B1A8/AC`` into ``0x20B1C0[opcode]`` handler records",
                "``0x02A62C`` merge uses ``g2=r14`` (= saved wrapper ``g4``), not direct FIFO read insn",
                "``0x02A258`` XOR gated on ``g3>0`` — not lone ``D`` compile emit path",
            ],
            "open": [
                "``0x005C8E90`` / ``0x005C8964`` body bytes — no ROM ``st`` sites",
                "Population of ``0x005C8E90`` format template before ``0x012E3C`` desert compile",
                "How ``0x005C8964`` runner reaches ``0x026F10``/``0x02A6D0`` without ``0x29A4C`` pre-walk",
                "``0x26F44`` table index when stream halfword is ``0x8420`` — **closed**: bind stream uses LE halfword ``0x0020`` (index 32); ``0x8420`` is descriptor-bus word only",
                "FIFO u16 read insn on desert compile+run path for tier-B slot 477",
                "Wrapper ``r10``/``r9`` bus coords for ``0x02A4E0`` from compile record ``+0x10``",
            ],
        },
        "related_tools": [
            "palette_compile_run_re",
            "palette_handler_dispatch",
            "palette_staging_bootstrap_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Workram runner static RE (disasm only)")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_workram_runner_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(report["summary"])
    xrefs = report["workram_rom_xrefs"]
    print(f"\nWorkram ROM xrefs ({len(xrefs)} addresses, all lda-only in static ROM):")
    for row in xrefs:
        print(f"  {row['workram']} ← {row['rom_refs']}  ({row['role'][:60]}…)")


if __name__ == "__main__":
    main()
