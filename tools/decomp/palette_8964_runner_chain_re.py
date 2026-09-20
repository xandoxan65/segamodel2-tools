#!/usr/bin/env python3
"""Disasm trace: ``0x005C8964`` runner requirements + workram arena slab ``0x005C8E60+``.

Documents how compile output links to the post-``0x05CEC0`` ``bx`` @ ``0x029958``,
what ``0x027130`` does on the alternate ``0x29A4C`` path, and the contiguous
workram pointer/thunk region (single runtime fill — no per-slot ROM ``st`` sites).

  python3 -m tools.decomp.palette_8964_runner_chain_re
  python3 -m tools.decomp.palette_8964_runner_chain_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_bind_stream_re import _slot477_d_bytecode
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_emit import compile_format_fragment
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

ARENA_BASE = 0x005C8E60
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

# Contiguous workram slab: all sites are ``lda``-only in ROM (zero static image).
ARENA_SLAB: tuple[dict[str, Any], ...] = (
    {"offset": 0x000, "vaddr": "0x005C8E60", "size": 8, "role": "``0x05CE18`` compare template"},
    {"offset": 0x010, "vaddr": "0x005C8E70", "role": "Overflow compile format qword @ ``0x02A010``"},
    {"offset": 0x030, "vaddr": "0x005C8E90", "role": "Mismatch compile format qword @ ``0x02A028`` (desert)"},
    {"offset": 0x090, "vaddr": "0x005C8BF0", "role": "``0x029C10`` negative-``g2`` compile format @ ``0x029C58``"},
    {"offset": 0x0E0, "vaddr": "0x005C8D40", "role": "``0x029D60`` compile variant @ ``0x029DA8``"},
    {"offset": 0x104, "vaddr": "0x005C8964", "role": "Post-compile run entry — ``bx`` @ ``0x029960``"},
    {"offset": 0x2B8, "vaddr": "0x005C9118", "role": "``0x02A0F8`` indirect dispatch stub"},
    {"offset": 0x420, "vaddr": "0x005C9280", "role": "Aux compile format @ ``0x02A2C4``"},
)

COMPILE_TO_RUN = (
    {
        "phase": "init_order",
        "rom": "0x012E18",
        "effect": (
            "Alpine ``call 0x029EB0`` (**before** desert @ ``0x012E3C``) — same ``g4=4``; "
            "may side-effect workram slab before desert mismatch compile"
        ),
    },
    {
        "phase": "compile",
        "rom": "0x05CEE4",
        "effect": "``stq g0,(g13)`` — record ``+0x00`` = qword loaded from ``0x005C8E90`` (@ ``0x02A028``)",
    },
    {
        "phase": "compile",
        "rom": "0x05CEE0",
        "effect": "``stq g4,0x10(g13)`` — record ``+0x10 = 4`` (``0x012E38`` ``mov 4,g4`` on desert init)",
    },
    {
        "phase": "compile",
        "rom": "0x05CEF8",
        "effect": "``st g13,(g1)`` — link compile record @ **block vaddr** ``g1`` (``0x028CCAF8`` desert)",
    },
    {
        "phase": "compile",
        "rom": "0x05D5AC",
        "effect": "``st r11,(g4)`` — bytecode-chain head into arena frame (``D``/``U`` path only)",
    },
    {
        "phase": "run",
        "rom": "0x02A038",
        "effect": "``bal 0x029958`` — **no** ``call 0x027130`` (contrast ``0x29A4C``)",
    },
    {
        "phase": "run",
        "rom": "0x029960",
        "effect": "``bx (0x005C8964)`` — patched workram program (body OPEN in static ROM)",
    },
)

# Alternate path with explicit pre-walk (not desert ``0x012E3C`` chain).
ALT_PREWALK_29A4C = (
    {"rom": "0x29A48", "insn": "``mov r4,g0`` — restore saved format/bytecode pointer"},
    {"rom": "0x29A4C", "insn": "``call 0x027130`` — replay ``0x027008`` over bytecode bytes"},
    {"rom": "0x29A50", "insn": "``bal 0x029958`` — same ``bx 0x005C8964`` entry"},
)

WALK_27130 = (
    {"rom": "0x27130", "insn": "``ldob (g0),g4`` — bytecode cursor in ``g0``"},
    {"rom": "0x27144", "insn": "``bal 0x027008`` per byte — refreshes ``0x20B1A8``/``AC`` counters"},
    {"rom": "0x27150", "insn": "ret — **does not** call ``0x027160``/``0x026F10`` (separate runner phase)"},
)

BIND_UPLOAD_CLUSTER = (
    {"rom": "0x026F10", "role": "Bind stream halfword → ``0x20B1C0[index*4]`` record"},
    {"rom": "0x026F70", "role": "Restore counters; ``bx`` cloned thunk"},
    {"rom": "0x02A6D0", "role": "Wrapper saving ``g0..g4`` → repeated ``call 0x02A5A0``"},
    {"rom": "0x02A5A0", "role": "FIFO/upload loops; ``r5`` bit 0 → ``call 0x02A4E0`` merge"},
    {"rom": "0x02A2E0", "role": "Fill ``0x20C95C``–``0x20C968`` merge globals from wrapper args"},
)

RUNNER_REQUIREMENTS = {
    "must_resolve": [
        "Block vaddr ``0x028CCAF8`` → compile record ``g13`` (@ ``0x05CEF8`` link)",
        "Bytecode chain head ``r11`` from ``0x05D5AC`` (or record ``+0x00`` if copied)",
        "Handler table ``0x20B1C0[0x20]`` cloned @ ``0x26800``/``0x05DAA0``",
    ],
    "must_execute": [
        "Either ``call 0x027130`` (omitted @ ``0x02A038``) or equivalent counter replay",
        "``0x026F10`` bind loop over ``0x20B1A0`` cursor / stream halfwords",
        "Cloned thunks → ``0x02A6D0``/``0x02A5A0`` upload (``0x500000``/``0x504000`` @ ``0x02A7C8``)",
    ],
    "desert_gap": (
        "ROM mirror @ ``0x029964`` contains full thunk table (``maincpu_029900_300.asm``) "
        "with embedded ``call 0x027130`` @ ``0x029A4C`` — but desert matched init "
        "(@ ``0x012E3C``) **never** ``bal 0x029958``; see ``palette_8964_runner_mirror_re``"
    ),
}

FORMAT_AT_8E90_HYPOTHESIS = {
    "observation": (
        "``0x02A028`` ``lda 0x005C8E90,g0`` loads a **32-bit pointer** from workram; "
        "``0x05CF60`` ``mov g0,r12`` then ``0x05CF74`` ``ldob (r12),g0`` walks format "
        "ASCII via that pointer (not inline bytes at ``+0x30``)."
    ),
    "slot477_frag_len": len(SLOT477_FRAG),
    "slot477_frag": SLOT477_FRAG,
    "note": (
        "Slab likely filled as one runtime blob (``+0x000``..``+0x420``); "
        "``+0x30`` cell holds format-string **address** — writer still OPEN."
    ),
}


def _arena_xrefs() -> list[dict[str, Any]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    rows: list[dict[str, Any]] = []
    for entry in ARENA_SLAB:
        addr = int(entry["vaddr"], 16)
        refs = find_word_refs(words, addr)
        rows.append({**entry, "rom_lda_count": len(refs), "rom_ldas": [f"0x{r:08X}" for r in refs]})
    return rows


def build_report(*, slot: int = 477) -> dict[str, Any]:
    d_sim = _slot477_d_bytecode(None)
    events = compile_format_fragment(SLOT477_FRAG)
    d_count = sum(1 for e in events if e.get("op") == "D")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + arena xref scan — no MAME, no XOR inference",
        "slot": slot,
        "arena_base": f"0x{ARENA_BASE:08X}",
        "arena_slab_span_bytes": 0x420 + 16,
        "arena_slab": _arena_xrefs(),
        "compile_to_run_chain": list(COMPILE_TO_RUN),
        "alt_prewalk_29a4c": list(ALT_PREWALK_29A4C),
        "walk_27130": list(WALK_27130),
        "bind_upload_cluster": list(BIND_UPLOAD_CLUSTER),
        "runner_requirements": RUNNER_REQUIREMENTS,
        "format_at_8e90": FORMAT_AT_8E90_HYPOTHESIS,
        "slot477_if_format_present": {
            "d_handler_count": d_count,
            "bytecode_sim": d_sim,
            "bind_index": d_sim.get("bind_stream_halfwords", [{}])[0] if d_sim else None,
        },
        "open_gaps": [
            "Single runtime fill of arena slab ``0x005C8E60``–``0x005C9280`` (no ROM ``st`` sites)",
            "``0x005C8964`` patched instruction bytes — must chain walk/bind/upload",
            "``0x02A6D0`` wrapper ``r10``/``r9``/``r14`` for tier-B slot 477 merge @ ``0x02A4E0``",
            "``0x20A7B0`` desert compile return — stored @ ``0x012E48``, zero static consumers",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slot", type=int, default=477)
    ap.add_argument(
        "-o",
        "--output",
        default=REPO_ROOT / "out/decomp/palette_8964_runner_chain_re.json",
        type=Path,
    )
    args = ap.parse_args()
    report = build_report(slot=args.slot)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Arena span: 0x{ARENA_BASE:08X} + 0x{report['arena_slab_span_bytes']:X}")
    print(f"Runner @ +0x104 → 0x005C8964")


if __name__ == "__main__":
    main()
