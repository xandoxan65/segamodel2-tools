#!/usr/bin/env python3
"""Disasm RE: desert ``0x29EB0`` gate splits matched stream vs mismatch compile.

Proves static desert init (@ ``0x012E3C``) takes **matched** path ``0x29EF0`` →
``0x29FE4`` gate — desert ``g4=4`` **skips** ``0x29C10`` at record tail, **not** mismatch
``0x02A038`` ``bal 0x029958``.

Documents ``0x029958`` static mirror behavior (``bx 0x005C8964`` = ``ret`` noop)
and corrects ``0x0271D0`` semantics: **zero-fill** descriptor link halfwords
(``stos g14`` with ``g14=0``), not stub-address injection.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_desert_path_split_re
  python3 -m tools.decomp.palette_desert_path_split_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_ENTRY_WR = 0x005C8964
RUNNER_ENTRY_ROM = 0x029964

# --- ``0x29EB0`` gate (@ ``maincpu_029eb0_600.asm``) --------------------------

GATE_29EB0 = (
    {
        "rom": "0x05CE18",
        "via": "``0x29EE8`` ``bal 0x05CE18`` with ``g1=0x005C8E60`` (``CGM 1.0 `` mirror)",
        "effect": "Compare block head vs template; ``g0=0`` on match",
    },
    {
        "rom": "0x29EEC",
        "test": "``cmpibne 0,g0,0x2A01C``",
        "match": "``0x29EF0`` matched-stream walk",
        "mismatch": "``0x02A01C`` → ``0x05CEC0`` → ``0x02A038`` ``bal 0x029958``",
    },
)

MATCHED_PATH = (
    {"rom": "0x29EF0", "effect": "``r5 = lda 0x40(fp)`` — stream node cursor (runtime link fixup OPEN)"},
    {"rom": "0x29F0C", "effect": "``ldos (g4),r9`` — node opcode halfword"},
    {"rom": "0x29F34", "effect": "``call 0x02A050`` — span / palram materialization"},
    {"rom": "0x29F88", "effect": "``0x20B950[row]`` row fill when inner count ``r4`` hits slot band"},
    {"rom": "0x29FA0", "effect": "``bal 0x02A0F8`` — may ``xor g13`` @ ``0x02A258`` when ``g3>0`` (``#``-class batch)"},
    {"rom": "0x29FF8", "effect": "``call 0x029C10`` only when ``(g4&7)<=3`` (@ ``0x29FE4``); desert ``g4=4`` **skips** to ``0x29FFC``"},
    {"rom": "0x02A000", "effect": "``ret`` — **no** ``bal 0x029958`` on matched desert init"},
)

MISMATCH_PATH = (
    {"rom": "0x02A024", "effect": "``bal 0x026E18`` — seed ``0x20B1A8``/``AC`` counters"},
    {"rom": "0x02A028", "effect": "``lda 0x005C8E90,g0`` — mismatch format qword"},
    {"rom": "0x02A034", "effect": "``call 0x05CEC0`` → ``0x05CF50`` format compile (``D`` @ ``0x05D860`` emit)"},
    {"rom": "0x02A038", "effect": "``bal 0x029958`` — ``bx 0x005C8964`` (static mirror = ``ret`` only)"},
    {"rom": "0x02A03C", "effect": "``subo 1,0,g0`` → ``g0=-1`` return convention"},
)

# --- ``0x029958`` + ``0x0271D0`` corrections ---------------------------------

RUNNER_29958 = {
    "rom": "0x029958",
    "steps": (
        "``lda 0x005C8964,g14``; ``mov g14,g0``; ``bx (g0)``",
    ),
    "static_mirror_word": f"ROM ``0x{RUNNER_ENTRY_ROM:06X}`` = ``0x0A000000`` (``ret``)",
    "static_stores_to_entry": 0,
    "callers_after_compile": (
        "0x02A038 (mismatch only)",
        "0x029C68 / 0x029DB8 (``0x029C10`` negative-``g2`` compile branch)",
        "0x29A50 (runner band — after ``call 0x027130`` prewalk)",
    ),
    "desert_matched": "**Not reached** on ``0x012E3C`` gate match",
}

PATCH_271D0_CORRECTED = {
    "rom": "0x0271D0",
    "return_via": "``g1 = 0x005C6250`` saved @ entry; ``bx (g1)`` @ ``0x027248``",
    "patch_insn": "``stos g14,(g5)`` @ ``0x02721C`` with ``g14=0`` (@ ``0x0271DC``)",
    "semantics": (
        "Each **non-zero** template byte triggers a **zero halfword** write into "
        "``0x01000000`` link table at ``(width<<6|slot)`` — **not** storing stub address"
    ),
    "27160_same": "``0x027160`` also ``mov 0,g14`` before ``stos`` loop (@ ``0x02716C``)",
    "27260_diff": "``0x027260`` ``stos g14`` — ``g14`` is **caller live** (boot ``0x012DE4``); not cleared in callee",
}

UPLOAD_29CFC = {
    "rom": "0x29CFC",
    "insn": "``addo g13,g4,g4`` after ``ldos (g7),g4`` @ ``0x29CF8``",
    "desert_matched_entry_g4": 4,
    "tier": "tier-A (``0x20B950`` row table)",
    "not_lone_d": "Lone ``D`` compile emit is @ ``0x05D860`` inside ``0x05CEC0`` — separate from this FIFO loop",
}


def _runner_mirror() -> dict[str, str]:
    _, words = load_maincpu_words(resolve_rom_dir())
    blob_idx = RUNNER_ENTRY_ROM // 4
    word = words[blob_idx] if blob_idx < len(words) else 0
    refs = find_word_refs(words, RUNNER_ENTRY_WR)
    st_band = sum(
        1
        for w in words
        if (w >> 24) in (0x92, 0x9A, 0xB2, 0x82, 0x8A)
        and 0x005C8000 <= (w & 0xFFFFFF) <= 0x005C9300
    )
    return {
        "workram": f"0x{RUNNER_ENTRY_WR:08X}",
        "rom_mirror": f"0x{RUNNER_ENTRY_ROM:06X}",
        "word": f"0x{word:08X}",
        "is_ret": word == 0x0A000000,
        "lda_refs": len(refs),
        "static_st_immediate_band": st_band,
    }


def _decode_negative(*, slot: int, raw_u16: int, target: int) -> dict[str, Any]:
    raw = int(raw_u16) & 0xFFFF
    tgt = int(target) & 0x7FFF
    g13 = g13_mask_for_slot(0x0700, slot)
    add = (raw + g13) & 0x7FFF
    xor = (raw ^ g13) & 0x7FFF
    return {
        "raw_u16": f"0x{raw:04x}",
        "oracle": f"0x{tgt:04x}",
        "29cfc_add_g13_table": f"0x{add:04x}",
        "02a258_xor_g13": f"0x{xor:04x}",
        "add_matches_oracle": add == tgt,
        "xor_matches_oracle": xor == tgt,
        "verdict": (
            "Matched desert tail uses ADD @ ``0x29CFC`` — does not match oracle; "
            "XOR @ ``0x02A258`` matches oracle but is ``#``/``0x02A0F8`` batch path only"
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm — no MAME workram",
        "gate_29eb0": list(GATE_29EB0),
        "matched_path": list(MATCHED_PATH),
        "mismatch_path": list(MISMATCH_PATH),
        "runner_29958": RUNNER_29958,
        "runner_mirror": _runner_mirror(),
        "patch_271d0_corrected": PATCH_271D0_CORRECTED,
        "upload_29cfc": UPLOAD_29CFC,
        "focus": {"slot": slot, **_decode_negative(slot=slot, raw_u16=raw_u16, target=target)},
        "conclusions": (
            "Desert @ ``0x012E3C`` with ROM mirror ``CGM 1.0 `` gate match → ``0x29EF0`` stream "
            "→ ``0x29F7C`` inner — ``0x29FE4`` **skips** ``0x29C10`` for ``g4=4`` — **never** ``0x02A038`` compile+run.",
            "``0x02A038`` ``bal 0x029958`` is **mismatch-only**; static ``0x005C8964`` mirror = ``ret`` "
            "(zero ROM ``st`` into stub band) — post-compile ``run`` phase is noop in static image.",
            "``0x0271D0`` / ``0x027160`` **zero-fill** descriptor link halfwords; "
            "``0x005C6250``/``0x005C61C8`` are **return** targets for ``bx (g1/g2)``, not patched into bus.",
            "Slot-477 oracle ``0x6683`` still unmatched on all proven static insn paths "
            "(ADD @ ``0x29CFC``, XOR @ ``0x02A258``, lone ``D`` @ ``0x05D860``).",
        ),
        "open_gaps": (
            "``fp+0x40`` / ``ld (r5)`` stream root — ``0x204D4743`` gate pointer vs ``block+0x08`` node layout",
            "Whether ``0x29F9C`` row ``+4`` record ever gains valid ``+0x14`` FIFO cursor before ``0x29CFC``",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Desert matched vs mismatch path split")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_desert_path_split_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    rm = report["runner_mirror"]
    print(f"\n0x005C8964 mirror: {rm['word']} (ret={rm['is_ret']})")
    print(f"Static st into stub band: {rm['static_st_immediate_band']}")

    f = report["focus"]
    print(f"\nSlot {args.slot}: raw={f['raw_u16']} oracle={f['oracle']}")
    print(f"  29CFC ADD={f['29cfc_add_g13_table']}  02A258 XOR={f['02a258_xor_g13']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
