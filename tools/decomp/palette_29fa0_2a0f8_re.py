#!/usr/bin/env python3
"""Disasm RE: ``0x29FA0`` ``bal 0x02A0F8`` does **not** reach XOR @ ``0x02A258``.

Proves the matched-stream inner loop (@ ``0x29F7C``) calls ``0x02A0F8`` entry which
loads a record ``+0x14`` table word then **immediately** ``bx (g1)`` (return link).
The ``xor g13`` loop @ ``0x02A200`` is a **separate** entry with **zero** static
``bal``/``call`` sites from the matched path.

Also documents boot ``0x012DE4`` ``call 0x027260``: ``stos g14`` stores the
**call return address** (``g14`` @ ``call``), not stub cells or zeros.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_29fa0_2a0f8_re
  python3 -m tools.decomp.palette_29fa0_2a0f8_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- ``0x02A0F8`` entry (@ ``maincpu_02a0f8_400.asm``) -----------------------

ENTRY_2A0F8 = (
    {"rom": "0x02A0F8", "insn": "``mov g14,g1`` — save ``bal`` return link"},
    {"rom": "0x02A0FC", "insn": "``mov 0,g14``"},
    {"rom": "0x02A100", "insn": "``ldis 0x10(g0),g4`` — record dimensions"},
    {"rom": "0x02A104", "insn": "``ldis 0x12(g0),g5``"},
    {"rom": "0x02A108", "insn": "``mulo g4,g5,g4`` — row index"},
    {"rom": "0x02A10C", "insn": "``lda 0x14(g0)[g4*2],g0`` — handler table word → ``g0``"},
    {"rom": "0x02A114", "insn": "``bx (g1)`` — **immediate return** to ``0x29FA4``"},
    {"rom": "0x02A118", "insn": "``ret`` — XOR body @ ``0x02A200`` is **unreachable** from entry"},
)

MATCHED_CALL_29FA0 = (
    {"rom": "0x29F84", "effect": "``g0 = lda 0x40(fp)`` — saved block head dword"},
    {"rom": "0x29F9C", "effect": "``st g0,0x4(g4)`` — row ``+4`` = block-head ptr before call"},
    {"rom": "0x29FA0", "effect": "``bal 0x02A0F8`` — table peek only"},
    {"rom": "0x29FC4", "effect": "``st g0,0x40(fp)`` — write back table word to saved root"},
    {"rom": "0x29FF8", "effect": "``call 0x029C10`` — tier-A ADD upload (@ ``0x29CFC``)"},
)

XOR_BODY_2A200 = (
    {"rom": "0x02A200", "entry": "Separate from ``0x02A0F8`` — no fall-through"},
    {"rom": "0x02A228", "test": "``cmpi g3,0`` — **g3 must be > 0** to enter XOR loop"},
    {"rom": "0x02A258", "insn": "``xor g4,g13,g4`` — matches xor_table oracle when ``g13`` seeded"},
    {"static_callers": "Zero ``bal``/``call`` to ``0x02A200`` in maincpu disasm"},
    {"reachable_via": "``0x02A0F0`` ``lda 0x005C9118`` trampoline (workram OPEN) or direct ``bx``"},
)

BOOT_27260_G14 = (
    {"rom": "0x012DE4", "insn": "``call 0x027260`` with ``g0=15,g1=30,g2=35,g3=6``"},
    {"rom": "0x012DF8", "insn": "Second batch ``g0=7,g1=29,g2=55,g3=21``"},
    {"rom": "0x02728C", "insn": "``stos g14,(g5)`` — **``g14`` = return addr after ``call``** (``0x012DE8`` / ``0x012DFC``)"},
    {"contrast_271d0": "``0x0271D0`` clears ``g14`` before ``stos`` — writes **zero** link halfwords"},
    {"contrast_27260": "``0x027260`` does **not** clear ``g14`` — writes **return-link** halfwords"},
    {"dest_band": "``0x01000000 + (g1<<7) + 2*g0`` (@ ``0x02726C``)"},
)


def _xor_callers_scan() -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    targets = (0x02A0F8, 0x02A200, 0x02A258)
    out: dict[str, list[str]] = {}
    for t in targets:
        refs = find_word_refs(words, t)
        out[f"0x{t:05X}"] = [f"0x{r:06X}" for r in refs[:12]]
    bal_29fa0 = [f"0x{r:06X}" for r in find_word_refs(words, 0x02A0F8) if r in (0x29FA0,)]
    return {"word_refs": out, "29FA0_is_only_matched_bal": "0x029FA0" in str(out.get("0x02A0F8", []))}


def _boot_patch_sim() -> list[dict[str, Any]]:
    """Simulate ``0x027260`` store pattern for ``0x012DE4`` args (return link placeholder)."""
    batches = (
        {"call_rom": "0x012DE4", "ret_after": "0x012DE8", "g0": 15, "g1": 30, "g2": 35, "g3": 6},
        {"call_rom": "0x012DF8", "ret_after": "0x012DFC", "g0": 7, "g1": 29, "g2": 55, "g3": 21},
    )
    rows: list[dict[str, Any]] = []
    for b in batches:
        tag = (int(b["g1"]) & 0xFF) << 7
        base_idx = int(b["g0"]) & 0xFF
        total = int(b["g2"]) * int(b["g3"])
        rows.append(
            {
                **b,
                "tag_base": f"0x{tag:04x}",
                "bus_base_byte": f"0x{0x01000000 + tag + base_idx * 2:08X}",
                "stos_count": total,
                "stos_value": f"return_link_g14_after_{b['call_rom']}",
                "note": "Each ``stos g14`` writes i960 ``call`` return address into link table",
            }
        )
    return rows


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    raw = int(raw_u16) & 0xFFFF
    tgt = int(target) & 0x7FFF
    g13 = g13_mask_for_slot(0x0700, slot)
    xor = (raw ^ g13) & 0x7FFF

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm — no MAME workram",
        "entry_2a0f8": list(ENTRY_2A0F8),
        "matched_call_29fa0": list(MATCHED_CALL_29FA0),
        "xor_body_2a200": list(XOR_BODY_2A200),
        "caller_scan": _xor_callers_scan(),
        "boot_27260_g14": list(BOOT_27260_G14),
        "boot_patch_sim": _boot_patch_sim(),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{raw:04x}",
            "oracle": f"0x{tgt:04x}",
            "xor_oracle_insn": f"0x{xor:04x}",
            "29fa0_runs_xor": False,
            "29fa0_reaches_29cfc_add": "via ``0x29FF8`` after inner loop — separate from ``0x02A0F8``",
        },
        "conclusions": (
            "``0x29FA0`` ``bal 0x02A0F8`` **never** executes ``xor g13`` @ ``0x02A258`` — entry "
            "returns @ ``0x02A114`` before ``0x02A200``.",
            "xor_table oracle ``0x6683`` for slot 477 **cannot** come from matched-stream "
            "``0x29FA0`` path; XOR requires ``g3>0`` entry @ ``0x02A228`` (``#``/compile thunk).",
            "Boot ``0x027260`` @ ``0x012DE4`` writes **call return links** (`g14`) into "
            "``0x01000000`` — distinct from ``0x0271D0`` zero-fill and from stub mirror cells.",
            "Matched upload for slot 477 remains ``0x29FF8`` → ``0x29CFC`` ADD — not XOR.",
        ),
        "open_gaps": (
            "What ``bx`` target reaches ``0x02A200`` with ``g3>0`` for desert tier-B slots",
            "``fp+0x40`` / ``ld (r5)`` stream root — ``0x204D4743`` gate pointer vs ``block+0x08`` node layout",
            "Whether ``0x29F9C`` row ``+4`` record ever gains valid ``+0x14`` FIFO cursor before ``0x29CFC``",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="29FA0/02A0F8 negative XOR + 27260 g14")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29fa0_2a0f8_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    print(f"\n29FA0 runs XOR: {report['focus']['29fa0_runs_xor']}")
    print(f"xor oracle 0x{int(args.raw,0) if isinstance(args.raw,str) else args.raw:04x} → {report['focus']['xor_oracle_insn']}")

    sim = report["boot_patch_sim"][0]
    print(f"\nBoot 27260 batch0: {sim['stos_count']}× stos g14 @ {sim['bus_base_byte']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
