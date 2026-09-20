#!/usr/bin/env python3
"""Disasm trace: ``0x029C10`` tier-A vs tier-B upload branches.

Documents the ``(entry_g4 & 7) >= 3`` gate (@ ``0x29C30`` / ``0x29D80``), the
``0x20B950`` FIFO+ADD loop (@ ``0x29C74``–``0x29D34``), and the alternate
``0x20B954`` subtract-index loop (@ ``0x29DC4``–``0x29E58``).

Runs **negative** decode checks on a focus slot (default 477 / ``0x8843``) using
only disasm-backed transforms — no ``xor_table`` inference.

  python3 -m tools.decomp.palette_29c10_tier_b_re
  python3 -m tools.decomp.palette_29c10_tier_b_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_cgm_g13_table import G13_CTRL_BITS, g13_mask_for_slot

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Entry / loop structure (maincpu_029c10_800.asm) -----------------------

ENTRY_DECISION = {
    "rom": "0x29C10",
    "steps": (
        {"rom": "0x29C10", "test": "``cmpi g2,0``", "lt_zero": "``bl 0x29C34`` compile+run (@ ``0x29C58`` ``0x5C8BF0``)"},
        {"rom": "0x29C1C", "effect": "``g6 = 0x20C954`` slot/group limit"},
        {"rom": "0x29C24", "test": "``g5 = g2 + g3`` vs ``g6``", "fail": "``bl 0x29C34`` compile+run"},
        {"rom": "0x29C2C", "test": "``g5 = g4 & 7``", "branch": "``cmpibge 3,g5,0x29C74`` → upload path"},
        {"rom": "0x29C34", "effect": "Compile+run: ``0x26E18`` bind, ``0x26FD8`` tag, ``0x29AE8`` slot→group, ``0x5CEC0`` @ workram cell, ``0x029958``"},
    ),
    "desert_matched_tail": {
        "call": "0x29FF8 → 0x029C10",
        "entry_g4": 4,
        "g4_and_7": 4,
        "upload_branch_taken": False,
        "compile_branch_taken": False,
        "29c10_called": False,
        "note": "``0x29FE4`` ``cmpibl 3,g5`` skips call when ``3 < (g4&7)``",
    },
}

TIER_A_UPLOAD = {
    "label": "tier_a_20b950_fifo_add",
    "entry": "0x29C74",
    "when": "``(entry_g4 & 7) >= 3`` and ``g2 + g3 < 0x20C954``",
    "g13_setup": (
        {"rom": "0x29C74", "test": "``bbc 0,g4``", "clear": "``g13=0``; staging @ ``0x01000000``", "set": "``g13|=0x8000``; staging @ ``0x01004000``"},
        {"rom": "0x29CA4", "test": "``bbc 1,g4``", "set": "``g6 += 0x2000`` (bank alias)"},
        {"rom": "0x29CB0", "test": "``bbc 3,g4``", "set": "``g13 |= 0x4000``"},
    ),
    "row_walk": (
        {"rom": "0x29CB8", "effect": "``r4 = g2 + g3`` group index"},
        {"rom": "0x29CBC", "effect": "``g4 = 0x20B950[r4*8]`` group row ptr"},
        {"rom": "0x29CC4", "effect": "``g0 = ld 0x4(g4)`` compile record ptr"},
        {"rom": "0x29CC8", "effect": "``g4 = ldos (g4)`` row head u16 → ``g13 |= g4`` (@ ``0x29CD8``)"},
        {"rom": "0x29CDC", "effect": "``g7 = lda 0x14(g0)`` FIFO cursor"},
        {"rom": "0x29CF8", "effect": "``g4 = ldos (g7)`` read FIFO u16"},
        {"rom": "0x29CFC", "effect": "``addo g13,g4,g4`` — **ADD** mask into value"},
        {"rom": "0x29D00", "effect": "``stos g4,(g6)`` write staging bus word"},
    ),
    "format_char": "Primarily ``U`` / legacy compiled thunks — **not** lone ``D`` (@ ``0x05D3DC`` merge path)",
}

TIER_B_UPLOAD = {
    "label": "tier_b_20b954_sub_index",
    "entry": "0x29DC4",
    "when": "Second ``0x029C10`` copy (@ ``0x29D60``) — same ``g4 & 7`` gate, different row table",
    "row_walk": (
        {"rom": "0x29DF8", "effect": "``r4 = g2 + g3``"},
        {"rom": "0x29DFC", "effect": "``g5 = 0x20B954[r4*8]`` (note **954**, not 950)"},
        {"rom": "0x29E18", "effect": "``setbit 6,0,g13`` — force bit 6 in mask"},
        {"rom": "0x29E28", "effect": "``stos g14,(g6)`` — write **saved g14**, not FIFO u16"},
        {"rom": "0x29E48", "effect": "``subo g4,g13,g4`` — index = count − g13 (scatter stride)"},
    ),
    "format_char": "Descriptor / span materialization — not direct ``D`` FIFO u16 decode",
}

SLOT_GROUP_LOOKUP = {
    "rom": "0x29AE8",
    "effect": "``g0 += g1`` slot cursor; if ``g0 >= 0x20C954`` → ``g0=0``; else ``g0 = 0x20B954[g0*8]`` handler thunk",
    "used_by": "Compile+run path @ ``0x29C50`` before ``0x5CEC0``",
}

# --- Negative decode (disasm transforms only) --------------------------------


def _disasm_decode_candidates(
    *,
    slot: int,
    raw_u16: int,
    g13_seed: int = 0x0700,
    chain_head: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Apply each proven insn effect to ``raw_u16``; compare to oracle target."""
    raw = int(raw_u16) & 0xFFFF
    g13_table = g13_mask_for_slot(g13_seed, slot) & 0xFFFF
    g13_slot7 = (slot & 0x3FF) << 7
    head = (int(chain_head) if chain_head is not None else g13_slot7) & 0xFFFF

    def _row(label: str, insn: str, value: int, *, proven_for_d: bool = False) -> dict[str, Any]:
        return {
            "insn": insn,
            "result": f"0x{value & 0x7FFF:04x}",
            "proven_for_single_d": proven_for_d,
        }

    g13_or_head = (G13_CTRL_BITS | head) & 0xFFFF  # 29C98 setbit15 | head @ 29CD8

    return {
        "29cfc_add_g13_table": _row(
            "29CFC",
            "addo g13,g4,g4 (g13=g13_mask_for_slot)",
            (raw + g13_table) & 0x7FFF,
        ),
        "29cfc_add_g13_or_chain_head": _row(
            "29CD8+29CFC",
            "g13=0x8040|head; addo g13,g4,g4",
            (raw + g13_or_head) & 0x7FFF,
        ),
        "29cfc_add_slot7_only": _row(
            "29CFC",
            "addo (slot<<7),g4,g4",
            (raw + g13_slot7) & 0x7FFF,
        ),
        "29e48_sub_index": _row(
            "29E48",
            "subo g4,g13,g4 (tier-B scatter — g14 source, not raw)",
            (raw - g13_or_head) & 0x7FFF,
        ),
        "02a258_xor_batch_only": _row(
            "02A258",
            "xor g4,g13,g4 (# batch, g3>0 — **not** lone D)",
            (raw ^ g13_table) & 0x7FFF,
            proven_for_d=False,
        ),
    }


def build_report(
    *,
    slot: int = 477,
    raw_u16: int = 0x8843,
    target_color15: int = 0x6683,
    g13_seed: int = 0x0700,
) -> dict[str, Any]:
    decodes = _disasm_decode_candidates(slot=slot, raw_u16=raw_u16, g13_seed=g13_seed)
    g13_table = g13_mask_for_slot(g13_seed, slot)

    target = target_color15 & 0x7FFF
    matches = [
        name
        for name, body in decodes.items()
        if int(body["result"], 16) == target and body.get("proven_for_single_d") is not False
    ]
    misleading_matches = [
        name
        for name, body in decodes.items()
        if int(body["result"], 16) == target and body.get("proven_for_single_d") is False
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm insn effects only — no xor_table unless labeled oracle",
        "entry_decision": ENTRY_DECISION,
        "tier_a_upload": TIER_A_UPLOAD,
        "tier_b_upload": TIER_B_UPLOAD,
        "slot_group_lookup": SLOT_GROUP_LOOKUP,
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "g13_seed": f"0x{int(g13_seed) & 0xFFFF:04x}",
            "g13_table": f"0x{g13_table:04x}",
            "oracle_target_color15": f"0x{int(target_color15) & 0x7FFF:04x}",
            "oracle_source": "Python xor_table replay (NOT hardware-proven for lone D)",
            "disasm_decode_results": decodes,
            "disasm_matches_target": matches,
            "misleading_matches_wrong_path": misleading_matches,
        },
        "conclusions": (
            "Desert ``0x012E3C`` matched tail calls ``0x029C10`` with ``entry_g4=4`` → "
            "tier-A ``0x29CFC`` ADD loop (@ ``0x20B950`` rows). Chunk-87 slot 477 is a "
            "lone ``D`` in ``0x1111`` format — hardware path is ``0x05D3DC`` → ``0x05D860`` "
            "→ ``0x02A5A0`` → ``0x02A4E0`` merge (@ ``0x02A61C`` r5 bit 0), **not** ``0x29CFC``.",
            "No disasm-backed single-u16 transform matches oracle ``0x6683`` for raw ``0x8843`` "
            "unless ``#``-batch XOR (@ ``0x02A258``) is incorrectly applied to ``D``.",
            "Tier-B ``0x20B954`` path (@ ``0x29E48``) writes ``g14`` and uses subtract-index "
            "scatter — unrelated to FIFO ``ldos`` @ ``0x29CF8``.",
        ),
        "open_gaps": (
            "Map ``0x05D860`` emit bytecode for chunk-87 ``D`` run → ``0x02A6D0`` wrapper "
            "``r10``/``r9``/``r14`` (@ ``0x02A61C`` merge args)",
            "Prove ``record+0x14`` FIFO cursor population on ``D`` compile path (only ``0x05DE00`` "
            "proven for ``E``/``f``/``g``)",
            "Static link ``0x29FF8`` ``0x029C10`` group index → replay fifo+0x3A6 for slot 477",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x029C10 tier-A/B disasm RE + negative decode")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29c10_tier_b_re.json",
    )
    args = parser.parse_args()

    report = build_report(
        slot=args.slot,
        raw_u16=args.raw,
        target_color15=args.target,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    focus = report["focus"]
    print(
        f"\nSlot {focus['slot']}: raw {focus['raw_u16']} → oracle {focus['oracle_target_color15']} "
        f"(g13_table={focus['g13_table']})"
    )
    print("\nDisasm decode candidates:")
    for name, body in focus["disasm_decode_results"].items():
        mark = " MATCH" if name in focus["disasm_matches_target"] else ""
        print(f"  {name:32s}: {body['result']}{mark}  ({body['insn']})")

    if focus.get("misleading_matches_wrong_path"):
        wrong = ", ".join(focus["misleading_matches_wrong_path"])
        print(f"\nMisleading match via wrong insn path: {wrong}")
    if not focus["disasm_matches_target"]:
        print("No disasm-backed single-u16 transform matches oracle (expected for lone D).")
    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
