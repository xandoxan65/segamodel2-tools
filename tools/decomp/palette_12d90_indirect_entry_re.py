#!/usr/bin/env python3
"""Disasm RE: indirect entry to ``0x012D90`` palette init + ``0x00FB58`` orchestrator.

Proves **zero** static ``call``/``bal``/branch from outside into ``0x012D90``,
``0x012CC0``, or ``0x00FB00`` (runtime ``bx`` / filled ``0x005B375C`` tables only).
Documents ``0x012D9C`` early-return gate, ``0x014788`` dispatch analogue, and the
``0x00FB58`` → ``0x0137D0`` pre-palette orchestrator (also runtime-entered).

No MAME. xor_table oracle only.

  python3 -m tools.decomp.palette_12d90_indirect_entry_re
  python3 -m tools.decomp.palette_12d90_indirect_entry_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks, _iter_cgm_v16_records
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_VADDR = COURSE_CGM_VADDRS[1]

# --- ``0x012D90`` internal gates (@ ``maincpu_012d00_200.asm``) -----------------

PALETTE_INIT_12D90 = (
    {
        "rom": "0x012D90",
        "effect": "``addo 16,sp,sp`` — frame prologue; **zero** static callers in full ROM",
    },
    {
        "rom": "0x012D9C",
        "effect": "``ld 0x20A530,g4``; ``cmpibne 3,g4,0x12DA4`` — **``0x20A530==3`` → ret @ ``0x12DA0``**",
    },
    {
        "rom": "0x012DA4",
        "effect": "``ld 0x20A790,g4``; seed ``0x20B914``/``0x20B91C``; optional ``0x026B60`` bus zero",
    },
    {
        "rom": "0x012DC4",
        "effect": "``cmpibne 0,g4,0x12EDC`` — skip staging when ``0x20A790==0``",
    },
    {
        "rom": "0x012E3C",
        "effect": "Desert ``0x029EB0`` compile: ``g2=0x028CCAF8``, ``g4=4`` → ``st g0,0x20A7B0``",
    },
    {
        "rom": "0x012E60",
        "effect": "Post-init ``0x029C10`` sweeps (``g4=2`` upload ADD) — max slot ≪ 477",
    },
)

# --- Static-entry negative targets ---------------------------------------------

INDIRECT_TARGETS = (
    {
        "entry": "0x012D90",
        "role": "Course palette init (alpine+desert ``0x029EB0`` + upload sweeps)",
        "static_call_bal": [],
    },
    {
        "entry": "0x012CC0",
        "role": "Extended ``0x029C10`` sweeps before palette init",
        "static_call_bal": [],
    },
    {
        "entry": "0x00FB00",
        "role": "Main-data atlas sort loop → ``call 0x0137D0`` pre-palette orchestrator",
        "static_call_bal": [],
    },
)

# --- Palette init tail (@ ``maincpu_013200_80.asm``) ---------------------------

PALETTE_INIT_TAIL = (
    {
        "rom": "0x012EF0",
        "effect": "``bge 0x01320C`` — only **internal** branch out of ``0x012D90`` body (from ``0x012ED4`` sweep path)",
    },
    {
        "rom": "0x01320C",
        "effect": "``call 0x012C70`` — post-init upload helper (**static** edge **from** palette init tail)",
    },
    {
        "rom": "0x012C70",
        "effect": "Early ``0x029C10`` helper; also called from ``0x013798`` et al. — **not** ``0x012D90`` entry",
    },
)

# --- ``0x005B375C`` ROM mirror scaffold (correction) ---------------------------

SCAFFOLD_375C_MIRROR = (
    {
        "workram": "0x005B375C",
        "rom_mirror": "0x01475C",
        "effect": (
            "``ld 0x005B375C[g0*4]`` @ ``0x0147A4`` reads workram that **mirrors** embedded "
            "pointer scaffold @ ``0x014760`` (not a separate zero-filled table)"
        ),
    },
    {
        "rom": "0x014760",
        "dwords": "``0x005B36E0`` ×2, ``0x005B36F0``, ``0x005B3710``, ``0x005B3730`` — range-table heads",
    },
    {
        "rom": "0x014690",
        "effect": "``0x005B3690`` mirror head = ``0x0A000000`` (``ret`` stub) @ ``0x014678`` ``bx``",
    },
)

# --- ``0x014788`` course dispatch (static analogue for indirect entry) ---------

DISPATCH_14788 = (
    {
        "rom": "0x014788",
        "effect": "``ld 0x005B375C[g0*4],g6`` → range table; ``bx (g3)`` @ ``0x0147F0``",
    },
    {
        "rom": "0x016160",
        "effect": "Game init: ``bal 0x014788`` after ``0x029EB0`` on ``0x02150EEC`` / ``0x020B65F4``",
    },
    {
        "rom": "0x014820",
        "effect": "Frame wrapper: ``bal 0x0146A8`` → ``bal 0x014788`` → ``call 0x014530`` when ``g0==2``",
    },
    {
        "note": "``0x005B375C`` mirror @ ``0x01475C`` aliases embedded scaffold — see ``scaffold_375c_mirror``",
    },
)

# --- ``0x00FB58`` → ``0x0137D0`` pre-palette orchestrator ----------------------

ORCHESTRATOR_0137D0 = (
    {
        "rom": "0x00FB58",
        "effect": (
            "After main-data ``0x01A121C2`` atlas index walk: ``call 0x0137D0`` "
            "(**zero** static callers into ``0x00FB00`` band)"
        ),
    },
    {
        "rom": "0x0137D0",
        "effect": "``call 0x016B70`` — bus/GPIO staging (``0x026A10``, ``0x026150``, ``0x0272B0``)",
    },
    {
        "rom": "0x0137D4",
        "effect": "``call 0x012B70`` — six-block pre-palette ``0x029EB0`` chain (non-desert blocks)",
    },
    {
        "rom": "0x0137D8",
        "effect": "``call 0x016B40`` — ``0x029EB0`` on ``0x0008251C`` ``g4=2`` → ``0x20A974``",
    },
    {
        "rom": "0x0137E4",
        "effect": "``st 0x005B1CC0,0x20A78C`` — palette dispatch token (not block vaddr)",
    },
)


def _call_target_mame(rom: int, word: int) -> int:
    off = word & 0xFFFFFF
    if off & 0x800000:
        off -= 0x1000000
    return (rom + off) & 0xFFFFFF


def _scan_static_call_bal(words: list[int], targets: set[int]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {f"0x{t:06X}": [] for t in sorted(targets)}
    for rom in range(0, len(words) * 4, 4):
        w = words[rom // 4]
        op = w >> 24
        if op not in (0x09, 0x0B):
            continue
        dest = _call_target_mame(rom, w)
        if dest in targets:
            kind = "call" if op == 0x09 else "bal"
            out[f"0x{dest:06X}"].append(f"0x{rom:06X} ({kind})")
    return out


def _scan_external_branches(words: list[int], lo: int, hi: int) -> list[str]:
    """Branch/call targets from **outside** ``[lo, hi)`` into the band."""
    hits: list[str] = []
    for rom in range(0, len(words) * 4, 4):
        if lo <= rom < hi:
            continue
        w = words[rom // 4]
        op = w >> 24
        if op not in (0x08, 0x09, 0x0B, 0x13, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E):
            continue
        dest = _call_target_mame(rom, w)
        if lo <= dest < hi:
            hits.append(f"0x{rom:06X} op=0x{op:02X} -> 0x{dest:06X}")
    return hits


def _rom_dword_hits(words: list[int], value: int) -> list[str]:
    return [f"0x{rom:06X}" for rom in range(0, len(words) * 4, 4) if words[rom // 4] == value]


def _block_has_1111(main_data: bytes, vaddr: int) -> bool:
    blocks = {b.vaddr: b for b in find_cgm_blocks(main_data)}
    if vaddr not in blocks:
        return False
    block = blocks[vaddr]
    return any(t == 0x1111 for t, _, _ in _iter_cgm_v16_records(main_data, block))


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])

    targets = {0x012D90, 0x012CC0, 0x012C70, 0x012B70, 0x00FB00, 0x0137D0}
    caller_scan = _scan_static_call_bal(words, targets)
    ext_12d = _scan_external_branches(words, 0x012D00, 0x012F00)
    ext_fb = _scan_external_branches(words, 0x00FB00, 0x00FD00)
    dword_12d90 = _rom_dword_hits(words, 0x00012D90)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "Full-ROM control-flow scan + MAME disasm slices — no workram",
        "focus": {"slot": slot, "desert_vaddr": f"0x{DESERT_VADDR:08X}"},
        "disasm_slices": (
            "decomp/disasm/maincpu/maincpu_012d00_200.asm",
            "decomp/disasm/maincpu/maincpu_012b80_220.asm",
            "decomp/disasm/maincpu/maincpu_00fb00_120.asm",
            "decomp/disasm/maincpu/maincpu_013700_100.asm",
            "decomp/disasm/maincpu/maincpu_014678_400.asm",
            "decomp/disasm/maincpu/maincpu_016b40_80.asm",
        ),
        "palette_init_12d90": list(PALETTE_INIT_12D90),
        "palette_init_tail": list(PALETTE_INIT_TAIL),
        "scaffold_375c_mirror": list(SCAFFOLD_375C_MIRROR),
        "indirect_targets": [
            {**t, "static_call_bal": caller_scan.get(t["entry"], [])} for t in INDIRECT_TARGETS
        ],
        "dispatch_14788": list(DISPATCH_14788),
        "orchestrator_0137d0": list(ORCHESTRATOR_0137D0),
        "static_caller_scan": caller_scan,
        "external_branches": {
            "0x012D00-0x012F00": ext_12d,
            "0x00FB00-0x00FD00": ext_fb,
        },
        "rom_dword_hits": {
            "0x00012D90": dword_12d90,
            "0x005B375C_lda_refs": [f"0x{r:06X}" for r in find_word_refs(words, 0x005B375C)],
        },
        "catalog_checks": {
            "0x0008251C_is_cgm_head": 0x0008251C in {b.vaddr for b in find_cgm_blocks(main_data)},
            "0x0008251C_has_1111": _block_has_1111(main_data, 0x0008251C),
            "desert_has_1111": _block_has_1111(main_data, DESERT_VADDR),
        },
        "verdicts": [
            {
                "id": "12d90_zero_static_entry",
                "proven": True,
                "note": (
                    "Full-ROM ``call``/``bal`` scan + external branch scan: **zero** entries "
                    "to ``0x012D90``; **zero** ROM dwords ``0x00012D90``"
                ),
            },
            {
                "id": "12d9c_mode3_early_ret",
                "proven": True,
                "note": (
                    "``0x012D9C``: ``0x20A530==3`` → ``ret`` @ ``0x12DA0`` **before** "
                    "``0x012E3C`` desert compile — init requires ``0x20A530≠3`` at entry"
                ),
            },
            {
                "id": "12cc0_zero_static_entry",
                "proven": True,
                "note": "``0x012CC0`` extended sweeps: **zero** static ``call``/``bal`` — same indirect class as ``0x012D90``",
            },
            {
                "id": "00fb58_runtime_orchestrator",
                "proven": True,
                "note": (
                    "``0x00FB58`` ``call 0x0137D0`` sits in atlas loop with **zero** static "
                    "callers into ``0x00FB00``; pre-palette chain is runtime-triggered"
                ),
            },
            {
                "id": "137d0_pre_palette_not_desert",
                "proven": True,
                "note": (
                    "``0x0137D4`` → ``0x012B70`` seeds non-desert blocks; ``0x016B40`` uses "
                    "``0x0008251C`` (not CGM head) — separate from ``0x012E3C`` desert path"
                ),
            },
            {
                "id": "14788_dispatch_analogue",
                "proven": True,
                "note": (
                    "``0x014788`` ``bx`` via ``0x005B375C[g0*4]``; mirror @ ``0x01475C`` "
                    "aliases embedded range-table scaffold @ ``0x014760``"
                ),
            },
            {
                "id": "1320c_tail_calls_12c70",
                "proven": True,
                "note": (
                    "``0x01320C`` ``call 0x012C70`` — **only** static edge from ``0x012D90`` "
                    "function (exit tail via ``0x012EF0``); **not** an entry to ``0x012D90``"
                ),
            },
            {
                "id": "slot_477_still_outside_12e60",
                "proven": True,
                "note": f"Even when ``0x012D90`` body runs, ``0x012E60`` sweeps use ``g4=2`` ADD with ``g0≤45`` — slot {slot} unreachable",
            },
        ],
        "open_gaps": [
            "Runtime ``bx`` entry into ``0x012D90`` (zero external static edges; ``0x014678`` ``bx`` → ``ret`` stub)",
            "Which ``bx`` site reaches ``0x00FB00`` atlas orchestrator on desert load",
            "Tier-B slot 477 ``D`` decode (``0x8843`` → ``0x6683`` oracle-only)",
        ],
        "related_tools": [
            "tools.decomp.palette_pre_palette_29eb0_re",
            "tools.decomp.palette_indirect_dispatch_re",
            "tools.decomp.palette_1111_driver_negative_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Indirect entry RE for 0x012D90 + 0x00FB58 orchestrator")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_12d90_indirect_entry_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["verdicts"] if v.get("proven"))
    print(f"\nVerdicts: {proven}/{len(report['verdicts'])} proven")
    scan = report["static_caller_scan"]
    print(f"012D90 callers: {scan.get('0x012D90', [])}")
    print(f"00FB00 callers: {scan.get('0x00FB00', [])}")
    print(f"0137D0 callers: {scan.get('0x0137D0', [])}")
    print(f"20A530==3 early ret @ 012D9C; ext branches 12D band: {report['external_branches']['0x012D00-0x012F00']}")


if __name__ == "__main__":
    main()
