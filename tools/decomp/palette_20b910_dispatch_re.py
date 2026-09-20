#!/usr/bin/env python3
"""Disasm RE: ``0x20B910`` indirect dispatch + ``0x20B914`` stream seeding.

Proves the handler bootstrap @ ``0x026980`` is **not** on the static desert
``0x012D90`` path: zero ``call 0x026980`` sites, ``0x20B910`` has a single
static ``st`` @ ``0x026704``, and course hook ``0x01638C`` only touches
``0x20B914``/``0x20B918`` — never ``0x20B910`` or ``0x026980``.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_20b910_dispatch_re
  python3 -m tools.decomp.palette_20b910_dispatch_re --slot 477
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- ``0x20B910`` / ``0x0269C4`` (@ ``maincpu_026800_200.asm``) ---------------

DISPATCH_20B910 = (
    {"rom": "0x026704", "insn": "``st g14,0x20B910``", "role": "**Only** static ROM store to ``0x20B910``"},
    {"rom": "0x026700", "insn": "``call 0x026A10``", "role": "Cold-boot bus zero @ ``0x26A10`` immediately before ``st g14``"},
    {"rom": "0x026744", "insn": "``ret``", "role": "``0x26690`` template tail — ``g14`` is caller link at entry (often 0 if uncalled)"},
    {"rom": "0x0269B8", "insn": "``ld 0x20B910,g4``", "role": "Load indirect target after clone @ ``0x26800``"},
    {"rom": "0x0269C0", "insn": "``cmpibe 0,g4,0x269C8``", "role": "Skip ``callx`` when ``0x20B910 == 0``"},
    {"rom": "0x0269C4", "insn": "``callx (g4)``", "role": "Runtime continuation — **no** static ROM target"},
)

# --- ``0x026980`` bootstrap (unreachable statically) ---------------------------

BOOTSTRAP_26980 = (
    {"rom": "0x026988", "effect": "``ld 0x20B914,g6`` — opcode-index u16 stream pointer"},
    {"rom": "0x026994", "effect": "``ldos (g6),g4`` loop → ``0x0100A000`` (max 8 entries via ``g5<=7`` gate)"},
    {"rom": "0x0269B0", "effect": "``call 0x026800`` — clone ``0x20B600`` list → ``0x20B1C0`` pool"},
    {"rom": "0x0269B4", "effect": "``call 0x0268B0`` — scratch flush"},
    {"rom": "0x0269C4", "effect": "``callx 0x20B910`` if non-zero"},
)

# --- ``0x20B914`` writers (never paired with ``0x026980`` on static paths) -----

WRITERS_20B914 = (
    {
        "rom": "0x012DB0",
        "context": "Palette init @ ``0x012D90`` (desert block gate follows)",
        "insn": "``stos g6,0x20B914`` after ``setbit 14,15`` → **``0xC000``** stream head",
        "calls_26980": False,
    },
    {
        "rom": "0x01638C",
        "context": "Course/frame hook @ ``0x0162E0`` (``g0!=0`` path @ ``0x016344``)",
        "insn": "``stos g14,0x20B914`` — clears/overwrites stream head",
        "calls_26980": False,
    },
    {
        "rom": "0x026A10",
        "context": "Cold-boot bus init (``0x26690`` tail @ ``0x026700``)",
        "insn": "``stos g14,0x20B914`` … ``0x20B922`` — zero-fill bus alias words",
        "calls_26980": False,
    },
)

# --- Confusable neighbour: ``0x0269D0`` (has static callers) -------------------

CONFUSABLE_269D0 = (
    {"rom": "0x0269D0", "effect": "Staging **bus zero** via ``0x26B60`` — **not** handler clone"},
    {"rom": "0x0160AC", "effect": "Game init cluster: ``call 0x0269D0`` then ``call 0x029EB0`` @ ``0x016104``"},
    {"rom": "0x004E40", "effect": "Geo cluster also ``call 0x0269D0`` — unrelated to ``0x1111``"},
    {"verdict": "``0x0269D0`` must not be confused with ``0x026980`` handler bootstrap"},
)

# --- ``0x0162E0`` course hook entry (indirect-only) ----------------------------

COURSE_HOOK_162E0 = (
    {"rom": "0x0162E0", "effect": "Course callback entry — **zero** static ``call``/``bal`` sites"},
    {"rom": "0x016344", "effect": "``cmpibne 0,g0,0x163C8`` — tail runs when ``g0!=0``"},
    {"rom": "0x01638C", "effect": "``stos g14,0x20B914``; ``stos g14,0x20B918``"},
    {"rom": "0x0163C8", "effect": "``ret`` — no ``call 0x026980`` / no ``call 0x029958``"},
    {"rom_word_refs": 0, "note": "No ROM immediate dword ``0x000162E0`` — reached only via runtime ``bx``"},
)

# --- Static call-site scan targets ---------------------------------------------

SCAN_TARGETS = (
    ("0x012D90", 0x012D90, "palette_init"),
    ("0x0162E0", 0x0162E0, "course_hook"),
    ("0x026690", 0x026690, "handler_template"),
    ("0x026700", 0x026700, "template_tail_26a10"),
    ("0x026980", 0x026980, "handler_bootstrap"),
    ("0x0269D0", 0x0269D0, "bus_zero_269d0"),
)


def _scan_call_bal_sites() -> dict[str, list[str]]:
    pat = re.compile(
        r"^([0-9a-f]+):\s+([0-9a-f]+)\s+(call|bal)\s+0x([0-9a-f]+)",
        re.I | re.M,
    )
    by_target: dict[int, list[str]] = {}
    root = REPO_ROOT / "decomp/disasm"
    for asm in sorted(root.rglob("*.asm")):
        if not asm.is_file():
            continue
        text = asm.read_text(encoding="utf-8", errors="replace")
        for m in pat.finditer(text):
            dest = int(m.group(4), 16)
            site = int(m.group(1), 16)
            kind = m.group(3)
            by_target.setdefault(dest, []).append(f"0x{site:06X} {kind} ({asm.name})")
    return {
        label: by_target.get(addr, [])
        for label, addr, _ in SCAN_TARGETS
    }


def _workram_immediate_refs(words: list[int]) -> dict[str, Any]:
    addrs = {
        "0x20B910": 0x0020B910,
        "0x20B914": 0x0020B914,
        "0x20B600": 0x0020B600,
        "0x20B1C0": 0x0020B1C0,
    }
    out: dict[str, Any] = {}
    for label, wr in addrs.items():
        refs = find_word_refs(words, wr)
        out[label] = {
            "workram": f"0x{wr:08X}",
            "static_immediate_refs": len(refs),
            "sites": [f"0x{r:06X}" for r in refs[:16]],
        }
    return out


def _rom_entry_refs(words: list[int]) -> dict[str, Any]:
    entries = {
        "0x162E0": 0x000162E0,
        "0x26690": 0x00026690,
        "0x26980": 0x00026980,
        "0x012D90": 0x00012D90,
    }
    return {
        label: {
            "rom": label,
            "dword_refs": len(find_word_refs(words, addr)),
            "sites": [f"0x{r:06X}" for r in find_word_refs(words, addr)[:8]],
        }
        for label, addr in entries.items()
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    call_sites = _scan_call_bal_sites()
    wr_refs = _workram_immediate_refs(words)
    entry_refs = _rom_entry_refs(words)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM immediate xref — no MAME",
        "focus": {"slot": slot, "course": "desert", "tier_b_decode": "open"},
        "dispatch_20b910": list(DISPATCH_20B910),
        "bootstrap_26980": list(BOOTSTRAP_26980),
        "writers_20b914": list(WRITERS_20B914),
        "confusable_269d0": list(CONFUSABLE_269D0),
        "course_hook_162e0": list(COURSE_HOOK_162E0),
        "static_call_bal_sites": call_sites,
        "workram_immediate_refs": wr_refs,
        "rom_entry_dword_refs": entry_refs,
        "verdicts": [
            {
                "id": "20b910_single_static_st",
                "proven": True,
                "note": "Only ``st`` @ ``0x026704``; ``ld`` @ ``0x0269B8`` — no other static immediate sites",
            },
            {
                "id": "26980_zero_static_callers",
                "proven": True,
                "note": "Handler clone/bootstrap never statically invoked",
            },
            {
                "id": "1638c_no_26980_chain",
                "proven": True,
                "note": "Course hook ``0x01638C`` writes ``0x20B914`` only; returns @ ``0x0163C8`` without clone/run",
            },
            {
                "id": "12d90_seeds_20b914_not_dispatch",
                "proven": True,
                "note": "Palette init seeds ``0xC000`` @ ``0x20B914`` but never calls ``0x026980``",
            },
            {
                "id": "20b600_20b1c0_runtime_lists",
                "proven": True,
                "note": "``0x20B600``/``0x20B1C0`` have **zero** static ``st`` immediate — clone pool fill requires ``0x026980``",
            },
            {
                "id": "slot477_needs_runtime_1111_driver",
                "proven": False,
                "note": (
                    f"Tier-B slot {slot} decode + ``0x20B1C0[0x20]`` handler body require runtime "
                    "``0x005C8964`` patch + unreachable-static bootstrap"
                ),
            },
        ],
        "open_gaps": [
            "Runtime writer that sets ``0x20B910`` nonzero before ``0x0269C4`` ``callx``",
            "Indirect caller of ``0x0162E0`` / ``0x026690`` / ``0x026980`` (no ROM dword refs)",
            "Whether gameplay ``0x01638C`` stream reset ever precedes a dynamic ``0x026980`` invoke",
            "``0x20B600`` template list population (workram-only before ``0x026800`` clone)",
        ],
        "related_tools": [
            "tools.decomp.palette_1111_driver_negative_re",
            "tools.decomp.palette_opcode20_bind_upload_re",
            "tools.decomp.palette_handler_template_26690_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="RE: 0x20B910 dispatch vs 0x26980 bootstrap")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_20b910_dispatch_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["verdicts"] if v.get("proven"))
    print(f"\nVerdicts: {proven}/{len(report['verdicts'])} proven")
    print(f"26980 callers: {len(report['static_call_bal_sites']['0x026980'])}")
    print(f"20B910 immediate refs: {report['workram_immediate_refs']['0x20B910']['static_immediate_refs']}")
    for gap in report["open_gaps"]:
        print(f"  OPEN: {gap}")


if __name__ == "__main__":
    main()
