#!/usr/bin/env python3
"""Disasm trace: ``0x029EB0`` exit paths — overflow compile vs matched inner tail.

Clarifies when ``0x02A004`` / ``0x02A01C`` compile diagnostic format strings vs
the matched ``0x29EF0`` stream walk and ``0x29FD0`` → ``0x029C10`` tail.
Documents ROM-mirror format bytes @ ``0x005C8E70`` / ``0x005C8E90``.

No MAME, no XOR inference.

  python3 -m tools.decomp.palette_overflow_matched_tail_re
  python3 -m tools.decomp.palette_overflow_matched_tail_re --focus-slot 477
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts, simulate_5ce18
from tools.i960_scan import load_maincpu_words
from tools.model2_cgm_1111 import replay_1111_record
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    load_colorxlat_from_main_data,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKRAM_ROM_MIRROR = 0x0059F000
WORKRAM_OVERFLOW_FMT = 0x005C8E70
WORKRAM_MISMATCH_FMT = 0x005C8E90
WORKRAM_GATE_TEMPLATE = 0x005C8E60
MAX_INNER_INDEX = 0x1FF


def _rom_mirror_ascii(words: list[int], vaddr: int, limit: int = 64) -> str:
    rom = vaddr - WORKRAM_ROM_MIRROR
    blob = b"".join(
        struct.pack("<I", words[(rom + i) // 4])
        for i in range(0, limit, 4)
        if 0 <= (rom + i) // 4 < len(words)
    )
    return "".join(chr(b) if 32 <= b < 127 else "." for b in blob[:limit])


# --- Disasm exit paths from ``0x029EB0`` ---------------------------------------

EXIT_PATHS: tuple[dict[str, Any], ...] = (
    {
        "id": "entry_overflow_compile",
        "trigger_rom": "0x029ED8",
        "trigger": "``cmpibg 0x20C954,0x1FF`` **before** gate — index already > 511 at record entry",
        "branch_rom": "0x02A004",
        "format_workram": f"0x{WORKRAM_OVERFLOW_FMT:08X}",
        "format_rom_mirror": f"0x{WORKRAM_OVERFLOW_FMT - WORKRAM_ROM_MIRROR:08X}",
        "then": "``bal 0x026E18`` → ``lda 0x005C8E70`` → ``call 0x05CEC0`` → ``bal 0x029958``",
        "format_role": "Diagnostic ``Color Group Full !! [%08x]`` — **not** ``0x1111`` payload",
        "slot_477_relevant": False,
        "note": "Desert init enters with ``0x20C954=0`` — this branch does **not** fire @ ``0x012E3C``",
    },
    {
        "id": "gate_mismatch_compile",
        "trigger_rom": "0x029EEC",
        "trigger": "``0x05CE18`` compare ``g0 != 0`` after 8-byte lexicographic walk",
        "branch_rom": "0x02A01C",
        "format_workram": f"0x{WORKRAM_MISMATCH_FMT:08X}",
        "format_rom_mirror": f"0x{WORKRAM_MISMATCH_FMT - WORKRAM_ROM_MIRROR:08X}",
        "then": "``bal 0x026E18`` → ``lda 0x005C8E90`` → ``call 0x05CEC0`` → ``bal 0x029958``",
        "format_role": "Diagnostic ``Not CGM Data !! [%08x]`` — **not** ``0x1111`` payload",
        "slot_477_relevant": False,
        "note": "Desert block head matches ROM mirror ``CGM 1.0 `` template — takes **matched** path",
    },
    {
        "id": "matched_stream_walk",
        "trigger_rom": "0x029EF0",
        "trigger": "Gate ``g0==0`` (@ ``0x029EEC``)",
        "branch_rom": "0x029EF0",
        "then": "``0x29F0C`` span read → ``0x02A050`` → ``0x29F7C`` inner loop → ``0x29FD0`` tail",
        "slot_477_relevant": True,
        "note": "Primary desert static path @ ``0x012E3C``",
    },
    {
        "id": "span_u16_wrap_compile",
        "trigger_rom": "0x029F24",
        "trigger": "``cmpibg (0x20C950+span),0xFFFF`` — **u16** cursor wrap, not slot>511",
        "branch_rom": "0x02A004",
        "format_workram": f"0x{WORKRAM_OVERFLOW_FMT:08X}",
        "then": "Same overflow compile as entry path",
        "slot_477_relevant": False,
        "note": "First node span=16 → ``20C950=30`` — does not trigger",
    },
    {
        "id": "inner_tail_29fd0",
        "trigger_rom": "0x29FD0",
        "trigger": (
            "Inner count ``r4==0`` (@ ``0x29F68``), or ``0x20C954>0x1FF`` before loop (@ ``0x29F78``), "
            "or inner loop exhausted ``0x20C954`` past ``0x1FF`` (@ ``0x29FCC`` fall-through)"
        ),
        "branch_rom": "0x29FD0",
        "then": "Patch row @ ``0x20B950[r7*8]``; ``0x29FE4`` ``cmpibl 3,(g4&7)`` → ``call 0x029C10`` only when ``(g4&7) <= 3``",
        "slot_477_relevant": True,
        "note": "Desert ``g4=4`` → **skips** ``0x29C10`` (@ ``0x29FFC``) — see ``palette_29fe4_g4_gate_re``",
    },
)


@dataclass
class FirstNodeSim:
    """Simulate first static node @ desert ``block+0x08`` on matched path."""

    slot_base: int = 14
    cursor_20c950: int = 14
    index_20c954: int = 0
    entry_g4: int = 4
    span: int = 16
    inner: int = 0xFFFF
    events: list[dict[str, Any]] = field(default_factory=list)

    def run(self) -> dict[str, Any]:
        before = self.cursor_20c950
        self.cursor_20c950 = (self.cursor_20c950 + self.span) & 0xFFFF
        self.events.append(
            {
                "rom": "0x29F54",
                "effect": f"20C950 {before} → {self.cursor_20c950} (span={self.span})",
            }
        )

        inner_iters = 0
        if self.inner == 0:
            self.events.append({"rom": "0x29F68", "effect": "inner=0 → skip to 0x29FD0"})
        elif self.index_20c954 > MAX_INNER_INDEX:
            self.events.append({"rom": "0x29F78", "effect": "20C954>0x1FF before loop → 0x29FD0"})
        else:
            while self.index_20c954 <= MAX_INNER_INDEX and inner_iters < 512:
                self.events.append(
                    {
                        "rom": "0x29F7C",
                        "index_20c954": self.index_20c954,
                        "20c950": self.cursor_20c950,
                    }
                )
                self.index_20c954 += 1
                inner_iters += 1
                if self.index_20c954 > MAX_INNER_INDEX:
                    break
            self.events.append(
                {
                    "rom": "0x29FCC",
                    "effect": f"fall-through after {inner_iters} inner iters (20C954={self.index_20c954})",
                }
            )

        calls_29c10 = (self.entry_g4 & 7) <= 3
        self.events.append(
            {
                "rom": "0x29FE4",
                "entry_g4": self.entry_g4,
                "entry_g4_and_7": self.entry_g4 & 7,
                "call_29c10": calls_29c10,
            }
        )

        return {
            "final_20c950": self.cursor_20c950,
            "final_20c954": self.index_20c954,
            "inner_29f7c_iters": inner_iters,
            "hit_slot_477": self.cursor_20c950 >= 477,
            "calls_29c10_at_tail": calls_29c10,
            "events_head": self.events[:4],
            "events_tail": self.events[-3:],
        }


def _desert_gate(main_data: bytes, words: list[int]) -> dict[str, Any]:
    facts = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    mirror_rom = WORKRAM_GATE_TEMPLATE - WORKRAM_ROM_MIRROR
    mirror = struct.pack(
        "<II",
        words[mirror_rom // 4],
        words[mirror_rom // 4 + 1],
    )
    head = bytes.fromhex(facts["head_vaddr_bytes_hex"])
    cmp = simulate_5ce18(head, mirror)
    return {
        "block_vaddr": facts["vaddr"],
        "head_ascii": facts["head_vaddr_bytes_ascii"],
        "mirror_template_ascii": facts["compare_vs_rom_mirror_template"]["template_ascii"],
        "gate_g0": cmp.g0,
        "path": "matched" if cmp.g0 == 0 else "mismatch_compile",
    }


def _format_mirror_report(words: list[int]) -> list[dict[str, Any]]:
    rows = []
    for name, va in (
        ("gate_template", WORKRAM_GATE_TEMPLATE),
        ("overflow_compile", WORKRAM_OVERFLOW_FMT),
        ("mismatch_compile", WORKRAM_MISMATCH_FMT),
    ):
        rows.append(
            {
                "id": name,
                "workram": f"0x{va:08X}",
                "rom_mirror": f"0x{va - WORKRAM_ROM_MIRROR:08X}",
                "ascii_preview": _rom_mirror_ascii(words, va, 48),
            }
        )
    return rows


def _replay_oracle(main_data: bytes) -> dict[str, Any]:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == 0x1111:
            payload = main_data[off : off + rec_len]
            break
    else:
        return {"error": "no 0x1111"}
    st = PaletteState()
    st._install_default_lumaram()
    load_colorxlat_from_main_data(st, main_data)
    r = replay_1111_record(st, payload, trace_slots=frozenset({477}))
    row = r.trace[0] if r.trace else None
    return {
        "method": "Python format-walk oracle (not hardware)",
        "slot_477": row,
        "gap": (
            "Replay slot counter reaches 477 via marker-split FIFO; "
            f"matched-path ``20C950`` after first node sim = 30"
        ),
    }


def build_report(*, focus_slot: int = 477) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)

    sim = FirstNodeSim()
    first_node = sim.run()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM mirror — no MAME, no XOR",
        "focus_slot": focus_slot,
        "desert_gate": _desert_gate(main_data, words),
        "exit_paths": list(EXIT_PATHS),
        "format_mirror_strings": _format_mirror_report(words),
        "first_node_matched_sim": first_node,
        "path_conclusions": [
            "``0x02A004`` / ``0x02A01C`` compile **diagnostic format strings** from ROM mirror — not ``0x1111`` body",
            "Desert @ ``0x012E3C``: gate match → ``0x029EF0``; **not** mismatch ``Not CGM Data`` compile",
            "First node ``inner=0xFFFF`` → 512× ``0x29F7C`` → ``0x29FD0`` → ``0x029C10`` (``g4=4``)",
            f"After first node: ``20C950={first_node['final_20c950']}`` — slot {focus_slot} **not** reached via span cursor",
            "``0x29CFC`` ADD consumes FIFO built during compile/run — static link to fifo+0x3A6 ``0x8843`` OPEN",
        ],
        "replay_oracle": _replay_oracle(main_data),
        "open_gaps": [
            "How ``0x029C10`` FIFO cursor @ ``record+0x14`` reaches replay fifo+0x3A6 for slot 477",
            "Additional matched-path nodes needed to advance ``20C950`` from 30 → 477 (static chain OPEN)",
            "``0x005C8964`` runner must replay ``0x1111`` format bytecode — not overflow/mismatch compile strings",
            "Tier-B lone ``D`` decode after ``0x29CFC`` ADD vs Python ``xor_table`` still unproven",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="029EB0 overflow vs matched tail RE")
    parser.add_argument("--focus-slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_overflow_matched_tail_re.json",
    )
    args = parser.parse_args()

    report = build_report(focus_slot=args.focus_slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    gate = report["desert_gate"]
    sim = report["first_node_matched_sim"]
    print(f"Desert gate: {gate['path']} (g0={gate['gate_g0']})")
    print(
        f"First node: 20C950={sim['final_20c950']} "
        f"29F7C iters={sim['inner_29f7c_iters']} "
        f"29C10={sim['calls_29c10_at_tail']}"
    )
    print(f"Overflow format: {report['format_mirror_strings'][1]['ascii_preview'][:40]!r}")


if __name__ == "__main__":
    main()
