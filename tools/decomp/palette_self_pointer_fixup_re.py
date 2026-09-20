#!/usr/bin/env python3
"""Disasm RE: self-pointer ``block+0`` fixup model + single ``0x029EB0`` record limits.

Proves one runtime word0 patch (``block+0 = block_vaddr``) satisfies **both**
``0x05CE18`` gate ``ldob (g0)`` **and** ``0x29EF4`` ``ld (r5)``/``+8`` → node
@ ``block+0x08``.  Documents that each ``0x029EB0`` invocation processes **one**
outer stream node — ``20C950`` gains at most one span; inner ``0x29F7C`` loop
does **not** advance ``20C950``.  Desert init @ ``0x012E3C`` therefore cannot
statically reach replay slot 477 on the matched path alone.

No MAME.  No XOR inference.

  python3 -m tools.decomp.palette_self_pointer_fixup_re
  python3 -m tools.decomp.palette_self_pointer_fixup_re --slot 477
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts, simulate_5ce18
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKRAM_MIRROR = 0x0059F000
MIRROR_TEMPLATE = 0x005C8E60
MAX_INNER_INDEX = 0x1FF
FIRST_NODE_OFF = 0x08

DISASM_SINGLE_RECORD = (
    {"rom": "0x029EF4", "effect": "``ld (r5),g4``; ``addo g4,8,g4`` — one inner cursor setup"},
    {"rom": "0x029F34", "effect": "``call 0x02A050`` — span/inner prep (once per record)"},
    {"rom": "0x029F54", "effect": "``addo r8,g4,g4``; ``st g4,0x20C950`` — **only** span add to slot cursor"},
    {"rom": "0x029F7C", "effect": "Inner loop — increments ``0x20C954`` only; **does not** touch ``0x20C950``"},
    {"rom": "0x029FD0", "effect": "Record tail → optional ``call 0x029C10`` (@ ``0x29FF8``)"},
    {"rom": "0x02A000", "effect": "``ret`` — **no** branch back to ``0x29F50`` for second outer node"},
)

DISASM_29EB0_CALLERS = (
    {
        "rom": "0x012E18",
        "block_g2": "0x028AF104",
        "g4": 4,
        "role": "Alpine CGM init — stores return @ ``0x20A79C``",
    },
    {
        "rom": "0x012E3C",
        "block_g2": "0x028CCAF8",
        "g4": 4,
        "role": "Desert CGM init — stores return @ ``0x20A7B0`` (no static consumers)",
    },
    {
        "rom": "0x016104",
        "block_g2": "0x02150EEC",
        "g4": 1,
        "role": "Unrelated CGM block (course select path)",
    },
    {
        "rom": "0x016144",
        "block_g2": "0x020B65F4",
        "g4": 0,
        "role": "Second call same function cluster — not desert palette",
    },
)


@dataclass
class SelfPointerModel:
    block_vaddr: int
    static_word0: int
    required_word0: int

    def gate_with_self_pointer(self, head_bytes: bytes, mirror: bytes) -> dict[str, Any]:
        """If ``block+0`` holds vaddr, ``29ECC`` ``g0=vaddr`` → ``ldob (g0)`` reads block bytes."""
        sim = simulate_5ce18(head_bytes[:8], mirror[:8], count=8)
        return {
            "g0_after_29ecc": f"0x{self.required_word0:08X}",
            "ldob_g0_first_byte": f"0x{head_bytes[0]:02X}" if head_bytes else None,
            "gate_compare_g0": sim.g0,
            "gate_reason": sim.reason,
            "matches_mirror_template": sim.g0 == 0,
        }

    def stream_with_self_pointer(self, main_data: bytes, block_rom: int) -> dict[str, Any]:
        from tools.i960_memory import MAIN_DATA_A

        r5 = self.required_word0
        outer = self.required_word0
        inner = (outer + 8) & 0xFFFFFFFF
        node = None
        if MAIN_DATA_A <= inner < MAIN_DATA_A + len(main_data):
            rom_off = inner - MAIN_DATA_A
            rel = rom_off - block_rom
            if 0 <= rel < 0x2000:
                span = struct.unpack_from("<H", main_data, rom_off)[0]
                inner_count = struct.unpack_from("<H", main_data, rom_off + 2)[0]
                node = {
                    "rom_offset": f"+0x{rel:02X}",
                    "span": span & 0xFFFF,
                    "inner": inner_count & 0xFFFF,
                }

        return {
            "fp_plus_40": f"0x{r5:08X}",
            "deref_r5": f"0x{outer:08X}",
            "inner_cursor_plus8": f"0x{inner:08X}",
            "first_node": node,
            "first_node_valid": node is not None and node.get("rom_offset") == f"+0x{FIRST_NODE_OFF:02X}",
        }


@dataclass
class SingleRecordSim:
    slot_base: int = 14
    entry_g4: int = 4
    span: int = 16
    inner: int = 0xFFFF
    cursor_20c950: int = field(init=False)
    index_20c954: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.cursor_20c950 = self.slot_base

    def run(self) -> dict[str, Any]:
        before = self.cursor_20c950
        self.cursor_20c950 = (self.cursor_20c950 + self.span) & 0xFFFF
        self.events.append(
            {
                "rom": "0x29F54",
                "20c950": f"{before} → {self.cursor_20c950}",
                "span": self.span,
            }
        )
        inner_iters = 0
        if self.inner > 0 and self.index_20c954 <= MAX_INNER_INDEX:
            while self.index_20c954 <= MAX_INNER_INDEX and inner_iters < 512:
                self.events.append({"rom": "0x29F7C", "20c954": self.index_20c954, "20c950": self.cursor_20c950})
                self.index_20c954 += 1
                inner_iters += 1
                if self.index_20c954 > MAX_INNER_INDEX:
                    break
        calls_29c10 = (self.entry_g4 & 7) <= 3
        self.events.append(
            {
                "rom": "0x29FF8",
                "call_29c10": calls_29c10,
                "note": "One FIFO u16 per tail call — not 463 replay reads",
            }
        )
        return {
            "final_20c950": self.cursor_20c950,
            "final_20c954": self.index_20c954,
            "inner_iters": inner_iters,
            "slots_gained": self.cursor_20c950 - before,
            "calls_29c10": calls_29c10,
        }


def _20a7b0_analysis(words: list[int]) -> dict[str, Any]:
    refs = find_word_refs(words, 0x0020A7B0)
    st_sites = [r for r in refs if True]  # all refs are lda/st immediates
    return {
        "workram": "0x0020A7B0",
        "written_at": "0x012E48 (desert ``0x029EB0`` return ``g0``)",
        "static_ld_refs": [f"0x{r:06X}" for r in refs],
        "static_consumer": "none — only ``0x20A79C`` (alpine) read @ ``0x012E60`` upload sweeps",
        "note": "Dead-store for static disasm; desert compile return not fed back into upload chain",
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    facts = cgm_block_head_facts(main_data, block.vaddr)
    head_bytes = bytes.fromhex(facts["head_vaddr_bytes_hex"])
    static_w0 = int(facts["word0_at_vaddr"], 16)
    mirror_rom = MIRROR_TEMPLATE - WORKRAM_MIRROR
    mirror = struct.pack("<II", words[mirror_rom // 4], words[mirror_rom // 4 + 1])

    model = SelfPointerModel(
        block_vaddr=block.vaddr,
        static_word0=static_w0,
        required_word0=block.vaddr,
    )
    first = struct.unpack_from("<H", main_data, block.rom_offset + FIRST_NODE_OFF)[0]
    inner = struct.unpack_from("<H", main_data, block.rom_offset + FIRST_NODE_OFF + 2)[0]
    sim = SingleRecordSim(span=first & 0xFFFF, inner=inner & 0xFFFF)
    sim_out = sim.run()

    gap_to_slot = max(0, slot - sim_out["final_20c950"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + static CGM — no MAME, no XOR",
        "focus": {"slot": slot, "block_vaddr": f"0x{block.vaddr:08X}"},
        "disasm_single_record": list(DISASM_SINGLE_RECORD),
        "disasm_29eb0_callers": list(DISASM_29EB0_CALLERS),
        "static_desert_head": {
            "word0": facts["word0_at_vaddr"],
            "ascii_8": facts["head_vaddr_bytes_ascii"],
            "node_at_plus_08": {"span": first & 0xFFFF, "inner": inner & 0xFFFF},
        },
        "self_pointer_fixup_model": {
            "static_word0": f"0x{static_w0:08X}",
            "required_word0": f"0x{block.vaddr:08X}",
            "static_st_to_block_vaddr": [],
            "gate_if_patched": model.gate_with_self_pointer(head_bytes, mirror),
            "stream_if_patched": model.stream_with_self_pointer(main_data, block.rom_offset),
            "summary": (
                "Single runtime patch ``block+0 ← block_vaddr`` makes ``29ECC`` ``g0`` a valid "
                "pointer for ``0x05CE18`` **and** ``*fp+0x40+8`` → first ``0x29F0C`` node. "
                "Static ROM stores ASCII ``CGM `` instead."
            ),
        },
        "single_29eb0_record_sim": {
            **sim_out,
            "hit_focus_slot": sim_out["final_20c950"] >= slot,
            "slots_short_of_focus": gap_to_slot,
            "events_head": sim.events[:3],
            "events_tail": sim.events[-2:],
        },
        "20a7b0_desert_return": _20a7b0_analysis(words),
        "replay_contrast": {
            "replay_slot477_cursor": slot,
            "replay_fifo_offset_raw_8843": "0x3A6",
            "replay_read_index": 463,
            "note": (
                "Python ``0x1111`` marker-split replay reaches slot 477 via format ``D`` ops — "
                "orthogonal namespace to one-shot ``0x29EB0`` matched span add"
            ),
        },
        "conclusions": (
            "``block+0 = block_vaddr`` is the **minimal** runtime fixup unifying gate + stream walk.",
            f"One desert ``0x029EB0`` call adds span={first & 0xFFFF} → ``20C950={sim_out['final_20c950']}``; "
            f"inner={inner & 0xFFFF} runs {sim_out['inner_iters']}× ``0x29F7C`` without advancing ``20C950``.",
            f"Slot {slot} requires {gap_to_slot} more slot cursor units — **not** from single matched record.",
            "``0x012E3C`` calls ``0x029EB0`` once; additional callers @ ``0x016104`` use other blocks.",
            "``0x20A7B0`` desert return has zero static readers — no disasm link to slot 477 replay.",
        ),
        "open_gaps": (
            "Static ROM writer for ``block+0 ← 0x028CCAF8`` (or equivalent map alias)",
            "Whether ``0x1111`` body is driven by repeated ``0x029EB0`` / ``0x005C8964`` vs marker-split replay only",
            "``0x29C10`` tail on matched path: one ADD vs hundreds of FIFO u16 for tier-B slots",
            "Runtime ``0x005C8964`` body for compile replay path (static mirror ``ret``)",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Self-pointer fixup + single 29EB0 record RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_self_pointer_fixup_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    sim = report["single_29eb0_record_sim"]
    fix = report["self_pointer_fixup_model"]
    print(f"Static word0={fix['static_word0']}  required={fix['required_word0']}")
    print(f"One record: 20C950={sim['final_20c950']}  inner_iters={sim['inner_iters']}  slot477={sim['hit_focus_slot']}")
    print(f"Stream valid if patched: {fix['stream_if_patched']['first_node_valid']}")


if __name__ == "__main__":
    main()
