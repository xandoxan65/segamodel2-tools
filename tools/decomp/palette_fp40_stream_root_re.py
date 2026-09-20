#!/usr/bin/env python3
"""Disasm RE: ``fp+0x40`` stream root vs ``0x05CE18`` gate identity model.

Formalizes why ``0x29ED4`` stores block dword ``0x204D4743`` while ``0x29EF4``
``ld (r5)`` needs an outer link cell whose value ``V`` satisfies ``V+8`` → first
``0x29F0C`` node (@ desert ``block+0x08``).  Evaluates static ROM candidates;
does **not** infer XOR/decode.

  python3 -m tools.decomp.palette_fp40_stream_root_re
  python3 -m tools.decomp.palette_fp40_stream_root_re --slot 477
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import (
    DISASM_29EB0_BRANCH,
    STREAM_NODE_FIELDS,
    cgm_block_head_facts,
    simulate_5ce18,
)
from tools.i960_memory import MAIN_DATA_A
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKRAM_MIRROR = 0x0059F000
MIRROR_TEMPLATE_ROM = 0x005C8E60 - WORKRAM_MIRROR

DISASM_FP40 = (
    {"rom": "0x029ECC", "effect": "``g0 = lda 0(g2)`` — first block dword (not ``g2`` vaddr)"},
    {"rom": "0x029ED4", "effect": "``st g0,0x40(fp)`` — ``fp+0x40`` = head dword ``0x204D4743`` static"},
    {"rom": "0x029EDC", "effect": "``g1=0x005C8E60; g2=8; bal 0x05CE18`` — gate uses **same** ``g0`` as pointer"},
    {"rom": "0x029EF0", "effect": "``r5 = lda 0x40(fp)`` — outer link cell address"},
    {"rom": "0x029EF4", "effect": "``g4 = ld (r5)``; ``addo g4,8,g4`` — inner cursor before span read"},
    {"rom": "0x029F1C", "effect": "``st g4,(r5)`` — persist inner cursor in outer cell"},
    {"rom": "0x029F9C", "effect": "``st g0,0x4(g4)`` where ``g0`` reloaded from ``fp+0x40`` (@ ``0x29F84``)"},
    {"rom": "0x029CC4", "effect": "``g0 = ld 0x4(row)`` — same dword for ``0x29CDC`` ``+0x14`` FIFO cursor"},
)

# Required arithmetic for first desert node span @ ``block+0x08`` (verified from ROM).
FIRST_NODE_ROM_OFF = 0x08


@dataclass
class StreamRootModel:
    id: str
    r5_value: int
    r5_label: str
    deref_u32: int | None
    inner_after_plus8: int | None
    first_node_match: bool
    span_inner: tuple[int, int] | None
    record_plus14_u32: int | None
    plus14_is_pointer: bool
    static_proven: bool
    notes: list[str]


def _is_pointer(v: int) -> bool:
    return (MAIN_DATA_A <= v < MAIN_DATA_A + 0xC0_0000) or (0x005C0000 <= v <= 0x005FFFFF)


def _read_node(main_data: bytes, block_rom: int, off: int) -> tuple[int, int] | None:
    if off + 4 > len(main_data):
        return None
    span = struct.unpack_from("<H", main_data, block_rom + off)[0]
    inner = struct.unpack_from("<H", main_data, block_rom + off + 2)[0]
    return span & 0xFFFF, inner & 0xFFFF


def _deref_u32(main_data: bytes, addr: int) -> int | None:
    if not (MAIN_DATA_A <= addr < MAIN_DATA_A + len(main_data)):
        return None
    off = addr - MAIN_DATA_A
    if off + 4 > len(main_data):
        return None
    return struct.unpack_from("<I", main_data, off)[0]


def _evaluate_model(
    *,
    model_id: str,
    r5: int,
    label: str,
    main_data: bytes,
    block_vaddr: int,
    block_rom: int,
    static_proven: bool,
    notes: list[str],
) -> StreamRootModel:
    deref = _deref_u32(main_data, r5)
    inner = (deref + 8) if deref is not None else None
    node: tuple[int, int] | None = None
    first_match = False
    if inner is not None and MAIN_DATA_A <= inner < MAIN_DATA_A + len(main_data):
        off = inner - MAIN_DATA_A - block_rom
        if 0 <= off < 0x2000:
            got = _read_node(main_data, block_rom, off)
            expect = _read_node(main_data, block_rom, FIRST_NODE_ROM_OFF)
            if got and expect:
                node = got
                first_match = got == expect
    record_plus14: int | None = None
    if deref is not None and deref != 0:
        # ``record+0x14`` read uses ``g0`` = ``fp+0x40`` stored dword (@ ``0x29F9C``).
        if MAIN_DATA_A <= deref < MAIN_DATA_A + len(main_data):
            off = deref - MAIN_DATA_A
            if off + 0x18 <= len(main_data):
                record_plus14 = struct.unpack_from("<I", main_data, off + 0x14)[0]
        elif deref == int.from_bytes(b"CGM ", "little"):
            # Static stored value — ``+0x14`` is block ``+0x14`` if misinterpreted as base.
            record_plus14 = struct.unpack_from("<I", main_data, block_rom + 0x14)[0]

    return StreamRootModel(
        id=model_id,
        r5_value=r5,
        r5_label=label,
        deref_u32=deref,
        inner_after_plus8=inner,
        first_node_match=first_match,
        span_inner=node,
        record_plus14_u32=record_plus14,
        plus14_is_pointer=_is_pointer(record_plus14) if record_plus14 is not None else False,
        static_proven=static_proven,
        notes=notes,
    )


def _gate_pointer_tension(block_vaddr: int, head_dword: int, head_bytes: bytes, mirror: bytes) -> dict[str, Any]:
    """``0x05CE18`` uses ``g0`` as address; ``0x29ED4`` stores dword **value**, not vaddr."""
    semantic = simulate_5ce18(head_bytes[:8], mirror[:8], count=8)
    return {
        "gate_entry_g0": f"0x{head_dword:08X}",
        "gate_semantic_compare": {
            "g0_exit": semantic.g0,
            "reason": semantic.reason,
            "bytes_compared": semantic.bytes_compared,
            "note": (
                "Byte compare of block head vs mirror selects matched path — "
                "independent of whether ``ldob (0x204D4743)`` is valid"
            ),
        },
        "pointer_tension": {
            "05ce30_reads": f"``ldob (g0)`` with g0=0x{head_dword:08X}",
            "main_data_mapped": MAIN_DATA_A <= head_dword < MAIN_DATA_A + 0xC0_0000,
            "required_for_stream": (
                f"outer cell ``*r5`` must equal ``block_vaddr-8`` = 0x{block_vaddr - 8:08X} "
                f"so ``*r5+8`` → node @ block+0x{FIRST_NODE_ROM_OFF:02X}"
            ),
            "static_block_word0": f"0x{head_dword:08X} (``CGM ``) — **not** block_vaddr-8",
            "fp40_stores_same": True,
        },
    }


def _link_byte1_model(block_vaddr: int, block_rom: int, main_data: bytes) -> dict[str, Any]:
    link = struct.unpack_from("<I", main_data, block_rom + 0x0C)[0]
    b = link.to_bytes(4, "little")
    off_b1 = b[1]
    target = block_vaddr + off_b1
    target_rom = block_rom + off_b1
    preview = main_data[target_rom : target_rom + 8]
    return {
        "link_dword": f"0x{link:08X}",
        "byte1_offset": f"0x{off_b1:02X}",
        "block_plus_byte1_vaddr": f"0x{target:08X}",
        "bytes_at_target": preview.hex(),
        "ascii_preview": "".join(chr(x) if 32 <= x < 127 else "." for x in preview),
        "note": (
            "Partial decode only: byte1 ``0x7C`` == ``block+0x7C`` (``0x1111`` marker band). "
            "Does **not** satisfy ``ld (r5)`` then ``+8`` → ``block+0x08`` without extra fixup"
        ),
    }


def _slot477_static_reach(cursor_20c950: int, span: int, inner: int) -> dict[str, Any]:
    after_span = (cursor_20c950 + span) & 0xFFFF
    inner_cap = min(inner, 512) if inner > 0x1FF else inner
    return {
        "20c950_before": cursor_20c950,
        "span": span,
        "20c950_after_span": after_span,
        "inner_iters_first_node": inner_cap,
        "slot_477_reached": after_span >= 477,
        "slots_to_477": max(0, 477 - after_span),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    head = cgm_block_head_facts(main_data, block.vaddr)
    head_dword = int(head["word0_at_vaddr"], 16)
    head_bytes = bytes.fromhex(head["head_vaddr_bytes_hex"])
    mirror_rom = MIRROR_TEMPLATE_ROM
    mirror = struct.pack(
        "<II",
        words[mirror_rom // 4] if mirror_rom // 4 < len(words) else 0,
        words[mirror_rom // 4 + 1] if mirror_rom // 4 + 1 < len(words) else 0,
    )

    required_outer = block.vaddr - 8
    models = [
        _evaluate_model(
            model_id="static_fp40_head_dword",
            r5=head_dword,
            label="``fp+0x40`` as disasm stores (@ ``0x29ED4``)",
            main_data=main_data,
            block_vaddr=block.vaddr,
            block_rom=block.rom_offset,
            static_proven=True,
            notes=[
                "``r5=0x204D4743`` — outside main_data map; ``ld (r5)`` invalid in static model",
                "``29F9C`` row ``+4`` and ``29CDC`` ``+0x14`` inherit same dword",
            ],
        ),
        _evaluate_model(
            model_id="block_vaddr_as_r5",
            r5=block.vaddr,
            label="hypothesis: ``fp+0x40`` holds block vaddr (runtime fixup)",
            main_data=main_data,
            block_vaddr=block.vaddr,
            block_rom=block.rom_offset,
            static_proven=False,
            notes=[
                f"``*r5`` = head dword; ``*r5+8`` = 0x{block.vaddr + 8:08X} = block+0x08 **if** outer holds vaddr",
                f"Requires ``*block+0`` = 0x{required_outer:08X}`` — static has ``0x{head_dword:08X}``",
            ],
        ),
        _evaluate_model(
            model_id="link_cell_plus_0c",
            r5=block.vaddr + 0x0C,
            label="hypothesis: outer cell @ ``block+0x0C`` link dword",
            main_data=main_data,
            block_vaddr=block.vaddr,
            block_rom=block.rom_offset,
            static_proven=False,
            notes=["``0x22F77C00`` high nibble ≠ main_data block prefix ``0x28``"],
        ),
        _evaluate_model(
            model_id="required_outer_value",
            r5=block.vaddr,
            label="required ``*r5`` value for first node (math)",
            main_data=main_data,
            block_vaddr=block.vaddr,
            block_rom=block.rom_offset,
            static_proven=False,
            notes=[f"Needs ``*({block.vaddr:08X})`` = 0x{required_outer:08X}; static ``0x{head_dword:08X}``"],
        ),
    ]

    first = _read_node(main_data, block.rom_offset, FIRST_NODE_ROM_OFF) or (0, 0)
    reach = _slot477_static_reach(14, first[0], first[1])

    model_rows = []
    for m in models:
        row = {
            "id": m.id,
            "r5": f"0x{m.r5_value:08X}",
            "label": m.r5_label,
            "deref_u32": f"0x{m.deref_u32:08X}" if m.deref_u32 is not None else None,
            "inner_after_plus8": f"0x{m.inner_after_plus8:08X}" if m.inner_after_plus8 else None,
            "first_node_span_inner_match": m.first_node_match,
            "observed_span_inner": list(m.span_inner) if m.span_inner else None,
            "record_plus14_u32": f"0x{m.record_plus14_u32:08X}" if m.record_plus14_u32 is not None else None,
            "plus14_is_pointer": m.plus14_is_pointer,
            "static_proven": m.static_proven,
            "notes": m.notes,
        }
        model_rows.append(row)

    refs_head = [f"0x{r:06X}" for r in find_word_refs(words, head_dword)]
    refs_vaddr = [f"0x{r:06X}" for r in find_word_refs(words, block.vaddr)]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + static CGM ROM — no MAME, no XOR inference",
        "focus": {"slot": slot, "block_vaddr": f"0x{block.vaddr:08X}"},
        "disasm_fp40": list(DISASM_FP40),
        "disasm_29eb0_branch": list(DISASM_29EB0_BRANCH),
        "stream_node_fields": list(STREAM_NODE_FIELDS),
        "gate_identity_model": _gate_pointer_tension(block.vaddr, head_dword, head_bytes, mirror),
        "link_byte1_partial": _link_byte1_model(block.vaddr, block.rom_offset, main_data),
        "stream_root_models": model_rows,
        "first_node_reach_slot": reach,
        "maincpu_word_refs": {
            "head_dword_204D4743": refs_head[:8],
            "block_vaddr": refs_vaddr[:8],
            "static_st_to_fp40_in_29eb0": ["0x029ED4", "0x029FC4"],
            "static_st_patches_block_word0": [],
        },
        "conclusions": (
            "``0x05CE18`` gate and ``0x29EF4`` stream walk disagree on ``g0``/``fp+0x40`` semantics: "
            "gate compares block **bytes**; ``fp+0x40`` stores head **dword** ``0x204D4743``.",
            f"First ``0x29F0C`` node requires ``*outer+8`` @ block+0x{FIRST_NODE_ROM_OFF:02X} — needs "
            f"``*r5``=0x{required_outer:08X}; static block+0 has ``0x{head_dword:08X}``.",
            "Only ``block_vaddr_as_r5`` (runtime fixup) aligns node layout; static ``29ED4`` path fails ``ld (r5)``.",
            f"First-node sim: ``20C950={reach['20c950_after_span']}`` after span {first[0]} — slot {slot} not reached.",
            "``29F9C`` record ``+4`` / ``29CDC`` ``+0x14`` inherit broken ``g0`` in static model — OPEN runtime fixup.",
        ),
        "open_gaps": (
            "Who rewrites ``block+0`` or ``fp+0x40`` to block vaddr before ``0x29EF4`` (no static ``st`` proof)",
            "Full ``0x22F77C00`` link semantics beyond byte1→``block+0x7C`` partial",
            "Whether ``0x1111`` payload chain continues past first ``inner=0xFFFF`` node without ``0x005C8964``",
            f"Map ``20C950`` progression to replay slot {slot} (@ FIFO ``0x3A6`` in format-walk order)",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="fp+0x40 stream root vs gate identity RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_fp40_stream_root_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    gate = report["gate_identity_model"]["pointer_tension"]
    reach = report["first_node_reach_slot"]
    winning = [m for m in report["stream_root_models"] if m["first_node_span_inner_match"]]
    print(f"Required *r5: {gate['required_for_stream']}")
    print(f"First-node match models: {[m['id'] for m in winning] or 'none (static)'}")
    print(f"20C950 after first span: {reach['20c950_after_span']}  slot477={reach['slot_477_reached']}")


if __name__ == "__main__":
    main()
