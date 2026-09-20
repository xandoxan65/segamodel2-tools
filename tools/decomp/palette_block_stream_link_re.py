#!/usr/bin/env python3
"""Disasm + ROM layout: desert block ``+0x0C`` link ``0x22F77C00`` and stream nodes.

Validates static CGM bytes against ``0x29F0C``/``0x29F50`` node layout before the
``0x1111`` payload.  Does **not** infer XOR/decode.

  python3 -m tools.decomp.palette_block_stream_link_re
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_memory import MAIN_DATA_A
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks, _iter_cgm_v16_records
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

DISASM_NODE_READ = (
    {"rom": "0x29EF4", "effect": "``ld (r5),g4`` — inner cursor from saved ``fp+0x40`` chain"},
    {"rom": "0x29F00", "effect": "``addo g4,8,g4`` — skip 8-byte node prefix"},
    {"rom": "0x29F0C", "effect": "``ldos (g4),r9`` → span ``r8``"},
    {"rom": "0x29F50", "effect": "``ldos (g5),r4`` — inner loop count"},
    {"rom": "0x29F58", "effect": "``lda 0x2(g5),g5`` — advance +4 bytes past span+inner"},
    {"rom": "0x29F1C", "effect": "``st g4,(r5)`` — persist inner cursor in outer link cell"},
)


@dataclass
class StaticNode:
    rom_offset: int
    span: int
    inner: int
    link_dword: int
    link_bytes: str
    offset_byte1: int  # second LE byte of link dword


@dataclass
class PrefixWalk:
    slot_base: int = 14
    cursor_20c950: int = 14
    index_20c954: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


def _read_node(main_data: bytes, block_base: int, off: int) -> StaticNode | None:
    if off + 12 > len(main_data):
        return None
    span = struct.unpack_from("<H", main_data, block_base + off)[0]
    inner = struct.unpack_from("<H", main_data, block_base + off + 2)[0]
    link = struct.unpack_from("<I", main_data, block_base + off + 4)[0]
    lb = link.to_bytes(4, "little")
    return StaticNode(
        rom_offset=off,
        span=span & 0xFFFF,
        inner=inner & 0xFFFF,
        link_dword=link,
        link_bytes=lb.hex(),
        offset_byte1=lb[1],
    )


def _payload_1111_off(main_data: bytes, block) -> int | None:
    for rec_type, _rec_len, payload_off in _iter_cgm_v16_records(main_data, block):
        if rec_type == 0x1111:
            return payload_off - block.rom_offset
    return None


def analyze_link_dword(link: int, *, block_vaddr: int, block_rom: int) -> dict[str, Any]:
    b = link.to_bytes(4, "little")
    off_b1 = b[1]
    target_vaddr_if_low_offset = block_vaddr + off_b1
    target_rom_if_low_offset = block_rom + off_b1
    return {
        "dword": f"0x{link:08X}",
        "bytes_le": b.hex(),
        "byte1_as_block_offset": f"0x{off_b1:02X}",
        "byte1_equals_0x7c_points_to_rom": f"0x{target_rom_if_low_offset:X}",
        "same_as_vaddr": f"0x{target_vaddr_if_low_offset:08X}",
        "unique_in_main_data": True,
        "rom_maincpu_word_refs": [],
        "valid_main_data_vaddr": MAIN_DATA_A <= link < MAIN_DATA_A + 0xC0_0000,
        "note": (
            "Desert-only dword @ block ``+0x0C``; byte1 ``0x7C`` == 124 == offset to "
            "``block+0x7C`` (marker/run bytes). Full ``0x22F77C00`` is **not** a "
            "``MAIN_DATA_A`` vaddr — high-nibble ``0x22`` vs block ``0x28`` OPEN"
        ),
    }


def walk_prefix_nodes(main_data: bytes, block, *, slot_base: int = 14) -> dict[str, Any]:
    base = block.rom_offset
    payload_off = _payload_1111_off(main_data, block)
    if payload_off is None:
        raise SystemExit("no 0x1111 record in desert block")

    nodes: list[dict[str, Any]] = []
    # First node @ +0x08 matches disasm when inner cursor lands after 8-byte CGM magic.
    first = _read_node(main_data, base, 0x08)
    if first:
        nodes.append(
            {
                "rom_offset": f"+0x{first.rom_offset:02X}",
                "span": first.span,
                "inner": first.inner,
                "link": analyze_link_dword(
                    first.link_dword, block_vaddr=block.vaddr, block_rom=base
                ),
                "disasm_match": True,
            }
        )

    # Scan for other u16 span/inner-like pairs in prefix (heuristic report only).
    seen: set[tuple[int, int, int]] = {(0x08, first.span, first.inner)} if first else set()
    for off in range(0x20, payload_off, 2):
        n = _read_node(main_data, base, off)
        if n is None:
            continue
        if not (0 < n.span <= 0x2000 and n.inner <= 0x5000):
            continue
        key = (off, n.span, n.inner)
        if key in seen:
            continue
        seen.add(key)
        entry: dict[str, Any] = {
            "rom_offset": f"+0x{off:02X}",
            "span": n.span,
            "inner": n.inner,
            "link_dword": f"0x{n.link_dword:08X}",
        }
        if n.inner == 4369:
            entry["note"] = "inner == desert 0x1111 record byte length (4369)"
        if off == 0x2C and n.span == 24:
            entry["note"] = "overlaps v16 record header (type 0x1111 len 24) @ +0x2C"
        nodes.append(entry)

    state = PrefixWalk(slot_base=slot_base, cursor_20c950=slot_base)
    if first and first.span == 0x10 and first.inner == 0xFFFF:
        before = state.cursor_20c950
        state.cursor_20c950 = (state.cursor_20c950 + first.span) & 0xFFFF
        inner_iters = min(first.inner, 512) if first.inner > 0x1FF else first.inner
        for _ in range(inner_iters):
            state.events.append(
                {
                    "rom": "0x029F7C",
                    "node": "+0x08",
                    "20c954": state.index_20c954,
                    "20c950": state.cursor_20c950,
                }
            )
            state.index_20c954 += 1
            if state.index_20c954 > 0x1FF:
                break
        state.events.insert(
            0,
            {
                "rom": "0x29F54",
                "node": "+0x08",
                "span": first.span,
                "20c950_before": before,
                "20c950_after": state.cursor_20c950,
            },
        )

    return {
        "block_vaddr": f"0x{block.vaddr:08x}",
        "payload_1111_rom_offset": f"0x{payload_off:02X}",
        "prefix_nodes": nodes[:12],
        "prefix_node_count": len(nodes),
        "simulation_first_node_only": {
            "final_20c950": state.cursor_20c950,
            "final_20c954": state.index_20c954,
            "29f7c_events": len(state.events),
            "slot_477_reached": state.cursor_20c950 >= 477,
            "note": "Only first ``+0x08`` node simulated — ``0x1111`` body chain not walked",
        },
    }


def build_report() -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    link = struct.unpack_from("<I", main_data, block.rom_offset + 0x0C)[0]
    link_info = analyze_link_dword(link, block_vaddr=block.vaddr, block_rom=block.rom_offset)
    link_info["rom_maincpu_word_refs"] = [
        f"0x{r:06X}" for r in find_word_refs(words, link)
    ]
    link_info["unique_in_main_data"] = (
        main_data.find(link.to_bytes(4, "little")) == block.rom_offset + 0x0C
    )

    alpine = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[0]]
    alpine_link = struct.unpack_from("<I", main_data, alpine.rom_offset + 0x0C)[0]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "static CGM layout + i960 disasm (no MAME, no XOR)",
        "disasm_node_read": list(DISASM_NODE_READ),
        "desert_link_at_plus_0c": link_info,
        "alpine_link_at_plus_0c": f"0x{alpine_link:08X}",
        "prefix_walk": walk_prefix_nodes(main_data, block),
        "fp_plus_40_model": {
            "disasm": "``0x29ED4`` stores ``lda 0(g2)`` dword @ block+0 (``0x204D4743`` static)",
            "stream_tension": (
                "Valid first node @ ``block+0x08`` requires inner cursor there; "
                "``ld (r5)`` needs ``*r5`` → ``block+0x08`` or ``r5`` = block vaddr with "
                "different read path — **not** proven from static dword alone"
            ),
            "gate_still_matches": (
                "``0x05CE18`` compares bytes via identical pointer ``0x204D4743`` both sides"
            ),
        },
        "open_gaps": [
            "Full ``0x22F77C00`` pointer semantics — byte1 ``0x7C`` == ``block+0x7C`` offset only partial",
            "``0x1111`` payload internal linked list not parsed as ``0x29F0C`` nodes",
            "Slot 477 not reached from first-node simulation (20C950=30 after span 16)",
            "No ROM ``st`` patches ``fp+0x40`` / block word0 to stream root",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Desert block +0x0C stream link RE")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_block_stream_link_re.json",
    )
    args = parser.parse_args()

    report = build_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    link = report["desert_link_at_plus_0c"]
    sim = report["prefix_walk"]["simulation_first_node_only"]
    print(f"Link @ +0xC: {link['dword']} byte1→block+{link['byte1_as_block_offset']}")
    print(f"Unique in main_data: {link['unique_in_main_data']}")
    print(
        f"First node sim: 20C950={sim['final_20c950']} "
        f"29F7C events={sim['29f7c_events']} slot477={sim['slot_477_reached']}"
    )


if __name__ == "__main__":
    main()
