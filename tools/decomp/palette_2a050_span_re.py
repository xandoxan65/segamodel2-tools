#!/usr/bin/env python3
"""Disasm trace: ``0x02A050`` span materializer @ ``0x29F34`` (matched stream).

Documents how the matched ``0x029EB0`` path copies stream bytes into
``0x01080000`` staging before the ``0x029F7C`` inner loop.  Reports static
desert block head u16 fields vs disasm node layout.  No XOR / decode inference.

  python3 -m tools.decomp.palette_2a050_span_re
  python3 -m tools.decomp.palette_2a050_span_re --block 0x028CCAF8
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Call site @ ``0x29F34`` (``maincpu_029eb0_600.asm``).
CALL_SITE_29F34 = {
    "rom": "0x29F34",
    "insn": "call 0x02A050",
    "args": {
        "g0": "``0x20C950`` slot cursor **before** span add (@ ``0x29EF8`` load; ``0x29F54`` adds ``r8`` after return)",
        "g1": "``r5`` — outer stream root saved @ ``0x29ED4`` / ``fp+0x40`` chain",
        "g2": "``r9`` — raw u16 from ``ldos (g4),r9`` @ ``0x29F0C`` (before ``r8 = r9 & 0xFFFF``)",
        "r10": "``shlo 7,g0,r10`` @ ``0x29F28`` — slot anchor written @ ``0x29F90`` ``stos r10,(g4)``",
    },
    "after_return": (
        "``0x29F54`` ``addo r8,g4,g4`` → ``0x20C950``; inner count @ ``0x29F50``; "
        "``0x029F7C`` loop or ``0x29FD0`` tail"
    ),
}

DISASM_2A050 = (
    {"rom": "0x02A050", "effect": "``r7 = g2`` — span u16 (header field from stream node)"},
    {"rom": "0x02A05C", "effect": "``g4 = r7 & 0xFFFF`` — masked span byte count"},
    {"rom": "0x02A060", "effect": "``r8 = g0`` — starting slot index (``0x20C950``)"},
    {"rom": "0x02A06C", "effect": "``r5 = ld (g1)`` — inner linked-list cursor from outer node"},
    {"rom": "0x02A074", "effect": "``be 0x2A0E8`` when span==0 — skip copy loop"},
    {
        "rom": "0x02A078",
        "effect": (
            "Per span slot ``r6``: ``g0 = r8+r6``; ``bal 0x026918`` scratch flush; "
            "``r5 = lda 0x22(r5)`` — advance chain node (+0x22 stride)"
        ),
    },
    {
        "rom": "0x02A08C",
        "effect": (
            "``ldos (r5),g4`` → ``lda 0x1080000(g4),g4`` — map FIFO u16 index into "
            "``0x01080000`` bus row; ``g3 = g4 & r10`` (slot mask from span header bit 7 path)"
        ),
    },
    {
        "rom": "0x02A0B0",
        "effect": (
            "Triple ``ldq``/``stq`` copy: staging @ ``0x10(r4)``, source ``(r5)`` / ``(g1+16)`` — "
            "32-byte structure copy per inner iteration"
        ),
    },
    {
        "rom": "0x02A0E8",
        "effect": (
            "``st r5,(r9)`` — write back advanced inner cursor; **local ``r9``** still holds "
            "header u16 from ``ldos`` @ ``0x29F0C`` (same value copied to ``g2`` @ ``0x29F30``). "
            "Primary cursor updates: ``st g4,(r5)`` @ ``0x29F1C`` / ``st g5,(r5)`` @ ``0x29F64``"
        ),
    },
)

BUS_REGIONS = (
    {"base": "0x01080000", "role": "Primary staging / merge target (@ ``0x02A090`` ``+0x1080000``)"},
    {"base": "0x01000000", "role": "Alternate staging (@ ``0x02A220`` ``+0x1000000`` branch)"},
    {"base": "0x01004000", "role": "Alternate staging (@ ``0x02A20C`` ``+0x1004000`` branch)"},
    {"base": "0x01800000", "role": "Scratch colorbase (@ ``0x026918`` / ``0x02A1AC``)"},
)

OPEN_GAPS = (
    "``st r5,(r9)`` @ ``0x02A0E8``: local ``r9`` = header u16 @ ``0x29F0C`` — semantic tension vs pointer writeback (OPEN)",
    "``ld (r5)`` / ``fp+0x40`` head dword is ASCII ``CGM `` in static ROM — runtime pointer fixup required",
    "Marker-split ``0x1111`` binary chunks are not ``0x02A050`` linked-list nodes (+0x22 stride unverified on ROM bytes)",
    "Whether ``0x8843`` @ FIFO+0x3a6 is reachable via ``0x02A08C`` ``ldos`` chain depends on unfixed stream root",
)


def block_node_header_facts(main_data: bytes, vaddr: int) -> dict[str, Any]:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}.get(vaddr)
    if block is None:
        raise SystemExit(f"no CGM block @ 0x{vaddr:08x}")
    base = block.rom_offset
    head = main_data[base : base + 0x40]
    word0 = struct.unpack_from("<I", head, 0)[0]
    u16_8 = struct.unpack_from("<H", head, 8)[0]
    u16_a = struct.unpack_from("<H", head, 0xA)[0]
    ldis_10 = struct.unpack_from("<H", head, 0x10)[0]
    ldis_12 = struct.unpack_from("<H", head, 0x12)[0]
    rec_1111 = None
    for off in range(0x20, 0x40, 4):
        w = struct.unpack_from("<I", head, off)[0]
        if (w & 0xFFFF) == 0x1111:
            rec_1111 = f"0x{off:02X}"
            break
    inner_path = "overflow_or_many_iters"
    if u16_a == 0:
        inner_path = "skip_29f7c (@ 0x29F68)"
    elif u16_a <= 0x1FF:
        inner_path = f"29f7c_loop_{u16_a}_times"
    elif u16_a > 0x1FF:
        inner_path = (
            f"inner_count_{u16_a}_gt_1FF — ``0x29F7C`` runs until ``0x20C954>0x1FF`` "
            f"(up to 512 ``bal 0x02A0F8`` per node @ ``0x29FCC``)"
        )
    return {
        "vaddr": f"0x{vaddr:08x}",
        "word0_head_dword": f"0x{word0:08x}",
        "head_ascii_8": head[:8].decode("latin1", errors="replace"),
        "disasm_node_u16": {
            "offset_08_span": f"0x{u16_8:04x}",
            "offset_0A_inner_count": f"0x{u16_a:04x}",
            "predicted_2a050_span": u16_8,
            "predicted_inner_loop": inner_path,
        },
        "disasm_2a0f8_mul_operands": {
            "ldis_10": f"0x{ldis_10:04x}",
            "ldis_12": f"0x{ldis_12:04x}",
            "mul_index": (ldis_10 * ldis_12) & 0xFFFF,
            "note": "Read from ``fp+0x40`` pointer @ ``0x29F84`` — needs runtime vaddr fixup in static image",
        },
        "cgm_1111_record_offset_in_head": rec_1111,
        "head_hex_40": head.hex(),
    }


def build_report(*, block_vaddr: int = COURSE_CGM_VADDRS[1]) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    desert = block_node_header_facts(main_data, COURSE_CGM_VADDRS[1])
    alpine = block_node_header_facts(main_data, COURSE_CGM_VADDRS[0])
    focus = block_node_header_facts(main_data, block_vaddr)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + static CGM block bytes (no MAME, no XOR)",
        "call_site_29f34": CALL_SITE_29F34,
        "disasm_2a050": list(DISASM_2A050),
        "bus_regions": list(BUS_REGIONS),
        "blocks": {"alpine": alpine, "desert": desert},
        "focus_block": focus,
        "slot_477_note": (
            "Tier-B slot 477 requires cumulative ``0x20C950`` span advances across "
            "many stream nodes — first desert node span=0x10, inner=0xFFFF; not reached "
            "from marker-split ``+8``/``+0xA`` simulation (0 valid headers)"
        ),
        "open_gaps": list(OPEN_GAPS),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x02A050 span materializer RE")
    parser.add_argument(
        "--block",
        type=lambda s: int(s, 0),
        default=COURSE_CGM_VADDRS[1],
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_2a050_span_re.json",
    )
    args = parser.parse_args()

    report = build_report(block_vaddr=args.block)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    focus = report["focus_block"]
    u16 = focus["disasm_node_u16"]
    print(f"Block {focus['vaddr']} head {focus['head_ascii_8']!r}")
    print(f"  +8 span={u16['offset_08_span']}  +A inner={u16['offset_0A_inner_count']}")
    print(f"  Inner path: {u16['predicted_inner_loop']}")
    for line in OPEN_GAPS[:3]:
        print(f"  OPEN: {line}")


if __name__ == "__main__":
    main()
