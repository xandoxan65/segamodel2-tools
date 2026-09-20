#!/usr/bin/env python3
"""Disasm-backed walk of desert ``0x1111`` payload vs ``0x29EF0`` / ``0x02A050`` layouts.

Tests whether static ROM bytes form ``0x29F0C`` stream nodes or ``0x02A050``
``+0x22`` chains that reach slot 477.  Reports FIFO ``0x8843`` correlation only
(no XOR inference).

  python3 -m tools.decomp.palette_1111_stream_walk_re
  python3 -m tools.decomp.palette_1111_stream_walk_re --focus-slot 477 --focus-raw 0x8843
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_cgm_1111 import (
    CGM_RECORD_1111,
    _is_format_chunk,
    _split_inner_chunks,
    replay_1111_record,
)
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    load_colorxlat_from_main_data,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

MAIN_DATA_A = 0x0200_0000
MAX_SPAN = 0x400
MAX_INNER_STRICT = 0x1FF  # @ 0x29F68 / 0x29FCC
InnerMode = str  # "strict" | "hardware" | "loose"


def _inner_iters(inner: int, mode: InnerMode) -> tuple[int, str | None]:
    """Return (iteration count, overflow_note)."""
    if inner == 0:
        return 0, "inner_zero_skip_29f7c"
    if mode == "strict" and inner > MAX_INNER_STRICT:
        return 0, f"inner_{inner}_gt_1ff_reject"
    if mode == "hardware" and inner > MAX_INNER_STRICT:
        # @ 0x29FCC: loop until 0x20C954 > 0x1FF, then overflow @ 0x02A004
        return min(inner, 512), f"inner_{inner}_overflow_path_cap_512"
    if mode == "loose":
        return min(inner, 512), None
    return inner, None


@dataclass
class WalkState:
    slot_base: int = 14
    cursor_20c950: int = 14
    index_20c954: int = 0
    nodes: list[dict[str, Any]] = field(default_factory=list)


def _desert_1111(main_data: bytes) -> tuple[bytes, int, int, Any]:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len], off, rec_len, block
    raise SystemExit("desert 0x1111 not found")


def _read_node(data: bytes, off: int) -> tuple[int, int, int] | None:
    if off + 8 > len(data):
        return None
    span, inner, link = struct.unpack_from("<HH I", data, off)
    return span & 0xFFFF, inner & 0xFFFF, link


def _link_targets(
    link: int,
    *,
    cur_off: int,
    block_rom: int,
    buf_base_rom: int,
) -> list[tuple[str, int]]:
    b = link.to_bytes(4, "little")
    out: list[tuple[str, int]] = [
        ("byte1_block_rel", b[1]),
        ("cur_plus_8", cur_off + 8),
        ("low_u16", link & 0xFFFF),
        ("cur_plus_low_u16", cur_off + (link & 0xFFFF)),
    ]
    if MAIN_DATA_A <= link < MAIN_DATA_A + 0xC0_0000:
        out.append(("main_data_vaddr", link - MAIN_DATA_A))
    if buf_base_rom == block_rom:
        out.append(("block_plus_byte1", b[1]))
    return out


def walk_29f_nodes(
    data: bytes,
    start: int,
    *,
    buf_base_rom: int,
    block_rom: int,
    inner_mode: InnerMode = "strict",
    max_nodes: int = 500,
    label: str,
) -> dict[str, Any]:
    state = WalkState()
    off = start
    visited: set[int] = set()
    stop = "end"
    overflow_notes: list[str] = []

    for step in range(max_nodes):
        if off in visited:
            stop = f"cycle@0x{off:X}"
            break
        visited.add(off)

        parsed = _read_node(data, off)
        if parsed is None:
            stop = f"trunc@0x{off:X}"
            break
        span, inner, link = parsed
        if span == 0 and inner == 0:
            stop = f"zero@0x{off:X}"
            break
        if span > MAX_SPAN:
            stop = f"span_implausible@0x{off:X}(span={span})"
            break
        if inner_mode == "strict" and inner > 0x10000:
            stop = f"inner_implausible@0x{off:X}(inner={inner})"
            break
        if inner_mode != "hardware" and inner_mode != "loose" and inner > MAX_INNER_STRICT:
            stop = f"inner_gt_1ff@0x{off:X}"
            break

        inner_iters, inner_note = _inner_iters(inner, inner_mode)
        if inner_note and inner_iters == 0:
            stop = inner_note
            break
        if inner_note:
            overflow_notes.append(inner_note)

        before = state.cursor_20c950
        state.cursor_20c950 = (state.cursor_20c950 + span) & 0xFFFF
        hit = before < 477 <= state.cursor_20c950

        for _ in range(inner_iters):
            state.index_20c954 += 1
            if state.index_20c954 > MAX_INNER_STRICT:
                overflow_notes.append("20c954_gt_1ff_stop_inner")
                break

        state.nodes.append(
            {
                "step": step,
                "rom_offset": f"0x{buf_base_rom + off:X}",
                "buf_off": f"0x{off:X}",
                "span": span,
                "inner": inner,
                "inner_iters_applied": inner_iters,
                "link": f"0x{link:08X}",
                "20c950_before": before,
                "20c950_after": state.cursor_20c950,
                "20c954_after": state.index_20c954,
                "hit_slot_477": hit,
            }
        )
        if hit:
            stop = f"hit_477@step{step}"
            break
        if state.index_20c954 > MAX_INNER_STRICT and inner_mode == "hardware":
            stop = "overflow_path_after_first_node"
            break

        nxt = None
        for name, rel in _link_targets(
            link, cur_off=off, block_rom=block_rom, buf_base_rom=buf_base_rom
        ):
            if rel < 0 or rel + 8 > len(data):
                continue
            trial = _read_node(data, rel)
            if trial is None:
                continue
            ts, ti, _ = trial
            if not (0 < ts <= MAX_SPAN):
                continue
            if inner_mode == "strict" and ti > MAX_INNER_STRICT:
                continue
            if inner_mode not in ("hardware", "loose") and ti > 0x10000:
                continue
            nxt = (name, rel)
            break
        if nxt is None:
            stop = f"no_link@0x{off:X}"
            break
        off = nxt[1]

    return {
        "label": label,
        "start_off": f"0x{start:X}",
        "inner_mode": inner_mode,
        "nodes_walked": len(state.nodes),
        "final_20c950": state.cursor_20c950,
        "final_20c954": state.index_20c954,
        "slot_477_reached": any(n.get("hit_slot_477") for n in state.nodes),
        "stop_reason": stop,
        "overflow_notes": overflow_notes,
        "nodes_head": state.nodes[:8],
        "nodes_tail": state.nodes[-3:] if len(state.nodes) > 3 else state.nodes,
    }


def walk_2a050_stride(payload: bytes, *, max_steps: int = 64) -> dict[str, Any]:
    """``0x02A084`` ``lda 0x22(r5),r5`` stride report (not a proven node parse)."""
    rows: list[dict[str, Any]] = []
    off = 0
    for step in range(max_steps):
        if off + 0x24 > len(payload):
            break
        u0 = struct.unpack_from("<H", payload, off)[0]
        u22 = struct.unpack_from("<H", payload, off + 0x22)[0]
        d22 = struct.unpack_from("<I", payload, off + 0x22)[0]
        rows.append(
            {
                "step": step,
                "payload_off": f"0x{off:X}",
                "u16_at_0": f"0x{u0:04X}",
                "u16_at_plus_22": f"0x{u22:04X}",
                "dword_at_plus_22": f"0x{d22:08X}",
            }
        )
        off += 0x22
    markerish = sum(1 for r in rows if r["u16_at_0"] in ("0x1111", "0x8111", "0x8116"))
    return {
        "stride_bytes": 0x22,
        "disasm": "0x02A084 lda 0x22(r5),r5 — chain through span materializer loop",
        "steps_reported": len(rows),
        "marker_u16_count": markerish,
        "conclusion": (
            "Payload bytes at +0x22 stride are dominated by 0x1111 marker "
            "patterns — not a clean separate linked list from marker-split replay"
        ),
        "rows_head": rows[:6],
    }


def _payload_off_for_fifo(fifo_pos: int, payload: bytes) -> int | None:
    """Map FIFO byte index to payload offset (skips format chunks)."""
    fifo = 0
    poff = 0
    for chunk in _split_inner_chunks(payload):
        if _is_format_chunk(chunk):
            poff += len(chunk)
            continue
        for i in range(len(chunk)):
            if fifo == fifo_pos:
                return poff + i
            fifo += 1
        poff += len(chunk)
    return None


def fifo_correlation(payload: bytes, *, focus_raw: int) -> dict[str, Any]:
    fifo = bytearray()
    chunk_map: list[dict[str, Any]] = []
    for idx, chunk in enumerate(_split_inner_chunks(payload), start=1):
        if _is_format_chunk(chunk):
            continue
        base = len(fifo)
        fifo.extend(chunk)
        chunk_map.append({"chunk": idx, "fifo_start": base, "size": len(chunk)})

    needle = focus_raw & 0xFFFF
    pat = struct.pack("<H", needle)
    fifo_hits: list[dict[str, Any]] = []
    pos = 0
    while True:
        j = fifo.find(pat, pos)
        if j < 0:
            break
        chunk_hit = next(
            (c for c in chunk_map if c["fifo_start"] <= j < c["fifo_start"] + c["size"]),
            None,
        )
        pay_off = _payload_off_for_fifo(j, payload)
        fifo_hits.append(
            {
                "fifo_offset": f"0x{j:X}",
                "chunk": chunk_hit["chunk"] if chunk_hit else None,
                "payload_off": f"0x{pay_off:X}" if pay_off is not None else None,
            }
        )
        pos = j + 1

    payload_hits: list[str] = []
    pos = 0
    while True:
        j = payload.find(pat, pos)
        if j < 0:
            break
        payload_hits.append(f"0x{j:X}")
        pos = j + 1

    return {
        "fifo_len": len(fifo),
        "fifo_hits": fifo_hits,
        "payload_direct_hits": payload_hits,
        "note": "FIFO layout != raw payload offsets; replay bin_pos uses FIFO coordinates",
    }


def replay_oracle(main_data: bytes, payload: bytes, *, slot: int) -> dict[str, Any]:
    st = PaletteState()
    st._install_default_lumaram()
    load_colorxlat_from_main_data(st, main_data)
    result = replay_1111_record(st, payload, trace_slots=frozenset({slot}))
    row = result.trace[0] if result.trace else None
    return {
        "method": "Python replay_1111_record (format-walk oracle, not hardware)",
        "slot": slot,
        "trace": row,
        "hardware_29f_equivalence": "not proven",
    }


def build_report(*, focus_slot: int = 477, focus_raw: int = 0x8843) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    payload, payload_rom, _plen, block = _desert_1111(main_data)
    block_rom = block.rom_offset
    block_buf = main_data[block_rom : payload_rom + len(payload)]

    walks = [
        walk_29f_nodes(
            block_buf,
            0x08,
            buf_base_rom=block_rom,
            block_rom=block_rom,
            inner_mode="strict",
            label="block_prefix_strict",
        ),
        walk_29f_nodes(
            block_buf,
            0x08,
            buf_base_rom=block_rom,
            block_rom=block_rom,
            inner_mode="hardware",
            label="block_prefix_hardware",
        ),
        walk_29f_nodes(
            block_buf,
            0x7C,
            buf_base_rom=block_rom,
            block_rom=block_rom,
            inner_mode="strict",
            label="block_at_link_byte1_7c",
        ),
        walk_29f_nodes(
            payload,
            0x00,
            buf_base_rom=payload_rom,
            block_rom=block_rom,
            inner_mode="strict",
            label="payload_start_strict",
        ),
        walk_29f_nodes(
            payload,
            0x00,
            buf_base_rom=payload_rom,
            block_rom=block_rom,
            inner_mode="loose",
            label="payload_start_loose",
        ),
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "static ROM + i960 layout rules (no MAME, no XOR)",
        "payload": {
            "rom_offset": f"0x{payload_rom:X}",
            "bytes": len(payload),
            "vaddr": f"0x{block.vaddr + (payload_rom - block_rom):X}",
        },
        "disasm_layout": {
            "29f_node_after_skip_8": "span u16 @ +0, inner u16 @ +2, link u32 @ +4",
            "block_first_node": "matches @ block+0x08 when outer cursor skips 8-byte CGM magic",
            "2a050_stride": "0x22 bytes per lda 0x22(r5),r5 @ 0x02A084",
        },
        "walks_29f_layout": walks,
        "walk_2a050_stride": walk_2a050_stride(payload),
        "fifo_correlation": fifo_correlation(payload, focus_raw=focus_raw),
        "replay_oracle": replay_oracle(main_data, payload, slot=focus_slot),
        "open_gaps": [
            "No 0x29F0C walk from static bytes reaches slot 477",
            "First block node inner=0xFFFF triggers overflow path (@ 0x02A004), not 477 inner iters",
            "First block link 0x22F77C00 → byte1 0x7C does not start next strict node",
            "0x1111 payload is marker/FIFO binary — not disasm node stream",
            "Replay slot 477 (FIFO bin_pos 936) ≠ 0x20C954 index without runtime walk",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x1111 payload vs 29EF0/2A050 layout walk")
    parser.add_argument("--focus-slot", type=int, default=477)
    parser.add_argument("--focus-raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_1111_stream_walk_re.json",
    )
    args = parser.parse_args()

    report = build_report(focus_slot=args.focus_slot, focus_raw=args.focus_raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    for w in report["walks_29f_layout"]:
        print(
            f"  {w['label']}: nodes={w['nodes_walked']} "
            f"20C950={w['final_20c950']} slot477={w['slot_477_reached']} stop={w['stop_reason']}"
        )
    rep = report["replay_oracle"].get("trace") or {}
    print(f"Replay oracle: slot {rep.get('slot')} raw {rep.get('raw')} bin_pos {rep.get('bin_pos')}")


if __name__ == "__main__":
    main()
