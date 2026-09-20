#!/usr/bin/env python3
"""Static walk of desert ``0x1111`` payload vs ``0x029EB0`` counter disasm.

Tracks ``0x20C950`` / ``0x20C954`` using **only** insn effects from
``maincpu_029eb0_600.asm`` (@ ``0x29EF4``–``0x029FB4``).  Segment headers are
**ROM u16 fields** at ``+8`` and ``+10`` when a binary segment has ``len>=12`` —
labeled as disasm layout candidates, not verified against hardware linked list.

Does **not** decode FIFO u16 or infer XOR.

  python3 -m tools.decomp.palette_29eb0_stream_walker
  python3 -m tools.decomp.palette_29eb0_stream_walker --simulate-headers
  python3 -m tools.decomp.palette_29eb0_stream_walker --focus-raw 0x8843
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_cgm_1111 import (
    CGM_RECORD_1111,
    _is_format_chunk,
    _split_inner_chunks,
)
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    find_cgm_blocks,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Disasm @ 0x29EB0 — segment byte layout before ``0x029F7C`` loop.
SEGMENT_HEADER = (
    {"offset": 0x08, "size": 2, "rom": "0x29F0C", "insn": "ldos (g4),r9", "name": "u16_span"},
    {"offset": 0x0A, "size": 2, "rom": "0x29F50", "insn": "ldos (g5),r4", "name": "inner_loop_count"},
)


def _u16_le(data: bytes, off: int) -> int | None:
    if off < 0 or off + 1 >= len(data):
        return None
    return data[off] | (data[off + 1] << 8)


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


@dataclass
class WalkerState:
    """Workram counters (@ ``0x0020C950``, ``0x0020C954``)."""

    cursor_20c950: int = 14  # after leading slots; hardware init varies by block
    index_20c954: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


def _parse_segment_header(segment: bytes) -> dict[str, Any] | None:
    if len(segment) < 12:
        return None
    u16_span = _u16_le(segment, 8)
    inner = _u16_le(segment, 10)
    if u16_span is None or inner is None:
        return None
    return {
        "u16_span": f"0x{u16_span:04x}",
        "u16_span_masked": u16_span & 0xFFFF,
        "inner_loop_count": inner & 0xFFFF,
        "disasm": "0x29F0C span → r8; 0x29F50 count → r4; 0x29F7C loop",
    }


def _apply_segment_header(state: WalkerState, header: dict[str, Any], *, segment_idx: int) -> str | None:
    """Apply ``0x29F54`` / ``0x29F7C`` / ``0x29FB4`` counter updates (no ``0x02A0F8`` body).

    Returns skip reason, or ``None`` if applied.  Skips when ``inner_loop_count`` >
    ``0x1FF`` — ``0x29FCC`` ``cmpible g4,r15,0x29f7c`` with ``r15=0x1FF`` takes the
    overflow path instead of the inner loop.
    """
    r8 = int(header["u16_span_masked"])
    r4 = int(header["inner_loop_count"])
    if r4 == 0:
        return "inner_loop_count_zero"
    if r4 > 0x1FF:
        return f"inner_loop_count_{r4}_gt_0x1FF_overflow_path"
    before = state.cursor_20c950
    # @ 0x29F54: addo r8,g4,g4 then st 0x20C950
    state.cursor_20c950 = (state.cursor_20c950 + r8) & 0xFFFF
    state.events.append(
        {
            "rom": "0x29F54",
            "segment": segment_idx,
            "20c950_before": before,
            "r8": r8,
            "20c950_after": state.cursor_20c950,
        }
    )
    for _ in range(r4):
        idx = state.index_20c954
        state.events.append(
            {
                "rom": "0x029F7C",
                "segment": segment_idx,
                "20c954": idx,
                "20c950": state.cursor_20c950,
                "r10_would_be": (state.cursor_20c950 & 0xFFFF) << 7,
                "note": "bal 0x02A0F8 — handler body not executed",
            }
        )
        state.index_20c954 += 1
    return None


def walk_payload(
    payload: bytes,
    *,
    simulate_headers: bool = False,
    focus_raw: int | None = None,
) -> dict[str, Any]:
    segments = _split_inner_chunks(payload)
    fifo = bytearray()
    segment_rows: list[dict[str, Any]] = []
    state = WalkerState()
    skip_log: list[dict[str, Any]] = []

    for idx, seg in enumerate(segments, start=1):
        kind = "format" if _is_format_chunk(seg) else "binary"
        fifo_before = len(fifo)
        row: dict[str, Any] = {
            "segment": idx,
            "kind": kind,
            "size": len(seg),
            "fifo_offset_before": fifo_before,
        }
        if kind == "format":
            row["format_frag"] = seg.decode("latin1", errors="replace")
        else:
            fifo.extend(seg)
            row["fifo_offset_after"] = len(fifo)
            hdr = _parse_segment_header(seg)
            if hdr:
                row["disasm_header_candidate"] = hdr
                if simulate_headers:
                    reason = _apply_segment_header(state, hdr, segment_idx=idx)
                    if reason:
                        skip_log.append({"segment": idx, "reason": reason, **hdr})
        segment_rows.append(row)

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "0x1111 marker split + 0x29EB0 counter rules (no decode)",
        "segment_header_layout": list(SEGMENT_HEADER),
        "segment_count": len(segments),
        "binary_fifo_bytes": len(fifo),
        "segments": segment_rows,
        "simulation": None,
    }

    if simulate_headers:
        report["simulation"] = {
            "note": (
                "Applied ``+8``/``+10`` u16 headers on binary segments only. "
                "Valid only if runtime linked list matches this byte layout."
            ),
            "final_20c950": state.cursor_20c950,
            "final_20c954": state.index_20c954,
            "events": state.events,
            "segments_skipped": skip_log[:32],
            "segments_skipped_total": len(skip_log),
        }

    if focus_raw is not None:
        needle = int(focus_raw) & 0xFFFF
        lo = needle & 0xFF
        hi = (needle >> 8) & 0xFF
        pattern = bytes([lo, hi])
        hits: list[dict[str, Any]] = []
        pos = 0
        while True:
            j = fifo.find(pattern, pos)
            if j < 0:
                break
            seg_hit = None
            for row in segment_rows:
                if row["kind"] != "binary":
                    continue
                fb = row["fifo_offset_before"]
                fa = row.get("fifo_offset_after", fb)
                if fb <= j < fa:
                    seg_hit = row["segment"]
                    off_in_seg = j - fb
                    break
            hits.append(
                {
                    "fifo_offset": j,
                    "segment": seg_hit,
                    "offset_in_segment": off_in_seg if seg_hit else None,
                    "raw_u16": f"0x{needle:04x}",
                }
            )
            pos = j + 1
        report["focus_raw"] = {
            "raw_u16": f"0x{needle:04x}",
            "fifo_hits": hits,
        }

        if simulate_headers and hits:
            # Report 29F7C events where 20c950 equals values near slot 477 (factual match only)
            slot_target = 477
            matching = [
                e
                for e in state.events
                if e.get("rom") == "0x029F7C" and e.get("20c950") == slot_target
            ]
            report["focus_raw"]["29f7c_events_at_20c950_477"] = matching

    return report


def build_report(
    *,
    simulate_headers: bool = False,
    focus_raw: int | None = None,
) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    payload = _desert_1111_payload(main_data)
    return walk_payload(payload, simulate_headers=simulate_headers, focus_raw=focus_raw)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x29EB0 stream walker (disasm counters)")
    parser.add_argument(
        "--simulate-headers",
        action="store_true",
        help="Apply +8/+10 u16 header rules on binary segments (disasm candidate layout)",
    )
    parser.add_argument("--focus-raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_29eb0_stream_walker.json",
    )
    args = parser.parse_args()

    report = build_report(
        simulate_headers=args.simulate_headers,
        focus_raw=args.focus_raw,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(f"Segments: {report['segment_count']}  binary FIFO: {report['binary_fifo_bytes']} bytes")

    hits = (report.get("focus_raw") or {}).get("fifo_hits") or []
    for h in hits[:5]:
        print(
            f"  raw {h['raw_u16']} @ fifo+0x{h['fifo_offset']:x} "
            f"seg={h.get('segment')} off={h.get('offset_in_segment')}"
        )

    if args.simulate_headers and report.get("simulation"):
        sim = report["simulation"]
        print(
            f"\nSimulated counters: 0x20C950={sim['final_20c950']} "
            f"0x20C954={sim['final_20c954']} ({len(sim['events'])} events)"
        )
        at477 = (report.get("focus_raw") or {}).get("29f7c_events_at_20c950_477") or []
        print(f"  29F7C events with 20C950==477: {len(at477)}")


if __name__ == "__main__":
    main()
