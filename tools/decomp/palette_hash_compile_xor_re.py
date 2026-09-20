#!/usr/bin/env python3
"""Disasm RE: ``#`` compile emit → ``0x02A200`` XOR reachability (not matched stream).

Traces ``0x05D1C8`` ``setbit 3,r9`` through ``0x05D824``/``0x05D860`` emit and
inventory desert ``0x1111`` format fragments containing ``#`` before replay slot
477.  Documents **zero** static ``bal``/``call`` to ``0x02A200``.  No xor_table proof.

  python3 -m tools.decomp.palette_hash_compile_xor_re
  python3 -m tools.decomp.palette_hash_compile_xor_re --slot 477
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_29fa0_2a0f8_re import XOR_BODY_2A200, _xor_callers_scan
from tools.model2_cgm_1111 import (
    Cgm1111Replay,
    _StreamState,
    _drain_pending_formats,
    _execute_format_chunk,
    _format_chunk_made_progress,
    _is_format_chunk,
    _split_inner_chunks,
)
from tools.model2_cgm_emit import compile_format_fragment, r9_bit_map
from tools.model2_cgm_staging import CgmStagingSim
from tools.model2_palette import PaletteState, load_colorxlat_from_main_data
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

HASH_COMPILE_DISASM = (
    {"rom": "0x05D1C8", "effect": "``#`` handler — ``setbit 3,r9``"},
    {"rom": "0x05D7CC", "effect": "``chkbit 3,r9`` — alternate ``g5`` load from linked field"},
    {"rom": "0x05D7E0", "effect": "``setbit 6,r9`` when count field == 0"},
    {"rom": "0x05D824", "effect": "``chkbit 3,r9`` — prefix ``0x5FBF10`` row with ``(char-31)==17`` bytes"},
    {"rom": "0x05D860", "effect": "emit engine — ``bal 0x027008`` template copy; builds ``bx`` thunk chain"},
    {"rom": "0x02A290", "effect": "batch boundary — ``+24`` gate → optional ``0x02A2C4`` ``0x05CEC0``"},
    {"rom": "0x02A200", "effect": "``cmpi g3,0`` / ``ble`` — XOR @ ``0x02A258`` only when ``g3>0``"},
)

MATCHED_PATH_EXCLUSION = (
    {"rom": "0x029EEC", "effect": "gate match → ``0x29EF0`` stream — never ``0x02A01C`` compile on desert init"},
    {"rom": "0x029FA0", "effect": "``bal 0x02A0F8`` returns @ ``0x02A114`` — no fall-through to ``0x02A200``"},
    {"rom": "0x02A038", "effect": "mismatch-only ``bal 0x029958`` — desert matched init skips"},
)


def _desert_payload(main_data: bytes) -> bytes:
    from tools.decomp.palette_29eb0_stream_walker import _desert_1111_payload

    return _desert_1111_payload(main_data)


def _scan_hash_fragments(main_data: bytes, *, slot: int) -> dict[str, Any]:
    payload = _desert_payload(main_data)
    pal = PaletteState()
    pal._install_default_lumaram()
    load_colorxlat_from_main_data(pal, main_data)
    staging = CgmStagingSim(slot_base=14, stream_cursor=14)
    stream = _StreamState(staging=staging)
    replay = Cgm1111Replay()
    hash_frags: list[dict[str, Any]] = []
    chunk_idx = 0

    def read_u16() -> int | None:
        if stream.bin_pos + 1 >= len(stream.binary):
            return None
        value = stream.binary[stream.bin_pos] | (stream.binary[stream.bin_pos + 1] << 8)
        stream.bin_pos += 2
        return value

    stream.read_u16 = read_u16
    pending: list[str] = []

    for chunk in _split_inner_chunks(payload):
        chunk_idx += 1
        if not chunk:
            continue
        if _is_format_chunk(chunk):
            text = chunk.decode("latin1", errors="replace")
            cursor_before = staging.stream_cursor
            if "#" in text:
                compile_ev = compile_format_fragment(text)
                hash_frags.append(
                    {
                        "chunk": chunk_idx,
                        "cursor_before": cursor_before,
                        "format_frag": text[:96],
                        "hash_count": text.count("#"),
                        "op_sequence": [e.get("op") for e in compile_ev],
                        "has_d_after_hash": bool(re.search(r"#.*[Dd]", text)),
                        "has_d_before_slot": cursor_before < slot,
                    }
                )
            stream.format_frag = text
            bb, cb = stream.bin_pos, staging.stream_cursor
            _execute_format_chunk(stream, pal, replay, text)
            if not _format_chunk_made_progress(stream, bin_pos_before=bb, cursor_before=cb):
                pending.append(text)
        else:
            stream.binary.extend(chunk)
            _drain_pending_formats(stream, pal, replay, pending)

    before_slot = [f for f in hash_frags if f["cursor_before"] < slot]
    with_d = [f for f in before_slot if f["has_d_after_hash"] or "D" in f["format_frag"]]

    return {
        "total_format_chunks_with_hash": len(hash_frags),
        "before_focus_slot": len(before_slot),
        "before_slot_with_d_or_hash_d_pattern": len(with_d),
        "samples_before_slot": before_slot[:12],
        "slot477_cursor_at_end": staging.stream_cursor,
        "note": (
            "Replay order only — compile path uses ``0x02A01C``/``0x05CEC0``, not desert matched ``0x29EF0``"
        ),
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    callers = _xor_callers_scan()
    frag_scan = _scan_hash_fragments(main_data, slot=slot)

    slot477_frag = "3333DD3DUUDTDDTU43UD33U433E4"
    slot477_compile = compile_format_fragment(slot477_frag)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + format compile simulation — no MAME, no xor_table hardware proof",
        "focus": {"slot": slot, "slot477_reference_frag": slot477_frag},
        "hash_compile_disasm": list(HASH_COMPILE_DISASM),
        "matched_path_exclusion": list(MATCHED_PATH_EXCLUSION),
        "r9_bit_map_hash": r9_bit_map().get("bit3"),
        "xor_body_2a200": list(XOR_BODY_2A200),
        "static_callers_02a200": callers,
        "desert_hash_fragment_scan": frag_scan,
        "slot477_fragment_compile": {
            "format_frag": slot477_frag,
            "op_sequence": [e.get("op") for e in slot477_compile],
            "contains_hash": "#" in slot477_frag,
            "compile_events": slot477_compile[:8],
        },
        "conclusions": (
            "``#`` sets ``r9`` bit 3 @ ``0x05D1C8``; emit @ ``0x05D860`` builds runtime ``bx`` thunks — "
            "**zero** static ``bal``/``call`` to ``0x02A200``.",
            "Desert init matched path (@ ``0x012E3C`` ``0x028CCAF8``) uses ``0x29EF0`` stream — "
            "**excludes** ``0x05CEC0`` compile that emits ``#`` handlers toward ``0x02A200``.",
            f"Slot {slot} reference fragment has **no** ``#`` — ``0x02A258`` oracle ``0x6683`` not reachable via ``#`` batch on that frag.",
            "``0x02A258`` XOR remains compile/mismatch-only in static disasm; lone ``D`` on matched path uses ``0x29CFC`` ADD.",
        ),
        "open_gaps": (
            "Runtime ``bx`` target from ``#``+``D`` compiled thunk chain → ``0x02A200`` with ``g3>0``",
            "Whether batch ``0x02A2C4`` aux compile (``FBT Error!`` mirror) ever runs during ``0x1111`` replay",
            "Workram thunk patch table @ ``0x005C9118`` — static ``ret`` only",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="# compile path vs 0x02A200 XOR RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_hash_compile_xor_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    scan = report["desert_hash_fragment_scan"]
    callers = report["static_callers_02a200"]
    refs_2a200 = callers.get("word_refs", {}).get("0x02A200", [])
    print(f"Static word refs 0x02A200: {len(refs_2a200)} ({refs_2a200[:3]})")
    print(
        f"Hash frags before slot {args.slot}: {scan['before_focus_slot']} "
        f"(with D pattern: {scan['before_slot_with_d_or_hash_d_pattern']})"
    )
    print(f"Slot477 frag has #: {report['slot477_fragment_compile']['contains_hash']}")


if __name__ == "__main__":
    main()
