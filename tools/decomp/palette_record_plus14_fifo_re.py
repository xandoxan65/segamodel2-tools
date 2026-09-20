#!/usr/bin/env python3
"""Disasm RE: compile record ``+0x14`` dual role vs replay FIFO @ slot 477.

Documents why ``0x29CDC`` ``lda 0x14(g0)`` (FIFO cursor) and ``0x02A10C``
``lda 0x14(g0)[g4*2]`` (handler table) cannot both use static desert block
bytes, inventories Python replay FIFO reads through ``0x8843`` @ ``fifo+0x3A6``,
and traces ``0x29FF8`` → ``0x029C10`` argument registers.

No MAME.  No XOR inference.

  python3 -m tools.decomp.palette_record_plus14_fifo_re
  python3 -m tools.decomp.palette_record_plus14_fifo_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts
from tools.model2_cgm_1111 import (
    Cgm1111Replay,
    _StreamState,
    _drain_pending_formats,
    _execute_format_chunk,
    _format_chunk_made_progress,
    _is_format_chunk,
    _split_inner_chunks,
)
from tools.model2_cgm_staging import CgmStagingSim
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    load_colorxlat_from_main_data,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- ``+0x14`` consumers (same offset name, different semantics) ----------------

PLUS14_CONSUMERS = (
    {
        "rom": "0x02A10C",
        "routine": "0x02A0F8",
        "insn": "``lda 0x14(g0)[g4*2],g0``",
        "semantics": "Indexed **handler u16 table**; index ``g4 = ldis(+0x10) × ldis(+0x12)``",
        "record_g0": "``fp+0x40`` block-head dword (@ ``0x29F84``) on matched path",
        "matched_path_29fa0": "``bal`` return link in ``g1`` — handler word loaded but not branched",
    },
    {
        "rom": "0x29CDC",
        "routine": "0x029C10",
        "insn": "``lda 0x14(g0),g7``",
        "semantics": "**Single pointer** to FIFO cursor; ``ldos (g7)`` @ ``0x29CF8``",
        "record_g0": "``ld 0x4(group_row)`` (@ ``0x29CC4``) — same ``st`` @ ``0x29F9C``",
        "transform": "``addo g13,g4,g4`` @ ``0x29CFC`` (not ``xor``)",
    },
    {
        "rom": "0x02A148",
        "routine": "0x02A120",
        "insn": "``ldos (g4),g3``",
        "semantics": "FIFO head from **group row** ``0x20B950[g0*8]`` — not ``+0x14``",
        "note": "No static ROM callers; ``0x1111`` record-end path",
    },
)

# --- ``0x29FF8`` call site (@ ``maincpu_029eb0_600.asm``) ----------------------

CALL_29FF8_ARGS = (
    {"reg": "g0", "source": "``movl r12,g0``", "value_note": "``r12`` = saved ``g2`` @ ``0x29EC4`` (block **vaddr** arg to ``0x029EB0``)"},
    {"reg": "g2", "source": "``mov r7,g2``", "value_note": "``r7`` = ``0x20C954`` snapshot @ ``0x29F44`` (0 on desert first node)"},
    {"reg": "g3", "source": "``mov r14,g3``", "value_note": "``r14`` = saved caller ``g3`` @ ``0x29EC8``"},
    {"reg": "g4", "source": "``mov r11,g4``", "value_note": "``r11`` = saved entry ``g4`` (=4 desert init) — ``(g4&7)>=3`` → tier-A ADD path"},
)

# --- Static writers to ``record+0x14`` (negative scan summary) -----------------

PLUS14_WRITERS = (
    {
        "path": "``0x05CEC0``–``0x05CF50``",
        "result": "Writes ``+0x00``/``+0x10``/``+0x20`` only — **no** ``+0x14``",
    },
    {
        "path": "``0x05DE00`` emit (@ ``0x05D524`` ``E``/``f``/``g`` only)",
        "result": "Fills handler blob via ``0x05DFA4`` — **not** ``D``/``U``",
    },
    {
        "path": "``0x05D5AC`` ``st r11,(g4)``",
        "result": "Bytecode chain head into arena frame — separate from ``+0x14``",
    },
)


def _desert_1111_payload(main_data: bytes) -> bytes:
    from tools.decomp.palette_29eb0_stream_walker import _desert_1111_payload as _load

    return _load(main_data)


def _block_head_dwords(main_data: bytes) -> dict[str, Any]:
    facts = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    from tools.model2_palette import find_cgm_blocks

    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    blob = main_data[block.rom_offset : block.rom_offset + 48]
    rows = []
    for off in range(0, 48, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        rows.append({"offset": f"+0x{off:02X}", "u32": f"0x{w:08X}"})
    w14 = struct.unpack_from("<I", blob, 0x14)[0]
    return {
        "block_vaddr": facts["vaddr"],
        "word0": facts["word0_at_vaddr"],
        "word0_ascii": facts["head_vaddr_bytes_ascii"],
        "plus_0x14_u32": f"0x{w14:08X}",
        "plus_0x14_is_pointer": (0x02000000 <= w14 <= 0x02FFFFFF) or (0x005C0000 <= w14 <= 0x005FFFFF),
        "dwords": rows,
        "29f9c_stored_to_row_plus4": (
            "``0x29F9C`` stores ``lda 0x40(fp)`` = first block dword (``0x204D4743`` ``CGM ``) — "
            "not a main_data pointer; ``ld (0x204D4743)`` / ``+0x14`` invalid in static model"
        ),
    }


def _fifo_read_inventory(main_data: bytes, *, slot: int, raw_u16: int) -> dict[str, Any]:
    payload = _desert_1111_payload(main_data)
    pal = PaletteState()
    pal._install_default_lumaram()
    load_colorxlat_from_main_data(pal, main_data)
    staging = CgmStagingSim(slot_base=14, stream_cursor=14)
    staging.begin_record()
    stream = _StreamState(staging=staging)
    replay = Cgm1111Replay()
    reads: list[dict[str, Any]] = []

    def read_u16() -> int | None:
        if stream.bin_pos + 1 >= len(stream.binary):
            return None
        pos = stream.bin_pos
        value = stream.binary[stream.bin_pos] | (stream.binary[stream.bin_pos + 1] << 8)
        stream.bin_pos += 2
        reads.append(
            {
                "index": len(reads),
                "fifo_offset": pos,
                "fifo_offset_hex": f"0x{pos:X}",
                "u16": f"0x{value:04X}",
                "slot_after": staging.stream_cursor,
            }
        )
        return value

    stream.read_u16 = read_u16
    chunks = _split_inner_chunks(payload)
    pending: list[str] = []
    for chunk in chunks:
        replay.chunks_seen += 1
        if not chunk:
            continue
        if _is_format_chunk(chunk):
            text = chunk.decode("latin1", errors="replace")
            stream.format_frag = text
            bb, cb = stream.bin_pos, staging.stream_cursor
            _execute_format_chunk(stream, pal, replay, text)
            if not _format_chunk_made_progress(stream, bin_pos_before=bb, cursor_before=cb):
                pending.append(text)
        else:
            stream.binary.extend(chunk)
            _drain_pending_formats(stream, pal, replay, pending)

    needle = raw_u16 & 0xFFFF
    hits = [r for r in reads if int(r["u16"], 16) == needle]
    slot_hit = next((r for r in hits if r["slot_after"] == slot), None)

    return {
        "total_u16_reads": len(reads),
        "fifo_len_bytes": len(stream.binary),
        "raw_hits": hits,
        "slot_focus_hit": slot_hit,
        "reads_before_slot_hit": slot_hit["index"] if slot_hit else None,
        "note": (
            "Replay order = marker-split format-walk; ``0x29CF8`` ADD loop count is "
            "compile-record inner ``ldis`` bound — not necessarily this read index"
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(None), SRALLY_DATA_ROMS["main_data"])
    block = _block_head_dwords(main_data)
    fifo = _fifo_read_inventory(main_data, slot=slot, raw_u16=raw_u16)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM/main_data bytes + replay FIFO trace — no XOR inference",
        "focus": {"slot": slot, "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}"},
        "plus14_consumers": list(PLUS14_CONSUMERS),
        "plus14_static_writers": list(PLUS14_WRITERS),
        "desert_block_head": block,
        "call_29ff8_args": list(CALL_29FF8_ARGS),
        "fifo_read_inventory": fifo,
        "linkage_analysis": {
            "replay_fifo_offset": (fifo.get("slot_focus_hit") or {}).get("fifo_offset_hex"),
            "replay_read_index": fifo.get("reads_before_slot_hit"),
            "29c10_fifo_insn": "0x29CF8 ldos (g7) where g7 = lda 0x14(g0)",
            "static_block_plus14": block["plus_0x14_u32"],
            "static_link_possible": False,
            "reason": (
                "``+0x14`` on block-head dword ``0x204D4743`` is not a valid pointer; "
                "``0x29F9C`` row ``+4`` stores that dword; ``0x29CC4`` reloads it as ``g0``. "
                "FIFO cursor @ ``+0x14`` requires runtime record fixup or a different ``g0`` "
                "chain than static desert bytes.  ``D`` path does not populate ``+0x14`` via ``0x05DE00``."
            ),
        },
        "conclusions": (
            "``record+0x14`` is **overloaded**: handler table index (@ ``0x02A10C``) vs FIFO cursor ptr (@ ``0x29CDC``).",
            "Desert block ``+0x14`` = ``0x03FF3231`` — not a workram/main_data pointer; static ``0x29CDC`` path OPEN.",
            f"Replay slot {slot} ``0x8843`` @ FIFO ``0x3A6`` after **{fifo.get('reads_before_slot_hit')}** prior u16 reads (format-walk order).",
            "``0x29FF8`` → ``0x029C10`` on matched tail uses ``g2=0x20C954`` snapshot — tier-A ADD; "
            "does not statically enumerate to replay slot 477 without stream-node fixup.",
            "Hardware lone-``D`` decode remains OPEN: ADD path ≠ xor_table oracle ``0x6683``.",
        ),
        "open_gaps": (
            "Runtime block-head fixup before ``0x29EF4`` ``ld (r5)`` (``0x204D4743`` → live list root)",
            "Who stores FIFO cursor pointer at compile-record ``+0x14`` on ``D``/``U`` path",
            "Map ``0x29CB8`` group index ``g2+g3`` → replay fifo read index / slot 477",
            "``0x02A120`` reachability for ``0x1111`` record-end vs ``0x29C10`` tail",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="record+0x14 vs FIFO slot 477 RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_record_plus14_fifo_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    link = report["linkage_analysis"]
    fifo = report["fifo_read_inventory"]
    hit = fifo.get("slot_focus_hit") or {}
    print(f"Block +0x14: {report['desert_block_head']['plus_0x14_u32']}  pointer={report['desert_block_head']['plus_0x14_is_pointer']}")
    print(
        f"Slot {args.slot}: fifo {hit.get('fifo_offset_hex')} "
        f"read_index={fifo.get('reads_before_slot_hit')} total_reads={fifo.get('total_u16_reads')}"
    )
    print(f"\n{link['reason'][:120]}…")


if __name__ == "__main__":
    main()
