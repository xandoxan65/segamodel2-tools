#!/usr/bin/env python3
"""Disasm-backed trace: ``0x029F7C`` group row → ``0x02A0F8`` record dispatch.

Reports only what i960 disasm proves plus ROM/CGM byte facts.  Does **not**
infer FIFO decode, XOR, or workram thunk bodies (@ ``0x005C9118``).

Sources:
  ``decomp/disasm/maincpu/maincpu_029eb0_600.asm`` (@ ``0x029F7C``)
  ``decomp/disasm/maincpu/maincpu_02a0f8_400.asm`` (@ ``0x02A0F8``)
  ``decomp/disasm/maincpu/maincpu_05cec0_300.asm`` (compile output @ ``g13``)

  python3 -m tools.decomp.palette_2a0f8_record_trace
  python3 -m tools.decomp.palette_2a0f8_record_trace --slot 477
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_disasm_provenance import OPEN_GAPS
from tools.decomp.palette_29eb0_stream_walker import build_report as build_stream_walk_report
from tools.model2_cgm_1111 import (
    CGM_RECORD_1111,
    _is_format_chunk,
    _split_inner_chunks,
    replay_1111_record,
)
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment, decode_bytecode_stream
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    load_palette_from_main_data,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Disasm-proven layouts (offsets only; values live in workram) ----------------

TRAMPOLINE_2A0F8 = 0x005C9118  # lda @ 0x02A0F0; bx target saved in g1 @ 0x02A0F8
GROUP_TABLE = 0x0020B950  # lda 0x20b950[g4*8] @ 0x029F88 — 8 bytes per index
COUNTER_20C950 = 0x0020C950  # colorbase slot cursor (@ 0x29F98, 0x29F5C, …)
COUNTER_20C954 = 0x0020C954  # inner-loop index @ 0x029F7C; also merge cursor @ 0x02A120
FRAME_STREAM_PTR = 0x40  # fp+0x40 — compile record pointer stored @ group row +4


@dataclass(frozen=True)
class DisasmInsn:
    rom: str
    effect: str


DISASM_2A0F8: tuple[DisasmInsn, ...] = (
    DisasmInsn("0x02A0F0", "``lda 0x005C9118,g14``"),
    DisasmInsn("0x02A0F8", "``mov g14,g1`` — bx target trampoline"),
    DisasmInsn("0x02A100", "``ldis 0x10(g0),g4`` — record halfword @ +0x10"),
    DisasmInsn("0x02A104", "``ldis 0x12(g0),g5`` — record halfword @ +0x12"),
    DisasmInsn("0x02A108", "``mulo g4,g5,g4`` — table index"),
    DisasmInsn("0x02A10C", "``lda 0x14(g0)[g4*2],g0`` — handler word → bx arg"),
    DisasmInsn("0x02A114", "``bx (g1)`` — indirect via ``0x005C9118``"),
)


DISASM_29F7C_PRE: tuple[DisasmInsn, ...] = (
    DisasmInsn("0x029F7C", "``ld 0x20C954,g4`` — group-table index (not ``0x20C950``)"),
    DisasmInsn("0x029F84", "``ld 0x40(fp),g0`` — compile-record pointer for ``0x02A0F8``"),
    DisasmInsn("0x029F88", "``lda 0x20B950[g4*8],g4`` — group row pointer"),
    DisasmInsn("0x029F90", "``stos r10,(g4)`` — row +0 u16 (``r10`` from prior ``shlo 7,g0``)"),
    DisasmInsn("0x029F94", "``stob g14,0x2(g4)`` — row +2 u8"),
    DisasmInsn("0x029F98", "``stob g14,0x3(g4)`` — row +3 u8"),
    DisasmInsn("0x029F9C", "``st g0,0x4(g4)`` — row +4 u32 compile record ptr"),
    DisasmInsn("0x029FA0", "``bal 0x02A0F8``"),
    DisasmInsn("0x029FB4", "``addo g4,1,g4; st g4,0x20C954`` — increment group index"),
)


DISASM_5CEC0_OUTPUT: tuple[DisasmInsn, ...] = (
    DisasmInsn("0x05CEE0", "``stq g4,0x10(g13)`` — 8 bytes @ record +0x10 (``ldis`` fields for ``0x02A0F8``)"),
    DisasmInsn("0x05CEE4", "``stq g0,(g13)`` — record +0x00"),
    DisasmInsn("0x05CEF0", "``stq g8,0x20(g13)`` — record +0x20"),
    DisasmInsn("0x05CEF8", "``st g13,(g1)``; ``st r5,0x4(g1)`` — link compiled node"),
    DisasmInsn("0x05CF00", "``call 0x05CF50`` — format-string bytecode emit"),
)


def dispatch_index(*, half_at_10: int, half_at_12: int) -> int:
    """``0x02A108`` ``mulo g4,g5,g4`` (16-bit operands)."""
    return (int(half_at_10) & 0xFFFF) * (int(half_at_12) & 0xFFFF) & 0xFFFF


def handler_word_offset(index: int) -> int:
    """Byte offset of u16 handler entry: ``0x02A10C`` ``lda 0x14(g0)[g4*2]``."""
    return 0x14 + (int(index) & 0xFFFF) * 2


def group_row_layout(
    *,
    r10_u16: int | None,
    g14_u8: int | None,
    record_ptr: int | None,
) -> dict[str, Any]:
    """Fields written @ ``0x029F90``–``0x029F9C`` before ``bal 0x02A0F8``."""
    row: dict[str, Any] = {
        "+0x00": {"size": 2, "disasm": "stos r10,(g4)", "value": None},
        "+0x02": {"size": 1, "disasm": "stob g14,0x2(g4)", "value": None},
        "+0x03": {"size": 1, "disasm": "stob g14,0x3(g4)", "value": None},
        "+0x04": {"size": 4, "disasm": "st g0,0x4(g4)", "value": None},
    }
    if r10_u16 is not None:
        row["+0x00"]["value"] = f"0x{int(r10_u16) & 0xFFFF:04x}"
    if g14_u8 is not None:
        v = int(g14_u8) & 0xFF
        row["+0x02"]["value"] = f"0x{v:02x}"
        row["+0x03"]["value"] = f"0x{v:02x}"
    if record_ptr is not None:
        row["+0x04"]["value"] = f"0x{int(record_ptr) & 0xFFFFFFFF:08x}"
    return row


def compile_record_layout_note() -> dict[str, Any]:
    """``g0`` at ``0x02A0F8`` = compile-record pointer (from ``0x40(fp)`` @ ``0x029F84``)."""
    return {
        "g0_source": f"fp+0x{FRAME_STREAM_PTR:X} (stored to group row +4 @ 0x029F9C)",
        "fields_read_by_2a0f8": {
            "+0x10": "ldis → mul operand g4",
            "+0x12": "ldis → mul operand g5",
            "+0x14": f"handler u16 table; selected entry @ +0x14 + index*2",
        },
        "index_formula": "index = half(+0x10) * half(+0x12)  (@ 0x02A108)",
        "handler_select": "handler_u16 = u16(record + 0x14 + index*2)  (@ 0x02A10C)",
        "bx_trampoline": f"0x{TRAMPOLINE_2A0F8:08X} (zero in static ROM; body not in ROM image)",
        "values_in_static_rom": False,
    }


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def _build_binary_fifo(payload: bytes) -> tuple[bytearray, list[dict[str, Any]]]:
    """Walk inner chunks; collect binary bytes only (CGM layout, no decode)."""
    fifo = bytearray()
    chunk_log: list[dict[str, Any]] = []
    for idx, chunk in enumerate(_split_inner_chunks(payload), start=1):
        entry: dict[str, Any] = {
            "chunk": idx,
            "kind": "format" if _is_format_chunk(chunk) else "binary",
            "size": len(chunk),
            "fifo_offset_before": len(fifo),
        }
        if _is_format_chunk(chunk):
            entry["format_frag"] = chunk.decode("latin1", errors="replace")
        else:
            fifo.extend(chunk)
            entry["fifo_offset_after"] = len(fifo)
        chunk_log.append(entry)
    return fifo, chunk_log


def _u16_le(data: bytes, pos: int) -> int | None:
    if pos < 0 or pos + 1 >= len(data):
        return None
    return data[pos] | (data[pos + 1] << 8)


def _replay_slot_facts(main_data: bytes, slot: int) -> dict[str, Any] | None:
    """CGM chunk/bin_pos for a slot from ``replay_1111_record`` trace (correlation only)."""
    state = PaletteState()
    state._install_default_lumaram()
    from tools.model2_palette import load_colorxlat_from_main_data

    load_colorxlat_from_main_data(state, main_data)
    payload = _desert_1111_payload(main_data)
    replay = replay_1111_record(state, payload, trace_slots=frozenset({slot}))
    if not replay.trace:
        return None
    row = replay.trace[0]
    return {
        "slot": slot,
        "chunk": row.get("chunk"),
        "format_frag": row.get("format_frag"),
        "bin_pos": row.get("bin_pos"),
        "note": (
            "From Python format-walk replay (skips ``0x005C9118`` thunks). "
            "Use for CGM byte correlation only — not hardware execution order."
        ),
    }


def _emit_trace_for_fragment(format_frag: str) -> dict[str, Any]:
    """``0x05CF50``/``0x05D860`` static emit sim — bytecode shape only."""
    events = compile_format_fragment(format_frag, template_rows=None)
    d_events = [e for e in events if e.get("op") == "D"]
    last_d = d_events[-1] if d_events else None
    out: dict[str, Any] = {
        "format_frag": format_frag,
        "d_handler_count": len(d_events),
        "compile_events": events,
    }
    if last_d:
        bc = [int(x, 16) for x in last_d.get("bytecode", [])]
        bound = bind_and_run(bc)
        out["last_d"] = {
            "repeat": last_d.get("repeat"),
            "r9": f"0x{int(last_d.get('r9', 0)):02x}",
            "bytecode": last_d.get("bytecode"),
            "bytecode_decoded": decode_bytecode_stream(bc),
            "stub_patches": bound.stub_patches,
            "descriptors": {str(k): f"0x{v:04x}" for k, v in bound.descriptors.items()},
            "disasm": "0x05D3DC setbit0,r9 → 0x05D860 bal 0x027008 (static sim)",
        }
    return out


def build_report(*, focus_slot: int | None = None) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    payload = _desert_1111_payload(main_data)
    fifo, chunk_log = _build_binary_fifo(payload)

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + CGM ROM bytes — no XOR/decode inference",
        "disasm_2a0f8": [{"rom": i.rom, "effect": i.effect} for i in DISASM_2A0F8],
        "disasm_29f7c_pre_call": [{"rom": i.rom, "effect": i.effect} for i in DISASM_29F7C_PRE],
        "disasm_5cec0_output": [{"rom": i.rom, "effect": i.effect} for i in DISASM_5CEC0_OUTPUT],
        "compile_record_layout": compile_record_layout_note(),
        "workram_addresses": {
            "0x20C950": "colorbase slot cursor (disasm @ 0x29F5C, 0x2A18C, …)",
            "0x20C954": "group-table index @ 0x029F7C (disasm @ 0x29F7C — not same as 0x20C950)",
            "0x20B950": "8-byte group rows; index = 0x20C954 at 0x029F7C",
            "0x005C9118": "bx trampoline @ 0x02A0F8; zero in static ROM",
        },
        "desert_1111": {
            "payload_bytes": len(payload),
            "inner_chunks": len(chunk_log),
            "binary_fifo_bytes": len(fifo),
            "chunk_log_head": chunk_log[:8],
        },
        "open_gaps": [g["id"] for g in OPEN_GAPS],
        "cannot_derive_from_rom": [
            "Compile-record halfwords @ +0x10/+0x12 and handler table @ +0x14 (workram)",
            "0x005C9118 thunk machine code after boot",
            "Which 0x20C954 group index corresponds to a given colorbase slot without full 0x29EB0 stream parse",
            "FIFO → color15 transform inside bx target",
        ],
    }

    if focus_slot is not None:
        slot_facts = _replay_slot_facts(main_data, focus_slot)
        report["focus_slot"] = focus_slot
        report["cgm_correlation"] = slot_facts

        if slot_facts:
            frag = slot_facts.get("format_frag") or ""
            bin_pos = int(slot_facts.get("bin_pos") or 0)
            raw = _u16_le(fifo, bin_pos - 2)
            report["cgm_bytes"] = {
                "fifo_len": len(fifo),
                "bin_pos": bin_pos,
                "raw_u16_at_bin_pos_minus_2": f"0x{raw:04x}" if raw is not None else None,
                "fifo_window": fifo[max(0, bin_pos - 8) : bin_pos + 4].hex(),
            }
            report["static_d_emit"] = _emit_trace_for_fragment(frag)

            report["2a0f8_dispatch"] = {
                "formula": "index = half(+0x10) * half(+0x12); handler @ +0x14 + index*2",
                "r10_formula": "row+0 u16 = r10 where r10 = (0x20C950 << 7) @ 0x29F28 (timing vs 0x029F7C not traced)",
                "example_if_dims_1x1": {
                    "half_at_10": 1,
                    "half_at_12": 1,
                    "index": dispatch_index(half_at_10=1, half_at_12=1),
                    "handler_word_byte_offset": handler_word_offset(
                        dispatch_index(half_at_10=1, half_at_12=1)
                    ),
                },
                "record_bytes_required": "workram compile output — not present in static ROM",
            }

            if raw is not None:
                stream = build_stream_walk_report(focus_raw=raw)
                report["stream_walker"] = {
                    "fifo_hits": (stream.get("focus_raw") or {}).get("fifo_hits"),
                    "format_segment_nearby": next(
                        (
                            s
                            for s in stream.get("segments", [])
                            if s.get("format_frag", "").startswith("3333DD3D")
                        ),
                        None,
                    ),
                    "note": (
                        "0x8843 ROM locations in binary FIFO; segment 85 carries format "
                        "frag; hardware linked-list layout may differ from marker split."
                    ),
                }

    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x02A0F8 record dispatch trace (disasm-only)")
    parser.add_argument("--slot", type=int, default=477, help="Correlate desert CGM bytes for slot")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_2a0f8_record_trace.json",
    )
    args = parser.parse_args()

    report = build_report(focus_slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    corr = report.get("cgm_correlation") or {}
    if corr:
        print(f"\nSlot {args.slot} CGM correlation (format-walk, not hardware order):")
        print(f"  chunk={corr.get('chunk')} bin_pos={corr.get('bin_pos')}")
        frag = corr.get("format_frag") or ""
        print(f"  format_frag: {frag[:72]}{'…' if len(frag) > 72 else ''}")

    cgm = report.get("cgm_bytes") or {}
    if cgm.get("raw_u16_at_bin_pos_minus_2"):
        print(f"  FIFO raw u16 @ bin_pos-2: {cgm['raw_u16_at_bin_pos_minus_2']}")

    emit = report.get("static_d_emit") or {}
    last = emit.get("last_d") or {}
    if last:
        print(f"\nStatic D emit (0x05D860 sim): repeat={last.get('repeat')} r9={last.get('r9')}")
        bc = last.get("bytecode") or []
        print(f"  bytecode ({len(bc)} bytes): {' '.join(bc[:12])}{'…' if len(bc) > 12 else ''}")
        print(f"  stub_patches: {len(last.get('stub_patches') or [])}")

    print("\nOpen (not in static ROM):")
    for item in report.get("cannot_derive_from_rom", []):
        print(f"  - {item}")


if __name__ == "__main__":
    main()
