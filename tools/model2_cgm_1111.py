"""CGM v16 type-0x1111 palette bytecode replay (ROM 0x29EB0 path).

The desert course block @ main_data 0x028CCAF8 ends with a 4369-byte type-0x1111
record after the leading 13 colorbase slots and a lumaram 0x0010 run. Geometry
references ~189 palette slots >= 14; those slots are filled only when this record
is replayed.

Hardware flow (maincpu disasm):
  0x29EB0  parse CGM block; 0x5CE18/0x5CEC0 build scanf-like thunks @ 0x5C8E60
  0x29FAC  per-record loop; 0x2A0F8 dispatches via descriptor @ stream+0x10
  0x2A120  type-0x1111 linked-list merge + palram flush @ 0x26918
  0x2A200  batched staging XOR (setbit 6+15 on g13 @ 0x2A234, xor @ 0x2A258)
  0x2A290  seed 0x20C958 = cursor<<7, advance 0x20C950 by 24
  0x2A490  scratch colorbase write (slot anchor = mask>>7)
  0x29CFC  ADD g13 staging path for ``U`` (@ 0x29C10)

The payload is NOT a flat (slot, color15) table. Roughly 400 inner ``0x1111``
markers split the stream into chunks that alternate embedded format fragments
(``3#333#DD3#UE…``) with binary parameter bytes.

Replay walks the interleaved chunk stream directly (no workram thunks @ 0x5C9118):
  * binary chunks extend a shared parameter FIFO
  * format chunks are deferred until the FIFO has enough atoms (hardware order)
  * digits set repeat for the next opcode (@ 0x27008); ``#`` does not clear repeat
  * ``D`` read u16 × repeat, decode via ``decode_d_u16`` (default ``merge_raw`` @ ``0x2A4E0``), scratch
  * ``T`` nop (@ ``0x05FC9B4`` — no FIFO read)
  * ``U`` read u16 × repeat, ADD g13 (@ ``0x29CFC``)
  * ``#`` batched second XOR over staging (@ ``0x2A200``, ``g3>0``)
  * ``0x2A290`` seeds ``0x20C958 = cursor<<7``; slots ``[anchor,anchor+24)`` use ``0x8040``,
    ``slot >= anchor+24`` use ``(slot<<7)|0x8040`` (@ ``0x2A3AC`` lookup table)
  * zero color15 after decode does not advance ``0x20C950``
  * record end: ``0x2A120`` scratch flush → ``0x26918`` palram commit
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.model2_cgm_staging import CgmStagingSim, D_DECODE_MERGE_RAW
from tools.model2_palette import PaletteState

CGM_RECORD_1111 = 0x1111


@dataclass
class Cgm1111Replay:
    """Outcome of attempting to replay a type-0x1111 record."""

    slots_written: dict[int, int] = field(default_factory=dict)
    bytes_consumed: int = 0
    format_tokens: int = 0
    chunks_seen: int = 0
    errors: list[str] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)


@dataclass
class _StreamState:
    """Binary parameter FIFO + ``CgmStagingSim`` (@ ``0x20C950`` / ``0x20C958``)."""

    staging: CgmStagingSim
    binary: bytearray = field(default_factory=bytearray)
    bin_pos: int = 0
    trace_slots: frozenset[int] | None = None
    trace: list[dict] | None = None
    chunk_idx: int = 0
    format_frag: str = ""

    def read_u16(self) -> int | None:
        if self.bin_pos + 1 >= len(self.binary):
            return None
        value = self.binary[self.bin_pos] | (self.binary[self.bin_pos + 1] << 8)
        self.bin_pos += 2
        return value

    def read_u32(self) -> int | None:
        if self.bin_pos + 3 >= len(self.binary):
            return None
        value = int.from_bytes(self.binary[self.bin_pos : self.bin_pos + 4], "little")
        self.bin_pos += 4
        return value

    def _maybe_trace(
        self,
        *,
        op: str,
        slot: int,
        raw_u16: int,
        color15: int,
    ) -> None:
        if self.trace is None or self.trace_slots is None:
            return
        if slot not in self.trace_slots:
            return
        g13 = self.staging.g13_for_slot(slot) & 0xFFFF
        self.trace.append(
            {
                "chunk": self.chunk_idx,
                "format_frag": self.format_frag[:120],
                "bin_pos": self.bin_pos,
                "op": op,
                "slot": slot,
                "raw": f"0x{raw_u16:04x}",
                "g13": f"0x{g13:04x}",
                "color15": f"0x{color15:04x}",
                "g13_seed": f"0x{self.staging.g13_mask:04x}",
            }
        )

    def upload_d(self, state: PaletteState, replay: Cgm1111Replay, raw_u16: int) -> None:
        """``D``: ``0x2A4E0`` merge + scratch (@ ``0x2A490``) — not ``0x2A258`` XOR."""
        slot_before = self.staging.stream_cursor
        slot = self.staging.ingest_u16(state, raw_u16)
        if slot is not None:
            color15 = self.staging.scratch.get(slot, 0)
            replay.slots_written[slot] = color15
            self._maybe_trace(op="D", slot=slot, raw_u16=raw_u16, color15=color15)
        elif slot_before in (self.trace_slots or ()):
            self._maybe_trace(op="D_skip", slot=slot_before, raw_u16=raw_u16, color15=0)

    def upload_add(self, state: PaletteState, replay: Cgm1111Replay, raw_u16: int) -> None:
        """``U``: ADD g13, scratch write (@ ``0x29CFC`` / ``0x2A490``)."""
        slot_before = self.staging.stream_cursor
        slot = self.staging.ingest_u16_add(state, raw_u16)
        if slot is not None:
            color15 = self.staging.scratch.get(slot, 0)
            replay.slots_written[slot] = color15
            self._maybe_trace(op="U", slot=slot, raw_u16=raw_u16, color15=color15)
        elif slot_before in (self.trace_slots or ()):
            self._maybe_trace(op="U_skip", slot=slot_before, raw_u16=raw_u16, color15=0)

    def hash_batch(self, state: PaletteState, replay: Cgm1111Replay, repeat: int) -> None:
        """``#`` → second XOR pass over staging (@ ``0x2A200``, ``g3>0``)."""
        del state
        self.staging.op_2a200_hash_batch(repeat)
        end = self.staging.stream_cursor
        start = max(self.staging.slot_base, end - repeat)
        for slot in range(start, end):
            color15 = self.staging.scratch.get(slot, 0)
            if color15:
                replay.slots_written[slot] = color15


def _split_inner_chunks(payload: bytes) -> list[bytes]:
    """Split on little-endian ``0x1111`` markers (400 in the desert block)."""
    chunks: list[bytes] = []
    index = 0
    while index < len(payload) - 1:
        if payload[index] == 0x11 and payload[index + 1] == 0x11:
            end = index + 2
            while end < len(payload) - 1:
                if payload[end] == 0x11 and payload[end + 1] == 0x11:
                    break
                end += 1
            chunks.append(payload[index + 2 : end])
            index = end
        else:
            index += 1
    return chunks


def _is_format_chunk(chunk: bytes) -> bool:
    return bool(chunk) and all(32 <= byte < 127 for byte in chunk)


def _execute_format_chunk(
    stream: _StreamState,
    state: PaletteState,
    replay: Cgm1111Replay,
    text: str,
) -> None:
    """Walk one embedded format fragment; consume ``stream.binary`` at ``bin_pos``."""
    repeat = 1
    index = 0
    while index < len(text):
        char = text[index]

        if char.isdigit():
            value = 0
            while index < len(text) and text[index].isdigit():
                value = value * 10 + int(text[index])
                index += 1
            repeat = max(1, min(value, 512))
            continue

        if char == "#":
            stream.hash_batch(state, replay, repeat)
            replay.format_tokens += 1
            index += 1
            continue

        if char in "%!":
            replay.format_tokens += 1
            index += 1
            continue

        if char in "Dd":
            for _ in range(repeat):
                raw = stream.read_u16()
                if raw is not None:
                    stream.upload_d(state, replay, raw)
                replay.format_tokens += 1
            repeat = 1
            index += 1
            continue

        if char in "Uu":
            for _ in range(repeat):
                raw = stream.read_u16()
                if raw is not None:
                    stream.upload_add(state, replay, raw)
                replay.format_tokens += 1
            repeat = 1
            index += 1
            continue

        if char in "EefgG":
            for _ in range(repeat):
                stream.read_u32()
                replay.format_tokens += 1
            repeat = 1
            index += 1
            continue

        replay.format_tokens += 1
        repeat = 1
        index += 1


def _format_chunk_made_progress(
    stream: _StreamState,
    *,
    bin_pos_before: int,
    cursor_before: int,
) -> bool:
    return stream.bin_pos > bin_pos_before or stream.staging.stream_cursor > cursor_before


def _drain_pending_formats(
    stream: _StreamState,
    state: PaletteState,
    replay: Cgm1111Replay,
    pending: list[str],
) -> None:
    """Run deferred format fragments once more binary has arrived."""
    index = 0
    while index < len(pending):
        bin_pos_before = stream.bin_pos
        cursor_before = stream.staging.stream_cursor
        _execute_format_chunk(stream, state, replay, pending[index])
        if _format_chunk_made_progress(
            stream,
            bin_pos_before=bin_pos_before,
            cursor_before=cursor_before,
        ):
            pending.pop(index)
        else:
            index += 1


def replay_1111_record(
    state: PaletteState,
    payload: bytes,
    *,
    slot_base: int = 14,
    trace_slots: set[int] | frozenset[int] | None = None,
    d_decode: str | None = None,
) -> Cgm1111Replay:
    """Replay one type-0x1111 CGM payload into ``state.palram`` colorbase slots."""
    replay = Cgm1111Replay()
    if not payload:
        return replay

    trace_set = frozenset(trace_slots) if trace_slots else None
    staging = CgmStagingSim(
        slot_base=slot_base,
        stream_cursor=slot_base,
        d_decode=d_decode or D_DECODE_MERGE_RAW,
    )
    staging.begin_record()
    stream = _StreamState(
        staging=staging,
        trace_slots=trace_set,
        trace=replay.trace if trace_set else None,
    )
    chunks = _split_inner_chunks(payload)
    pending: list[str] = []

    for chunk in chunks:
        replay.chunks_seen += 1
        stream.chunk_idx = replay.chunks_seen
        if not chunk:
            continue
        if _is_format_chunk(chunk):
            text = chunk.decode("latin1", errors="replace")
            stream.format_frag = text
            bin_pos_before = stream.bin_pos
            cursor_before = stream.staging.stream_cursor
            _execute_format_chunk(stream, state, replay, text)
            if not _format_chunk_made_progress(
                stream,
                bin_pos_before=bin_pos_before,
                cursor_before=cursor_before,
            ):
                pending.append(text)
        else:
            stream.binary.extend(chunk)
            _drain_pending_formats(stream, state, replay, pending)

    for _ in range(len(pending) + 1):
        if not pending:
            break
        before = len(pending)
        _drain_pending_formats(stream, state, replay, pending)
        if len(pending) == before:
            break

    flushed = staging.finalize(state)
    replay.slots_written.update(flushed)

    replay.bytes_consumed = len(payload)
    return replay


def apply_cgm_v16_1111_records(
    state: PaletteState,
    data: bytes,
    block,
    *,
    slot_base: int = 14,
) -> Cgm1111Replay:
    """Apply all type-0x1111 records from a CGM v16 block."""
    from tools.model2_palette import _iter_cgm_v16_records

    merged = Cgm1111Replay()
    for rec_type, rec_len, payload_off in _iter_cgm_v16_records(data, block):
        if rec_type != CGM_RECORD_1111 or rec_len <= 0:
            continue
        payload = data[payload_off : payload_off + rec_len]
        part = replay_1111_record(state, payload, slot_base=slot_base)
        merged.slots_written.update(part.slots_written)
        merged.bytes_consumed += part.bytes_consumed
        merged.format_tokens += part.format_tokens
        merged.chunks_seen += part.chunks_seen
        merged.errors.extend(part.errors)
    return merged


def main() -> None:
    import argparse
    from pathlib import Path

    from tools.model2_palette import (
        COURSE_CGM_VADDRS,
        find_cgm_blocks,
        load_palette_from_main_data,
        PALRAM_COLORBASE_WORD,
    )
    from tools.rom_io import load32_word_region, resolve_rom_dir, SRALLY_DATA_ROMS

    parser = argparse.ArgumentParser(description="Analyze/replay CGM 0x1111 palette bytecode")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--apply", action="store_true", help="Write decoded slots into palette state")
    parser.add_argument("--slot", type=int, default=None, help="Print one replayed colorbase slot")
    parser.add_argument(
        "--trace-slot",
        type=int,
        action="append",
        dest="trace_slots",
        metavar="SLOT",
        help="Log FIFO decode steps for slot(s) >= 38 (repeatable)",
    )
    from tools.model2_cgm_staging import D_DECODE_MODES, D_DECODE_MERGE_RAW

    parser.add_argument(
        "--d-decode",
        choices=D_DECODE_MODES,
        default=D_DECODE_MERGE_RAW,
        help="Single-D FIFO decode mode (compare via palette_d_path_compare)",
    )
    parser.add_argument(
        "--g13-report",
        action="store_true",
        help="Print g13 table vs flat-0x8040 divergence for high slots",
    )
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    blocks = {b.vaddr: b for b in find_cgm_blocks(main_data)}
    block = blocks.get(COURSE_CGM_VADDRS[1])
    if block is None:
        raise SystemExit("desert CGM v16 block not found")

    palette = load_palette_from_main_data(main_data) if args.apply else PaletteState()
    trace_slots = set(args.trace_slots or [])
    if args.g13_report:
        from tools.model2_cgm_g13_table import mask_divergence_report

        for row in mask_divergence_report(14 << 7, (38, 45, 100, 477)):
            flag = " *" if row["diverges"] else ""
            print(
                f"slot {row['slot']:3d}: table={row['table_mask']} flat={row['flat_mask']}{flag}"
            )

    if trace_slots:
        from tools.model2_palette import _iter_cgm_v16_records

        trace_state = PaletteState()
        trace_state._install_default_lumaram()
        result = Cgm1111Replay()
        for rec_type, rec_len, payload_off in _iter_cgm_v16_records(main_data, block):
            if rec_type != CGM_RECORD_1111 or rec_len <= 0:
                continue
            payload = main_data[payload_off : payload_off + rec_len]
            result = replay_1111_record(
                trace_state,
                payload,
                trace_slots=trace_slots,
                d_decode=args.d_decode,
            )
            break
        if args.apply:
            for slot, color15 in result.slots_written.items():
                from tools.model2_palette import _write_colorbase

                _write_colorbase(palette, slot, color15)
    else:
        result = apply_cgm_v16_1111_records(palette, main_data, block)

    print(f"slots_written: {len(result.slots_written)}")
    print(
        f"chunks_seen: {result.chunks_seen}  format_tokens: {result.format_tokens}  "
        f"bytes_consumed: {result.bytes_consumed}"
    )
    if args.slot is not None:
        slot = args.slot
        print(f"slot {slot}: replay=0x{result.slots_written.get(slot, 0):04x}", end="")
        if args.apply:
            print(f" palram=0x{palette.palram[PALRAM_COLORBASE_WORD + slot]:04x}")
        else:
            print()
    if result.trace:
        print(f"trace ({len(result.trace)} events):")
        for ev in result.trace:
            print(
                f"  chunk={ev['chunk']} bin_pos={ev['bin_pos']} {ev['op']} "
                f"slot={ev['slot']} raw={ev['raw']} g13={ev['g13']} "
                f"→ {ev['color15']} seed={ev['g13_seed']}"
            )
    if result.errors:
        print(f"errors: {len(result.errors)} (first: {result.errors[0]!r})")
    for slot in sorted(result.slots_written)[:20]:
        print(f"  slot {slot:3d} (0x{slot:03x}) → 0x{result.slots_written[slot]:04x}")
    if len(result.slots_written) > 20:
        print(f"  … {len(result.slots_written) - 20} more")


if __name__ == "__main__":
    main()
