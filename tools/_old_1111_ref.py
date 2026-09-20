"""CGM v16 type-0x1111 palette bytecode replay (ROM 0x29EB0 path).

The desert course block @ main_data 0x028CCAF8 ends with a 4369-byte type-0x1111
record after the leading 13 colorbase slots and a lumaram 0x0010 run. Geometry
references ~189 palette slots >= 14; those slots are filled only when this record
is replayed.

Hardware flow (maincpu disasm):
  0x29EB0  parse CGM block; 0x5CE18/0x5CEC0 build scanf-like thunks @ 0x5C8E60
  0x29FAC  per-record loop; 0x2A0F8 dispatches via descriptor @ stream+0x10
  0x2A120  type-0x1111 linked-list merge + palram flush @ 0x26918
  0x2A200  batched u16 palram upload (XOR 0x8040)
  0x2A2E0  ASCII digit / nybble staging helpers
  0x2A410  staging write → 0x01080000 family
  0x2A490  colorbase table write → palram 0x01802000 (slot * 0x20)

The payload is NOT a flat (slot, color15) table. Roughly 400 inner ``0x1111``
markers split the stream into chunks that alternate embedded format fragments
(``3#333#DD3#UE…``) with binary parameter bytes. The 0x5CF50 format compiler
builds runtime thunks @ 0x5C9118 (zero in the static ROM image); this module
replays the interleaved chunk stream directly:

  * binary chunks extend a shared parameter buffer
  * format chunks walk 0x5CF50-style ``D``/``U`` (u16) and ``E``/``f`` (u32) reads
  * ``D``/``U`` uploads XOR with 0x8040 (0x2A200) into colorbase slots
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.model2_palette import PaletteState, _write_colorbase

CGM_RECORD_1111 = 0x1111
PALRAM_UPLOAD_XOR = 0x8040  # 0x2A200: xor g13=0x8040 before staging store


@dataclass
class Cgm1111Replay:
    """Outcome of attempting to replay a type-0x1111 record."""

    slots_written: dict[int, int] = field(default_factory=dict)
    bytes_consumed: int = 0
    format_tokens: int = 0
    chunks_seen: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class _StreamState:
    """Workram stand-in: binary parameter FIFO + slot cursor."""

    slot_next: int
    binary: bytearray = field(default_factory=bytearray)
    bin_pos: int = 0

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

    def upload_u16(self, state: PaletteState, replay: Cgm1111Replay, raw_u16: int) -> None:
        """0x2A200: XOR 0x8040 then store into the next colorbase slot."""
        color15 = (int(raw_u16) ^ PALRAM_UPLOAD_XOR) & 0x7FFF
        if not color15:
            return
        slot = self.slot_next
        self.slot_next += 1
        _write_colorbase(state, slot, color15)
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
    """Walk one embedded format fragment; consume ``stream.binary`` at ``bin_pos``.

    Digits set a repeat count for the next opcode (``0x27008`` workram counters in
    hardware). ``D``/``U``/``T`` read u16 and upload via ``0x2A200`` (XOR 0x8040).
    """
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

        if char in "#%!":
            replay.format_tokens += 1
            index += 1
            continue

        if char in "DdUuTt":
            for _ in range(repeat):
                raw = stream.read_u16()
                if raw is not None:
                    stream.upload_u16(state, replay, raw)
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

        # Letters like C/H and punctuation are no-ops in the desert block.
        replay.format_tokens += 1
        index += 1


def _run_format_chunks(
    stream: _StreamState,
    state: PaletteState,
    replay: Cgm1111Replay,
    chunks: list[bytes],
) -> None:
    for chunk in chunks:
        if not chunk or not _is_format_chunk(chunk):
            continue
        _execute_format_chunk(
            stream,
            state,
            replay,
            chunk.decode("latin1", errors="replace"),
        )


def replay_1111_record(
    state: PaletteState,
    payload: bytes,
    *,
    slot_base: int = 14,
) -> Cgm1111Replay:
    """Replay one type-0x1111 CGM payload into ``state.palram`` colorbase slots."""
    replay = Cgm1111Replay()
    if not payload:
        return replay

    stream = _StreamState(slot_next=slot_base)
    chunks = _split_inner_chunks(payload)
    format_chunks = [c for c in chunks if c]

    for chunk in chunks:
        replay.chunks_seen += 1
        if not chunk:
            continue
        if _is_format_chunk(chunk):
            _execute_format_chunk(
                stream,
                state,
                replay,
                chunk.decode("latin1", errors="replace"),
            )
        else:
            stream.binary.extend(chunk)

    # 0x2A120 flush pass: if parameter bytes remain, re-walk format thunks from the
    # start of the FIFO (hardware may invoke compiled thunks @ 0x5C9118 more than once).
    if stream.bin_pos < len(stream.binary):
        stream.bin_pos = 0
        _run_format_chunks(stream, state, replay, format_chunks)

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
    )
    from tools.rom_io import load32_word_region, resolve_rom_dir, SRALLY_DATA_ROMS

    parser = argparse.ArgumentParser(description="Analyze/replay CGM 0x1111 palette bytecode")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--apply", action="store_true", help="Write decoded slots into palette state")
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    blocks = {b.vaddr: b for b in find_cgm_blocks(main_data)}
    block = blocks.get(COURSE_CGM_VADDRS[1])
    if block is None:
        raise SystemExit("desert CGM v16 block not found")

    palette = load_palette_from_main_data(main_data) if args.apply else PaletteState()
    result = apply_cgm_v16_1111_records(palette, main_data, block)

    print(f"slots_written: {len(result.slots_written)}")
    print(
        f"chunks_seen: {result.chunks_seen}  format_tokens: {result.format_tokens}  "
        f"bytes_consumed: {result.bytes_consumed}"
    )
    if result.errors:
        print(f"errors: {len(result.errors)} (first: {result.errors[0]!r})")
    for slot in sorted(result.slots_written)[:20]:
        print(f"  slot {slot:3d} (0x{slot:03x}) → 0x{result.slots_written[slot]:04x}")
    if len(result.slots_written) > 20:
        print(f"  … {len(result.slots_written) - 20} more")


if __name__ == "__main__":
    main()
