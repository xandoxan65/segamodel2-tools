"""CGM palette block replay (ROM 0x29EB0 / 0x12E00 path).

Handlers (maincpu disasm):
  0x2A050  leading colorbase upload (slots 1..N from CGM header)
  0x2A0F8  record handler dispatch (descriptor @ stream+0x10)
  0x2A120  type-0x1111 linked-list / staging flush
  0x2A200  batched u16 palram upload (XOR 0x8000)
  0x29C10  staging -> palram colorbase region

Type-0x1111 records are partially replayed in ``tools.model2_cgm_1111`` (binary atoms
+ embedded format strings). Full fidelity still needs the 0x5CEC0 thunk builder and
0x29FAC per-record dispatch against runtime workram @ 0x5C9118.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.model2_cgm_1111 import replay_1111_record

from tools.model2_palette import (
    CgmBlock,
    PaletteState,
    _iter_cgm_v16_records,
    _write_colorbase,
    parse_cgm_colorbase_block,
)

CGM_SLOT_BASE = 9  # 0x20C950 after 0x29A68
CGM_RECORD_1111 = 0x1111
CGM_RECORD_LUMARAM = 0x0010


@dataclass
class CgmReplayState:
    """Minimal workram stand-in for CGM parse @ 0x29EB0."""

    slot_next: int = CGM_SLOT_BASE
    colorbase_by_slot: dict[int, int] = field(default_factory=dict)
    records_applied: list[tuple[int, int]] = field(default_factory=list)
    pending_1111_bytes: int = 0
    replay_1111_slots: dict[int, int] = field(default_factory=dict)
    replay_1111_errors: list[str] = field(default_factory=list)


def _apply_leading_colors(
    state: PaletteState,
    replay: CgmReplayState,
    data: bytes,
    block: CgmBlock,
) -> int:
    """Replay 0x2A050 leading palette colors (slots 1..N)."""
    applied = 0
    for slot, color15 in parse_cgm_colorbase_block(data, block):
        if slot <= 0:
            continue
        _write_colorbase(state, slot, color15)
        replay.colorbase_by_slot[slot] = color15 & 0x7FFF
        replay.slot_next = max(replay.slot_next, slot + 1)
        applied += 1
    return applied


def _apply_lumaram_record(
    state: PaletteState,
    data: bytes,
    payload: int,
    length: int,
    *,
    lumaram_base: int = 0,
) -> None:
    """CGM v16 type-0x0010: lumaram byte run (dest base = 0x20C950<<7 @ 0x2A29C)."""
    for i in range(length):
        idx = lumaram_base + i
        if idx < len(state.lumaram):
            state.lumaram[idx] = data[payload + i]


def replay_cgm_block(
    state: PaletteState,
    data: bytes,
    block: CgmBlock,
    replay: CgmReplayState | None = None,
) -> CgmReplayState:
    """Parse one CGM block (static subset of 0x29EB0)."""
    if replay is None:
        replay = CgmReplayState()

    _apply_leading_colors(state, replay, data, block)

    if block.version != 16:
        return replay

    for rec_type, rec_len, payload in _iter_cgm_v16_records(data, block):
        if rec_type == CGM_RECORD_LUMARAM and 0 < rec_len <= len(state.lumaram):
            _apply_lumaram_record(state, data, payload, rec_len)
            replay.records_applied.append((rec_type, rec_len))
        elif rec_type == CGM_RECORD_1111 and rec_len > 0:
            payload = data[payload : payload + rec_len]
            part = replay_1111_record(
                state,
                payload,
                slot_base=max(replay.slot_next, CGM_SLOT_BASE),
            )
            for slot, color15 in part.slots_written.items():
                replay.colorbase_by_slot[slot] = color15 & 0x7FFF
                replay.slot_next = max(replay.slot_next, slot + 1)
            replay.replay_1111_slots.update(part.slots_written)
            replay.replay_1111_errors.extend(part.errors)
            replay.pending_1111_bytes = max(0, rec_len - part.bytes_consumed)
            replay.records_applied.append((rec_type, rec_len))

    return replay


def replay_course_cgm_blocks(
    state: PaletteState,
    data: bytes,
    blocks: tuple[CgmBlock, ...],
) -> CgmReplayState:
    """Replay desert course init CGM path @ ROM 0x12E00 (two blocks)."""
    replay = CgmReplayState()
    for block in blocks:
        replay = replay_cgm_block(state, data, block, replay)
    return replay


def missing_colorbase_slots(
    replay: CgmReplayState,
    needed: set[int],
) -> list[int]:
    """Slots referenced by geometry but not filled by CGM replay."""
    return sorted(s for s in needed if s not in replay.colorbase_by_slot)
