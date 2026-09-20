"""CGM palette staging simulator (maincpu disasm-backed).

Models the workram / staging path between CGM ``0x1111`` format reads and
``palram[0x1000 + slot]`` commits.  ROM thunks @ ``0x5C9118`` are not executed;
effects of the fixed upload cluster are replayed directly.

Disasm sources (``decomp/disasm/maincpu/``):
  ``0x29F7C``  per-group node setup @ ``0x20B950`` + ``0x2A0F8`` dispatch
  ``0x2A290``  seed ``0x20C958`` from ``0x20C950``, +24 slot cursor, format compile
  ``0x2A200``  batched XOR into staging @ ``0x01000000`` / ``0x01004000``
  ``0x29CFC``  ADD ``g13`` into staging (single-upload path @ ``0x29C10``)
  ``0x2A490``  scratch colorbase write @ ``0x01800000`` (slot = ``mask>>7``)
  ``0x2A4E0``  read-modify-write merge into ``0x01080000`` (@ ``0x2A56C``)
  ``0x2A5A0``  FIFO upload runner — D/U (r5 bit 0) → ``0x2A4E0`` without XOR
  ``0x2A120``  linked-list merge @ ``0x20B950`` + scratch flush @ ``0x26918``
  ``0x26918``  commit scratch color15 → ``palram`` colorbase table
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from tools.model2_cgm_g13_table import (
    CGM_SLOT_WINDOW,
    G13_CTRL_BITS,
    g13_hash_mask,
    g13_mask_for_slot,
)
from tools.decomp.cgm_merge_ref import merge_g0_for_d, palram_bus_merge_u16

# How one ``D`` FIFO u16 becomes color15.  ``0x2A258`` XOR only runs when ``g3>0``
# (``#`` batch inner loop).  Hardware D sets r9 bit 0 → ``0x02A62C`` calls
# ``0x02A4E0`` merge (not xor_table).  Compare modes via palette_d_path_compare;
# ``merge_raw`` uses ``@ 0x2A62C`` bus coords: ``g1=merge_max``, ``g0`` from ``merge_g0_for_d``.
D_DECODE_XOR_TABLE = "xor_table"  # legacy replay only — not lone-D disasm path
D_DECODE_XOR_SLOT7 = "xor_slot7"  # raw ^ (slot << 7)
D_DECODE_XOR_8040 = "xor_8040"  # raw ^ 0x8040 only
D_DECODE_ADD_TABLE = "add_table"  # (raw + g13_mask_for_slot) & 0x7fff — ``U``-style
D_DECODE_ADD_SLOT7 = "add_slot7"  # ``0x29CD8``/``0x29CFC`` hint: g13 = slot<<7 only
D_DECODE_SUB_40 = "sub_40"  # ``0x29E18`` setbit-6 path: (raw - 0x40) & 0x7fff
D_DECODE_MERGE_RAW = "merge_raw"  # ``0x02A4E0`` merge with g2=raw (D bit-0 path stub)
D_DECODE_XOR_MERGE = "xor_merge"  # xor_table then ``0x02A4E0`` merge (hybrid test)

D_DECODE_MODES = (
    D_DECODE_XOR_TABLE,
    D_DECODE_XOR_SLOT7,
    D_DECODE_XOR_8040,
    D_DECODE_ADD_TABLE,
    D_DECODE_ADD_SLOT7,
    D_DECODE_SUB_40,
    D_DECODE_MERGE_RAW,
    D_DECODE_XOR_MERGE,
)
from tools.model2_palette import PaletteState, _write_colorbase

# Scratch colorbase stride @ 0x01800000 (@ 0x2A1AC: shlo 5,r4; @ 0x2A490: +0x20 loop).
SCRATCH_SLOT_STRIDE = 0x20


@dataclass
class ChainNode:
    """8-byte node copied by ``0x2A164`` ``ldl``/``stl``."""

    head_u16: int = 0
    byte2: int = 0
    byte3: int = 0
    dword4: int = 0
    next: ChainNode | None = None


@dataclass
class GroupRow:
    """One row of the upload group table @ ``0x20B950[g*8]``."""

    head: ChainNode = field(default_factory=ChainNode)
    merge_off: int = 0  # byte @ ``0x20B953[g*8]`` — 0 skips ``0x2A120``
    tail: ChainNode | None = None


@dataclass
class CgmStagingSim:
    """Minimal workram + bus staging stand-in for CGM palette upload."""

    slot_base: int = 14
    stream_cursor: int = 14  # 0x20C950
    g13_mask: int = 0  # 0x20C958 (cursor << 7 after 0x2A290)
    slot_limit: int = 0x3FF  # 0x20C954
    group_index: int = 0  # next free index @ 0x20C954
    record_group: int = 0  # ``r7`` preserved across one ``0x29EB0`` record

    staging0: dict[int, int] = field(default_factory=dict)
    staging1: dict[int, int] = field(default_factory=dict)
    scratch: dict[int, int] = field(default_factory=dict)
    palram_bus: dict[int, int] = field(default_factory=dict)
    groups: dict[int, GroupRow] = field(default_factory=dict)
    _batch_anchors: list[int] = field(default_factory=list)

    # ``0x20C95C``–``0x20C968`` merge bounds (@ ``0x2A2E0`` compile setup).
    merge_lo: int = 0
    merge_mid: int = 0
    merge_max: int = 0x17F
    merge_max2: int = 0x1EF

    stats: dict[str, int] = field(default_factory=dict)
    d_decode: str = D_DECODE_MERGE_RAW

    def _bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    # --- 0x2A290 / 0x29AA8 -------------------------------------------------

    def op_2a290_prepare_batch(self) -> None:
        """``0x2A290``: seed ``0x20C958`` from cursor, advance ``0x20C950`` by 24."""
        anchor = self.stream_cursor & 0x3FF
        if self.g13_mask == 0:
            self.g13_mask = anchor << 7
            self._batch_anchors.append(anchor)
            self._bump("2a290_batch")
        else:
            self._bump("2a290_skip")
        self.stream_cursor = self.op_29aa8_cap_cursor(self.stream_cursor + CGM_SLOT_WINDOW)

    @staticmethod
    def op_29aa8_cap_cursor(cursor: int) -> int:
        """``0x29AA8``: store cursor @ ``0x20C950`` capped at ``0x7F``."""
        if cursor > 0x7F:
            return 0
        return cursor & 0x3FF

    # --- g13 helpers -------------------------------------------------------

    def g13_for_slot(self, slot: int) -> int:
        """Effective XOR/ADD mask (@ ``0x2A39C``–``0x2A3AC`` ``0x8000`` table)."""
        return g13_mask_for_slot(self.g13_mask, slot)

    def g13_ctrl(self) -> int:
        """Current ``g13`` for the active write cursor."""
        return self.g13_for_slot(self.stream_cursor)

    def decode_rom_u16_xor(self, raw_u16: int, *, slot: int | None = None) -> int:
        """Python replay: ``raw ^ g13_mask_for_slot`` (@ ``0x2A3AC`` table formula).

        ``0x2A258`` ``xor g4,g13`` applies only on the ``#`` batch path (@ ``0x2A200``,
        ``g3>0``).  That loop is **not** invoked for a lone ``D`` in disasm.  This
        helper is the ``xor_table`` replay mode, not a disasm-proven 0x1111 decode.
        """
        if slot is None:
            slot = self.stream_cursor
        mask = self.g13_for_slot(slot) & 0xFFFF
        return ((int(raw_u16) & 0xFFFF) ^ mask) & 0x7FFF

    def decode_d_u16(self, raw_u16: int, *, slot: int | None = None) -> int:
        """Map one ``D`` FIFO u16 → color15 for the active decode mode."""
        if slot is None:
            slot = self.stream_cursor
        raw = int(raw_u16) & 0xFFFF
        mode = self.d_decode
        if mode == D_DECODE_XOR_TABLE:
            return self.decode_rom_u16_xor(raw, slot=slot)
        if mode == D_DECODE_XOR_SLOT7:
            mask = ((int(slot) & 0x3FF) << 7) & 0xFFFF
            return (raw ^ mask) & 0x7FFF
        if mode == D_DECODE_XOR_8040:
            return (raw ^ G13_CTRL_BITS) & 0x7FFF
        if mode == D_DECODE_ADD_TABLE:
            mask = self.g13_for_slot(slot) & 0xFFFF
            return (raw + mask) & 0x7FFF
        if mode == D_DECODE_ADD_SLOT7:
            mask = ((int(slot) & 0x3FF) << 7) & 0xFFFF
            return (raw + mask) & 0x7FFF
        if mode == D_DECODE_SUB_40:
            return (raw - 0x40) & 0x7FFF
        if mode in (D_DECODE_MERGE_RAW, D_DECODE_XOR_MERGE):
            word = raw
            if mode == D_DECODE_XOR_MERGE:
                word = self.decode_rom_u16_xor(raw, slot=slot)
            self.setup_merge_globals_for_d(slot)
            g0 = merge_g0_for_d(merge_lo=self.merge_lo)
            merged = self.op_2a4e0_merge(g0=g0, g1=self.merge_max, g2=word)
            return merged if merged is not None else (word & 0x7FFF)
        raise ValueError(f"unknown d_decode mode: {mode!r}")

    def setup_merge_globals(self, *, g0_idx: int = 0, g1_idx: int | None = None) -> None:
        """``0x2A2E0`` defaults when indices are in-range (not ``g14`` spill)."""
        self.merge_lo = (int(g0_idx) & 0xFF) << 3
        g1_i = int(g1_idx if g1_idx is not None else g0_idx) & 0xFF
        self.merge_mid = g1_i << 3
        self.merge_max = 0x17F
        self.merge_max2 = 0x1EF

    def setup_merge_globals_for_d(self, slot: int) -> None:
        """Seed ``0x20C958`` + merge bounds for one ``D`` upload (@ ``0x2A4E0``)."""
        self.g13_mask = (int(slot) & 0x3FF) << 7
        self.merge_lo = 0
        self.merge_mid = 0
        self.merge_max = 0x17F
        self.merge_max2 = 0x1EF

    def _palram_bus_read(self, byte_off: int) -> int:
        return self.palram_bus.get(byte_off, 0) & 0xFFFF

    def _palram_bus_write(self, byte_off: int, value: int) -> None:
        self.palram_bus[byte_off] = int(value) & 0xFFFF

    def op_2a4e0_merge(self, *, g0: int, g1: int, g2: int) -> int | None:
        """``0x2A4E0``–``0x2A58C``: read-modify-write @ ``0x01080000``."""
        merged = palram_bus_merge_u16(
            self.palram_bus,
            g0=g0,
            g1=g1,
            g2=g2,
            merge_lo=self.merge_lo,
            merge_mid=self.merge_mid,
            merge_max=self.merge_max,
            merge_max2=self.merge_max2,
            g13_mask=self.g13_mask,
        )
        if merged is not None:
            self._bump("2a4e0_merge")
        return merged

    # --- 0x29EB0 record setup ----------------------------------------------

    def begin_record(self) -> None:
        """One ``0x29EB0`` record — group row @ ``0x20B950`` + ``0x2A290`` batch seed."""
        self.record_group = self.group_index
        head = (self.stream_cursor & 0x3FF) << 7
        row = GroupRow(head=ChainNode(head_u16=head, byte2=0, byte3=0))
        row.tail = row.head
        self.groups[self.record_group] = row

        # ``0x2A290``: when ``0x20C958 == 0``, ``st (cursor<<7), 0x20C958``.
        # The ``+24`` cursor bump in the same handler is for the format-compile row
        # (@ ``0x2A2C4`` → ``0x5CEC0``); palram slot writes still advance per ``D``.
        if self.g13_mask == 0:
            anchor = self.stream_cursor & 0x3FF
            self.g13_mask = anchor << 7
            self._batch_anchors.append(anchor)
            self._bump("2a290_batch")

    def _append_chain_node(self, group: int, node: ChainNode) -> None:
        row = self.groups.get(group)
        if row is None:
            return
        if row.tail is None:
            row.head = node
            row.tail = node
        else:
            row.tail.next = node
            row.tail = node
        self._bump("chain_append")

    # --- 0x2A200 / 0x29CFC staging transforms ------------------------------

    def op_2a258_xor_staging(
        self,
        bank: int,
        word_index: int,
        *,
        count: int = 1,
        slot: int | None = None,
    ) -> None:
        """``0x2A258``: ``staging[word] ^= g13`` (batched path, ``g3>0``)."""
        table = self.staging1 if bank else self.staging0
        g13 = self.g13_for_slot(slot if slot is not None else word_index) & 0xFFFF
        for offset in range(count):
            idx = word_index + offset
            value = table.get(idx, 0) & 0xFFFF
            table[idx] = (value ^ g13) & 0xFFFF
        self._bump("2a258_xor", count)

    def op_29cfc_add_staging(
        self,
        bank: int,
        dest_index: int,
        src_value: int,
        *,
        slot: int | None = None,
    ) -> None:
        """``0x29CFC``: ``staging[dest] = (src + g13) & 0xffff``."""
        table = self.staging1 if bank else self.staging0
        g13 = self.g13_for_slot(slot if slot is not None else dest_index) & 0xFFFF
        table[dest_index] = (int(src_value) + g13) & 0xFFFF
        self._bump("29cfc_add")

    def op_2a490_scratch_write(self, color15: int, *, slot: int) -> int:
        """``0x2A490``: write color15 into scratch @ ``0x01800000 + slot<<5``."""
        color15 &= 0x7FFF
        if not color15:
            return slot
        self.scratch[slot] = color15
        self._bump("2a490_scratch")
        return slot

    def op_26918_commit(self, palette: PaletteState, slot: int, color15: int) -> None:
        """``0x26918``: ``palram[0x1000 + slot] = color15 & 0x7fff``."""
        _write_colorbase(palette, slot, color15 & 0x7FFF)
        self._bump("26918_commit")

    def _merge_chain_nodes(self, dest: GroupRow, src: GroupRow, r7: int) -> None:
        """``0x2A150``–``0x2A188``: copy 8-byte nodes from ``src`` chain into ``dest``."""
        g2 = (r7 & 0xFF) << 7
        g5 = dest.head
        g6 = src.head
        while g6 is not None:
            g5.head_u16 = g6.head_u16
            g5.byte2 = g6.byte2
            g5.byte3 = g6.byte3
            g5.dword4 = g6.dword4
            g5.head_u16 = (g5.head_u16 + 1 - g2) & 0xFFFF
            self._bump("2a120_merge_node")
            g6 = g6.next
            if g6 is None:
                break
            if g5.next is None:
                g5.next = ChainNode()
            g5 = g5.next
            if g5 is dest.head:
                break
        dest.tail = g5

    def op_2a120_merge(self, group: int) -> None:
        """``0x2A150``–``0x2A188`` linked-list merge without palram commit."""
        row = self.groups.get(group)
        if row is None:
            return
        merge_off = row.merge_off & 0xFF
        if merge_off == 0:
            return
        g7 = self.group_index
        node = row.head
        r7 = node.byte2 & 0xFF
        src_index = group + merge_off
        if src_index < g7:
            src = self.groups.get(src_index)
            if src is not None:
                self._merge_chain_nodes(row, src, r7)

    def op_2a120_commit(self, palette: PaletteState, group: int) -> int:
        """``0x2A18C``–``0x2A1E8`` scratch → ``0x26918`` commit loop."""
        row = self.groups.get(group)
        if row is None:
            return 0
        if (row.merge_off & 0xFF) == 0:
            self._bump("2a120_skip")
            return 0

        node = row.head
        r7 = node.byte2 & 0xFF
        g3 = node.head_u16 & 0xFFFF
        stream_end = self.stream_cursor

        r5 = (g3 >> 7) & 0x3FF
        start_slot = max(self.slot_base, (r7 + r5) & 0x3FF)

        if start_slot >= stream_end:
            self._bump("2a120_flush")
            return 0

        committed = 0
        for slot in range(start_slot, stream_end):
            color15 = self.scratch.get(slot, 0)
            if color15:
                self.op_26918_commit(palette, slot, color15)
                committed += 1

        merge_off = row.merge_off & 0xFF
        self.group_index = (self.group_index - merge_off) & 0x3FF
        self.stream_cursor = (stream_end - r7) & 0x3FF
        self._bump("2a120_flush")
        return committed

    # --- Format-level hooks --------------------------------------------------

    def ingest_u16(self, palette: PaletteState, raw_u16: int) -> int | None:
        """One FIFO u16: ``D`` → ``0x2A4E0`` merge (@ ``0x2A62C``), then scratch (@ ``0x2A490``)."""
        del palette
        slot = self.stream_cursor
        if slot < self.slot_base or slot > self.slot_limit:
            return None

        self.setup_merge_globals_for_d(slot)
        color15 = self.decode_d_u16(raw_u16, slot=slot)
        bank = 1 if self.d_decode.startswith("add_") else 0
        table = self.staging1 if bank else self.staging0
        table[slot] = color15 & 0xFFFF
        self._bump("d_ingest")

        group = self.record_group
        if group in self.groups:
            self._append_chain_node(
                group,
                ChainNode(
                    head_u16=(slot & 0x3FF) << 7,
                    byte2=0,
                    byte3=0,
                    dword4=color15,
                ),
            )

        if color15:
            self.op_2a490_scratch_write(color15, slot=slot)
            self.stream_cursor += 1
            return slot
        return None

    def ingest_u16_add(self, palette: PaletteState, raw_u16: int) -> int | None:
        """``U`` format opcode → ``0x29CFC`` ADD ``g13`` then scratch (@ ``0x2A490``)."""
        del palette
        slot = self.stream_cursor
        if slot < self.slot_base or slot > self.slot_limit:
            return None

        g13 = self.g13_for_slot(slot) & 0xFFFF
        color15 = ((int(raw_u16) & 0xFFFF) + g13) & 0x7FFF
        self.staging0[slot] = color15 & 0xFFFF

        group = self.record_group
        if group in self.groups:
            self._append_chain_node(
                group,
                ChainNode(
                    head_u16=(slot & 0x3FF) << 7,
                    byte2=0,
                    byte3=0,
                    dword4=color15,
                ),
            )

        if color15:
            self.op_2a490_scratch_write(color15, slot=slot)
            self.stream_cursor += 1
            return slot
        return None

    def op_2a200_hash_batch(self, repeat: int) -> None:
        """``#`` format opcode → ``0x2A200`` batched XOR over recent staging words."""
        if repeat <= 0:
            return
        end = min(self.stream_cursor, self.slot_limit + 1)
        start = max(self.slot_base, end - repeat)
        hash_g13 = g13_hash_mask(self.g13_mask)
        for slot in range(start, end):
            if slot in self.staging0:
                value = self.staging0[slot] & 0xFFFF
                self.staging0[slot] = (value ^ hash_g13) & 0xFFFF
                self._bump("2a258_xor")
                color15 = self.staging0[slot] & 0x7FFF
                if color15:
                    self.scratch[slot] = color15
                    self._bump("2a490_scratch")
        self._bump("2a200_hash")

    def finalize(self, palette: PaletteState) -> dict[int, int]:
        """``0x29FD0`` + ``0x2A120`` at end of one ``0x29EB0`` record."""
        row = self.groups.get(self.record_group)
        if row is not None and row.merge_off == 0:
            row.merge_off = 1

        self.op_2a120_merge(self.record_group)
        self.op_2a120_commit(palette, self.record_group)
        return {slot: word for slot, word in self.scratch.items() if word}
