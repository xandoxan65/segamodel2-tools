"""Disasm-backed ``0x2A4E0`` palram bus merge (D opcode path @ ``0x2A5A0`` → ``0x2A62C``).

Single ``D`` FIFO u16 uses read-modify-write into the packed bus @ ``0x01080000``,
not ``0x2A258`` XOR (that runs only on the ``#`` batch path when ``g3>0``).
"""

from __future__ import annotations

CHAR_RAM_BASE = 0x0108_0000


def merge_g0_for_d(*, merge_lo: int = 0) -> int:
    """``@ 0x2A62C`` inner merge: ``g1=merge_max``, ``g0`` so ``(g0+merge_lo)&3==3``.

    Disasm @ ``0x2A568`` uses ``nibble_off=(g1_sum&3)<<2`` with ``g1_sum=g0+merge_lo``;
    full-word insert needs ``nibble_off==12`` → ``g1_sum&3==3``.
    """
    return (3 - (int(merge_lo) & 3)) & 3


def _shift_insert_mask(shift_amt: int) -> int:
    """``0x2A570``/``0x2A580``: mask from signed ``nibble_off-12`` (@ ``0x2A568``)."""
    if shift_amt >= 16:
        return 0
    if shift_amt <= 0:
        return (0xFFFF >> (-shift_amt)) & 0xFFFF if shift_amt < 0 else 0xFFFF
    return (0xFFFF << shift_amt) & 0xFFFF


def _shift_new_bits(g2: int, shift_amt: int) -> int:
    g2 &= 0xFFFF
    if shift_amt < 0:
        return (g2 >> (-shift_amt)) & 0xFFFF
    return (g2 << shift_amt) & 0xFFFF


def palram_bus_merge_u16(
    bus: dict[int, int],
    *,
    g0: int,
    g1: int,
    g2: int,
    merge_lo: int,
    merge_mid: int,
    merge_max: int,
    merge_max2: int,
    g13_mask: int,
) -> int | None:
    """Replay ``0x2A4E0``–``0x2A58C`` into a sparse u16 bus (byte offset → word)."""
    g5_bound = merge_max & 0xFFFF
    g4_lo = merge_lo & 0xFFFF
    g6 = (int(g1) - g5_bound) & 0xFFFF
    g1_sum = (int(g0) + g4_lo) & 0xFFFF

    merge_mid &= 0xFFFF
    merge_max2 &= 0xFFFF
    if g1_sum < g4_lo or g1_sum > merge_max2:
        return None
    if g6 < merge_mid or g6 > g5_bound:
        return None

    g4_idx = (g6 >> 3) & 0xFFFF
    g7_base = g13_mask & 0xFFFF
    g4_idx = ((g4_idx << 6) + g7_base) & 0xFFFF
    g5_idx = (g1_sum >> 3) & 0xFFFF
    g0_n = g6 & 7
    g6_n = g1_sum & 7

    g4_addr = ((g4_idx + g5_idx) << 5) & 0xFFFF
    byte_base = g4_addr

    if g6_n > 3:
        g1_n = g1_sum & 3
        nibble_off = (g1_n << 2) & 0xFFFF
        byte_off = byte_base + nibble_off + 2
        existing = bus.get(byte_off, 0) & 0xFFFF
        g1_n = g1_sum & 3
        nibble_off = (g1_n << 2) & 0xFFFF
        shift_amt = nibble_off - 12  # signed (@ 0x2A568 subo g4,12,g1)
    else:
        byte_off = byte_base + (g0_n * 4)
        existing = bus.get(byte_off, 0) & 0xFFFF
        g1_n = g1_sum & 3
        nibble_off = (g1_n << 2) & 0xFFFF
        shift_amt = nibble_off - 12

    insert_mask = _shift_insert_mask(shift_amt)
    new_bits = _shift_new_bits(int(g2), shift_amt)
    merged = (existing & ~insert_mask) | (new_bits & insert_mask)
    merged &= 0xFFFF
    bus[byte_off] = merged
    return merged & 0x7FFF


def decode_d_u16_merge(
    bus: dict[int, int],
    raw_u16: int,
    *,
    slot: int,
    merge_lo: int = 0,
    merge_mid: int = 0,
    merge_max: int = 0x17F,
    merge_max2: int = 0x1EF,
) -> int | None:
    """One ``D`` upload: ``g1=merge_max`` (@ ``0x2A62C``), ``g0`` from ``merge_g0_for_d``."""
    g13_mask = (int(slot) & 0x3FF) << 7
    g0 = merge_g0_for_d(merge_lo=merge_lo)
    return palram_bus_merge_u16(
        bus,
        g0=g0,
        g1=merge_max,
        g2=raw_u16,
        merge_lo=merge_lo,
        merge_mid=merge_mid,
        merge_max=merge_max,
        merge_max2=merge_max2,
        g13_mask=g13_mask,
    )
