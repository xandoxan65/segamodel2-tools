"""g13 XOR/ADD mask table (@ maincpu ``0x2A39C``–``0x2A3AC``).

Hardware path (``decomp/disasm/maincpu/maincpu_02a0f8_400.asm``):

  ``0x2A370``  ``g13 = ldos 0x20C958``  (anchor slot << 7, seeded @ ``0x2A290``)
  ``0x2A39C``  ``g5 = g13 + (slot << 6)``; ``g6 = staging0 + (slot << 7)``
  ``0x2A3AC``  ``g5 = lda 0x8000(g5)[sub]``  — runtime table row per slot

The table at bus ``0x008000`` is **built during format compile** (``0x5CEC0`` /
``0x2A3E4`` store loop); it is not present as a static blob in main_data ROM.
Replay derives each row's XOR mask from the slot window @ ``0x2A378``:

  * ``slot in [anchor, anchor + 24)`` → ``0x8040`` (setbit 6+15 only)
  * ``slot >= anchor + 24``           → ``(slot << 7) | 0x8040``

The ``#`` hash path @ ``0x2A234`` uses ``(0x20C958 | 0x8040)`` for every word
in the batch — not the per-slot table entry.
"""

from __future__ import annotations

G13_CTRL_BITS = 0x8040
G13_TABLE_BUS_BASE = 0x8000
CGM_SLOT_WINDOW = 24


def anchor_from_seed(g13_seed: int) -> int:
    """Slot anchor encoded in ``0x20C958`` (@ ``0x2A290`` ``shlo 7``)."""
    return (int(g13_seed) >> 7) & 0x3FF


def g13_table_row_offset(g13_seed: int, slot: int) -> int:
    """Byte offset for ``lda 0x8000(g5)[sub]`` (@ ``0x2A3A4`` / ``0x2A3AC``)."""
    return (int(g13_seed) & 0xFFFF) + ((int(slot) & 0x3FF) << 6)


def g13_mask_for_slot(g13_seed: int, slot: int, *, sub_index: int = 0) -> int:
    """Effective XOR/ADD mask for one colorbase slot.

    ``sub_index`` selects the half-row loaded by ``0x2A3AC`` (``g0`` is 0 or 1);
    both entries carry the same mask in practice.
    """
    del sub_index
    if g13_seed == 0:
        return G13_CTRL_BITS
    anchor = anchor_from_seed(g13_seed)
    if int(slot) < anchor + CGM_SLOT_WINDOW:
        return G13_CTRL_BITS
    return ((int(slot) & 0x3FF) << 7) | G13_CTRL_BITS


def g13_hash_mask(g13_seed: int) -> int:
    """Batch XOR mask for ``#`` / ``0x2A200``.

    Disasm ``0x2A234`` ``setbit 6,0,g13`` then ``0x2A240`` ``setbit 15,0,g13``
    overwrites with bit15 only → ``0x8000`` (see ``palram_batch_upload``).
    ``g13_seed`` is unused; kept for call-site compatibility.
    """
    del g13_seed
    return 0x8000


def build_g13_table(
    g13_seed: int,
    slot_lo: int,
    slot_hi: int,
) -> dict[int, int]:
    """Materialize per-slot masks for reporting or diff against a workram capture."""
    return {
        slot: g13_mask_for_slot(g13_seed, slot)
        for slot in range(slot_lo, slot_hi + 1)
    }


def flat_g13_mask(slot: int) -> int:
    """Legacy flat ``0x8040`` XOR (wrong for ``slot >= anchor + 24``)."""
    return G13_CTRL_BITS


def mask_divergence_report(
    g13_seed: int,
    slots: tuple[int, ...] = (38, 45, 100, 477),
) -> list[dict]:
    """Compare table formula vs flat ``0x8040`` for high slots."""
    rows: list[dict] = []
    for slot in slots:
        table = g13_mask_for_slot(g13_seed, slot)
        flat = flat_g13_mask(slot)
        rows.append(
            {
                "slot": slot,
                "table_mask": f"0x{table:04x}",
                "flat_mask": f"0x{flat:04x}",
                "diverges": table != flat,
            }
        )
    return rows
