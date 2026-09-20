"""Scene draw scripts and placement batches (i960 / main_data RE)."""

from __future__ import annotations

from dataclasses import dataclass

from tools.i960_memory import MAIN_DATA_A
from tools.model2_placements import (
    PlacementRecord,
    _apply_placement,
    identity_matrix,
    is_polygon_rom_oba,
)

# Contiguous geo draw script in main_data (ends before invalid tail words).
DRAW_SCRIPT_VADDR = 0x0286_56C0
DRAW_SCRIPT_MAX_FIELD = 0x0030_0000

# Draw-layer records loaded via ldq (not always contiguous — see parse_cpu_draw_entries).
CPU_DRAW_ENTRY_VADDRS: tuple[int, ...] = (
    0x0286_5620,
    0x0286_5650,
    0x0286_5660,
    0x0286_5680,
    0x0286_56C0,
    0x0286_56D0,
    0x0286_56E0,
    0x0286_56F0,
    0x0286_5780,
)

# Single-entry anchors referenced directly from maincpu (scene init clusters).
CPU_SCENE_ANCHORS: dict[str, int] = {
    "anchor_13e84": 0x0286_56C0,
    "anchor_158f0": 0x0286_5660,
    "anchor_157c0": 0x0286_5680,
    "anchor_159d8": 0x0286_56F0,
    "anchor_15a74": 0x0286_5710,
    "anchor_15548": 0x0286_5730,
    "anchor_42d50": 0x0286_57C0,
}


@dataclass
class DrawLayer:
    index: int
    vaddr: int
    field_a: int
    field_b: int
    oba: int
    obc: int
    rom_offset: int


def parse_cpu_draw_entry(main_data: list[int], vaddr: int) -> DrawLayer | None:
    """Parse one CPU-referenced draw record (stride-4 at a fixed main_data vaddr)."""
    i = (vaddr - MAIN_DATA_A) // 4
    if i + 3 >= len(main_data):
        return None
    a, b, oba, obc = main_data[i : i + 4]
    if not is_polygon_rom_oba(oba) or obc <= 0 or obc > 3000:
        return None
    return DrawLayer(
        index=-1,
        vaddr=vaddr,
        field_a=a,
        field_b=b,
        oba=oba,
        obc=obc,
        rom_offset=0,
    )


def parse_cpu_draw_entries(main_data: list[int]) -> list[DrawLayer]:
    """All draw-layer records the CPU loads with ldq before / beside the big draw script."""
    out: list[DrawLayer] = []
    for vaddr in CPU_DRAW_ENTRY_VADDRS:
        layer = parse_cpu_draw_entry(main_data, vaddr)
        if layer:
            layer.index = len(out)
            out.append(layer)
    return out


def parse_draw_script(
    main_data: list[int],
    *,
    start_vaddr: int = DRAW_SCRIPT_VADDR,
    max_field: int = DRAW_SCRIPT_MAX_FIELD,
) -> list[DrawLayer]:
    """Parse stride-4 geo draw layers: (workram_a, workram_b, polygon oba, param)."""
    i = (start_vaddr - MAIN_DATA_A) // 4
    layers: list[DrawLayer] = []
    while i + 3 < len(main_data):
        a, b, oba, obc = main_data[i : i + 4]
        if not is_polygon_rom_oba(oba):
            break
        if obc <= 0 or obc > 3000:
            break
        if a > max_field or b > max_field:
            break
        layers.append(
            DrawLayer(
                index=len(layers),
                vaddr=MAIN_DATA_A + i * 4,
                field_a=a,
                field_b=b,
                oba=oba,
                obc=obc,
                rom_offset=0,  # filled by caller if mask known
            )
        )
        i += 4
    return layers


def parse_track_draw_layers(
    main_data: list[int],
    *,
    max_placement_index: int,
    start_vaddr: int = DRAW_SCRIPT_VADDR,
) -> list[DrawLayer]:
    """
    Parse draw-script layers until the placement stream is fully covered.

    Draw-layer obc snapshots workram placement cursor 0x20B940 (exclusive end index).
    """
    layers = parse_draw_script(main_data, start_vaddr=start_vaddr)
    if not layers:
        return []

    segments = placement_segments_from_draw_layers(layers, max_placement_index=max_placement_index)
    monotonic = [
        layer_idx
        for _start, end, layer_idx in segments
        if layer_idx < len(layers) and layers[layer_idx].obc == end
    ]
    if not monotonic:
        return layers
    last_layer_index = monotonic[-1]
    return [layer for layer in layers if layer.index <= last_layer_index]


def placement_segments_from_draw_layers(
    layers: list[DrawLayer],
    *,
    max_placement_index: int,
) -> list[tuple[int, int, int]]:
    """
    When draw-layer word4 (obc) rises monotonically, treat it as a placement-stream cursor.

    Confirmed in i960 RE: workram ``0x0020B940`` is the live placement index; geo cluster
    @ ``0x023CC8`` does ``addo catalog_obc, cursor`` after each ``ldq 0x2864b40[..]``.
    Draw-script ``obc`` is a snapshot of that cursor (end index exclusive) after the layer.
    Returns (start, end, layer_index) spans.
    """
    segments: list[tuple[int, int, int]] = []
    prev = 0
    for layer in layers:
        cursor = layer.obc
        if cursor > prev and cursor < max_placement_index:
            segments.append((prev, cursor, layer.index))
            prev = cursor
    if prev < max_placement_index:
        segments.append((prev, max_placement_index, len(layers)))
    return segments


def layer_mesh_vertices(
    polygon_rom: list[int],
    layer: DrawLayer,
    *,
    polygon_rom_mask: int,
) -> list[tuple[float, float, float]] | None:
    """Parse one draw layer's polygon object (identity transform — positions live in workram)."""
    rom_offset = layer.oba & polygon_rom_mask
    return _apply_placement(
        polygon_rom,
        matrix=identity_matrix(),
        rom_offset=rom_offset,
        obc=layer.obc,
    )


def slice_placements(
    placements: list[PlacementRecord],
    start: int,
    end: int,
) -> list[PlacementRecord]:
    return placements[start:end]
