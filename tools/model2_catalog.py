"""Model 2 master object catalog + placement stream (srallyc, RE-backed)."""

from __future__ import annotations

from dataclasses import dataclass

from tools.model2_placements import (
    PlacementRecord,
    _apply_placement,
    identity_matrix,
    is_polygon_rom_oba,
)
from tools.i960_memory import (
    CATALOG_ENTRY_COUNT,
    CATALOG_VADDR,
    MAIN_DATA_A,
    PLACEMENT_STREAM_VADDR,
)

CATALOG_ENTRY_WORDS = 4


def vaddr_to_word(vaddr: int) -> int:
    return (vaddr - MAIN_DATA_A) // 4


def catalog_start_word() -> int:
    return vaddr_to_word(CATALOG_VADDR)


def placement_stream_start_word() -> int:
    return vaddr_to_word(PLACEMENT_STREAM_VADDR)


@dataclass(frozen=True)
class CatalogEntry:
    index: int
    main_data_word: int
    vaddr: int
    field_a: int
    field_b: int
    oba: int
    obc: int
    rom_offset: int


@dataclass(frozen=True)
class SceneRange:
    """Descriptor block in main_data (e.g. 0x02865730) referencing catalog/placement slices."""

    vaddr: int
    field_a: int
    field_b: int
    oba: int
    obc: int


def parse_catalog(main_data: list[int], *, mask: int) -> list[CatalogEntry]:
    base = catalog_start_word()
    out: list[CatalogEntry] = []
    for i in range(CATALOG_ENTRY_COUNT):
        w = base + i * CATALOG_ENTRY_WORDS
        a, b, oba, obc = main_data[w : w + 4]
        out.append(
            CatalogEntry(
                index=i,
                main_data_word=w,
                vaddr=MAIN_DATA_A + w * 4,
                field_a=a,
                field_b=b,
                oba=oba,
                obc=obc,
                rom_offset=oba & mask,
            )
        )
    return out


def parse_placement_stream(
    main_data: list[int],
    polygon_rom: list[int],
    *,
    polygon_rom_mask: int,
    start_word: int | None = None,
    max_records: int = 10_000,
) -> list[PlacementRecord]:
    """Stride-4 (tpa, tha, oba, obc) instances after the master catalog."""
    i = start_word if start_word is not None else placement_stream_start_word()
    records: list[PlacementRecord] = []
    while i + 3 < len(main_data) and len(records) < max_records:
        tpa, tha, oba, obc = main_data[i : i + 4]
        if not is_polygon_rom_oba(oba):
            break
        if obc <= 0 or obc > 200_000:
            break
        rom_offset = oba & polygon_rom_mask
        matrix = identity_matrix()
        verts = _apply_placement(
            polygon_rom, matrix=matrix, rom_offset=rom_offset, obc=obc
        )
        if verts is not None:
            records.append(
                PlacementRecord(
                    main_data_word=i,
                    matrix=matrix,
                    tpa=tpa,
                    tha=tha,
                    oba=oba,
                    obc=obc,
                    rom_offset=rom_offset,
                    vertices=verts,
                    placement_index=len(records),
                )
            )
        i += 4
    return records


def parse_scene_descriptor_block(main_data: list[int], vaddr: int, *, count: int = 32) -> list[SceneRange]:
    """Legacy helper — prefer tools.model2_scenes.parse_draw_script."""
    from tools.model2_scenes import parse_draw_script

    layers = parse_draw_script(main_data, start_vaddr=vaddr)
    return [
        SceneRange(vaddr=layer.vaddr, field_a=layer.field_a, field_b=layer.field_b, oba=layer.oba, obc=layer.obc)
        for layer in layers[:count]
    ]
