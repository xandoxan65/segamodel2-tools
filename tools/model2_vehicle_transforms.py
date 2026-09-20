"""Decode per-part 4×3 transforms from vehicle descriptor main_data blobs."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import Path

from tools.model2_float import u2f
from tools.model2_geo import (
    GeoParseError,
    GeoState,
    MeshCollector,
    PolyVertex,
    geo_parse_np_ns_collect,
    identity_matrix,
    transform_point,
    try_parse_polygon_object,
)
from tools.model2_placements import _matrix_ok
from tools.i960_vehicles import (
    TRIM_INDICES,
    WHEEL_INDICES,
    VehicleRomDescriptor,
    parse_rom_vehicle_descriptors,
    parse_vehicle_catalog_tables,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

# draw_catalog_sequence @ 0x280D0 advances records with lda 0x14(g0) → 20 words.
VEHICLE_PART_RECORD_WORDS = 20

VEHICLE_BODY_BLOB_VADDR = 0x0284_EA20
VEHICLE_TRIM_BLOB_VADDR = 0x0284_AD30
VEHICLE_WHEEL_BLOB_VADDR = 0x0204_DC50
# Tag words inside each 20-word part record (copy_catalog @ 0x28530 skips via r8 index).
VEHICLE_PART_TAG_WORD_INDICES: tuple[int, ...] = (4, 9, 14, 19)

# Wheel hubs (small parts). 137–143 are large body panels in the same draw batch.
WHEEL_HUB_INDICES: tuple[int, ...] = tuple(range(132, 137))
PANEL_INDICES: tuple[int, ...] = tuple(range(137, 144))


@dataclass(frozen=True)
class CatalogPolygonOffsets:
    """Master catalog stride-4 row (field_a/b are polygon-ROM byte offsets)."""

    catalog_index: int
    field_a: int
    field_b: int
    oba: int
    obc: int
    rom_offset: int


@dataclass(frozen=True)
class PartTransformRef:
    main_data_vaddr: int
    part_index: int
    source: str


def translation_matrix(tx: float, ty: float, tz: float) -> list[float]:
    return [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, tx, ty, tz]


def _translation_ok(tx: float, ty: float, tz: float) -> bool:
    if not all(math.isfinite(v) for v in (tx, ty, tz)):
        return False
    if max(abs(tx), abs(ty), abs(tz)) > 25.0:
        return False
    return abs(tx) > 1e-6 or abs(ty) > 1e-6 or abs(tz) > 1e-6


def parse_part_matrix(main_data: list[int], vaddr: int, part_index: int) -> list[float] | None:
    """12-float row-major 3×4 matrix at the start of a descriptor part record."""
    base = (vaddr - 0x0200_0000) // 4
    start = base + part_index * VEHICLE_PART_RECORD_WORDS
    if start + 12 > len(main_data):
        return None
    matrix = [u2f(main_data[start + i]) for i in range(12)]
    return matrix if _matrix_ok(matrix) else None


def read_part_record_words(main_data: list[int], vaddr: int, part_index: int) -> list[int] | None:
    base = (vaddr - 0x0200_0000) // 4
    start = base + part_index * VEHICLE_PART_RECORD_WORDS
    if start + VEHICLE_PART_RECORD_WORDS > len(main_data):
        return None
    return main_data[start : start + VEHICLE_PART_RECORD_WORDS]


def record_matrix_columns(record: list[int]) -> list[list[float]]:
    """Four matrix lanes in a 20-word part record (data @ 0/5/10/15, tags @ 4/9/14/19)."""
    columns: list[list[float]] = []
    for base in (0, 5, 10, 15):
        columns.append([u2f(record[base + i]) for i in range(4)])
    return columns


def compute_copy_catalog_weights(g1: float) -> tuple[float, float, float, float]:
    """
    Bilinear weights for copy_catalog @ 0x28530 (four matrix lanes).

    Ports the fractional split @ 0x283E0–0x284DC: ``g1`` supplies one axis; the
    second axis uses the integer lane index modulo four columns.
    """
    value = abs(g1)
    axis = value - math.floor(value)
    lane = int(math.floor(value)) % 4
    next_lane = (lane + 1) % 4
    w_lane = 1.0 - axis
    w_next = axis
    weights = [0.0, 0.0, 0.0, 0.0]
    weights[lane] = w_lane
    weights[next_lane] = w_next
    return tuple(weights)


def record_matrix_float_stream(record: list[int]) -> list[float]:
    """
    Eight floats fed to geo FIFO by copy_catalog @ 0x28530 (g1=0, single column).

    Tag words at indices 4/9/14/19 separate matrix lanes in the 20-word record.
    """
    stream: list[float] = []
    for word_index, word in enumerate(record):
        if word_index in VEHICLE_PART_TAG_WORD_INDICES:
            continue
        stream.append(u2f(word))
        if len(stream) == 8:
            break
    return stream


def build_copy_catalog_matrix(
    main_data: list[int],
    vaddr: int,
    part_index: int,
    *,
    g1: float = 0.0,
) -> list[float] | None:
    """
    Reconstruct the 3×4 matrix copy_catalog_index_table pushes before draw_catalog.

    At rest (g1=0) the 0x28530 loop reads eight floats from the record stream; translation
    is words 10–11 when present. Non-zero g1 blends the four matrix lanes.
    """
    record = read_part_record_words(main_data, vaddr, part_index)
    if record is None:
        return None

    if abs(g1) > 1e-6:
        columns = record_matrix_columns(record)
        value = abs(g1)
        lane = int(math.floor(value)) % 4
        frac = value - math.floor(value)
        next_lane = (lane + 1) % 4
        follow = (lane + 2) % 4

        def lerp_col(left: int, right: int) -> list[float]:
            return [
                (columns[left][row] * (1.0 - frac)) + (columns[right][row] * frac)
                for row in range(4)
            ]

        stream = lerp_col(lane, next_lane) + lerp_col(next_lane, follow)
    else:
        stream = record_matrix_float_stream(record)

    if len(stream) < 8:
        return None

    matrix = [
        stream[0],
        stream[1],
        stream[2],
        stream[4],
        stream[5],
        stream[6],
        stream[7] if len(stream) > 7 else 0.0,
        0.0,
        1.0,
        u2f(record[9]) if abs(u2f(record[9])) < 1e-3 else 0.0,
        u2f(record[10]),
        u2f(record[11]),
    ]
    tx, ty, tz = matrix[9], matrix[10], matrix[11]
    if abs(tx) < 1e-4:
        matrix[9] = 0.0
    if abs(ty) < 1e-4:
        matrix[10] = 0.0
    if abs(tz) < 1e-4:
        matrix[11] = 0.0
    return matrix if _matrix_ok(matrix) else None


def parse_part_translation(main_data: list[int], vaddr: int, part_index: int) -> tuple[float, float, float] | None:
    """
    Part placement from descriptor record (copy_catalog / draw_catalog path).

    Records are 20 words; the geo FIFO path pushes a full matrix built at runtime,
    but the translation components in words 9–11 are stable for static export even
    when the 3×3 block is mid-interpolation garbage.
    Body shells stay at identity — catalog vertices are already object-local.
    """
    base = (vaddr - 0x0200_0000) // 4
    start = base + part_index * VEHICLE_PART_RECORD_WORDS
    if start + 12 > len(main_data):
        return None
    tx = u2f(main_data[start + 9])
    ty = u2f(main_data[start + 10])
    tz = u2f(main_data[start + 11])
    if not all(math.isfinite(v) for v in (tx, ty, tz)):
        return None
    if max(abs(tx), abs(ty), abs(tz)) > 25.0:
        return None
    # Snap denormal noise to zero (rotation coeffs often leak into word 9).
    if abs(tx) < 1e-4:
        tx = 0.0
    if abs(ty) < 1e-4:
        ty = 0.0
    if abs(tz) < 1e-4:
        tz = 0.0
    if _translation_ok(tx, ty, tz):
        return tx, ty, tz
    return None


def _wheel_blob_index(catalog_index: int, assembly_indices: list[int]) -> int:
    first_wheel = assembly_indices.index(WHEEL_INDICES[0])
    return assembly_indices.index(catalog_index) - first_wheel


def _wheel_translation(main_data: list[int], blob_index: int) -> tuple[float, float, float] | None:
    for idx in (blob_index, blob_index + 1, blob_index - 1):
        if idx < 0:
            continue
        translation = parse_part_translation(main_data, VEHICLE_WHEEL_BLOB_VADDR, idx)
        if translation is not None:
            return translation
    return None


def build_descriptor_part_lookup(
    descriptors: list[VehicleRomDescriptor],
) -> dict[int, PartTransformRef]:
    lookup: dict[int, PartTransformRef] = {}
    for desc in descriptors:
        for part_index, catalog_index in enumerate(desc.catalog_indices):
            lookup[catalog_index] = PartTransformRef(
                main_data_vaddr=desc.main_data_vaddr,
                part_index=part_index,
                source=f"descriptor_0x{desc.rom_offset:06x}",
            )
    return lookup


def resolve_part_transform(
    catalog_index: int,
    *,
    body_catalog_index: int,
    main_data: list[int],
    descriptor_lookup: dict[int, PartTransformRef],
    assembly_indices: list[int],
) -> tuple[list[float], PartTransformRef | None]:
    """Return a translation-only 3×4 matrix for one assembly catalog row."""
    if catalog_index == body_catalog_index:
        return identity_matrix(), PartTransformRef(
            main_data_vaddr=VEHICLE_BODY_BLOB_VADDR,
            part_index=-1,
            source="body_identity",
        )

    if catalog_index in TRIM_INDICES:
        ref = descriptor_lookup.get(catalog_index)
        if ref is not None:
            translation = parse_part_translation(main_data, ref.main_data_vaddr, ref.part_index)
            if translation is not None:
                tx, ty, tz = translation
                return translation_matrix(tx, ty, tz), ref

    if catalog_index in WHEEL_INDICES and catalog_index in assembly_indices:
        blob_index = _wheel_blob_index(catalog_index, assembly_indices)
        translation = _wheel_translation(main_data, blob_index)
        if translation is not None:
            tx, ty, tz = translation
            return translation_matrix(tx, ty, tz), PartTransformRef(
                main_data_vaddr=VEHICLE_WHEEL_BLOB_VADDR,
                part_index=blob_index,
                source="wheel_blob_translation",
            )

    ref = descriptor_lookup.get(catalog_index)
    if ref is not None:
        translation = parse_part_translation(main_data, ref.main_data_vaddr, ref.part_index)
        if translation is not None:
            tx, ty, tz = translation
            return translation_matrix(tx, ty, tz), ref

    return identity_matrix(), None


def load_catalog_vertices(
    polygon_rom: list[int],
    *,
    rom_offset: int,
    obc: int,
) -> list[tuple[float, float, float]]:
    parsed = try_parse_polygon_object(polygon_rom, rom_offset)
    if parsed is not None:
        return parsed.vertices
    collector = MeshCollector()
    geo = GeoState()
    try:
        geo_parse_np_ns_collect(geo, polygon_rom, rom_offset, max(obc, 64), collector)
    except GeoParseError:
        return []
    return collector.vertices


def matrix_4x4_words_to_geo12(words: list[int], *, offset: int = 0) -> list[float]:
    """Convert 16-word column-friendly 4×4 (geo FIFO layout) to 12-float 3×4."""
    floats = [u2f(words[offset + i]) for i in range(16)]
    return [
        floats[0],
        floats[1],
        floats[2],
        floats[4],
        floats[5],
        floats[6],
        floats[8],
        floats[9],
        floats[10],
        floats[12],
        floats[13],
        floats[14],
    ]


def multiply_matrices(left: list[float], right: list[float]) -> list[float]:
    """Multiply 3×4 row-basis matrices (same convention as transform_point)."""
    out = [0.0] * 12
    for col in range(3):
        for row in range(3):
            out[col * 3 + row] = (
                (left[row] * right[col])
                + (left[row + 3] * right[col + 3])
                + (left[row + 6] * right[col + 6])
            )
    out[9] = (
        (left[0] * right[9])
        + (left[3] * right[10])
        + (left[6] * right[11])
        + left[9]
    )
    out[10] = (
        (left[1] * right[9])
        + (left[4] * right[10])
        + (left[7] * right[11])
        + left[10]
    )
    out[11] = (
        (left[2] * right[9])
        + (left[5] * right[10])
        + (left[8] * right[11])
        + left[11]
    )
    return out


def _pose_is_yaw_like(matrix: list[float]) -> bool:
    """True for yaw-about-Y style poses; menu captures often swap axes instead."""
    if not _pose_preserves_depth(matrix):
        return False
    if abs(matrix[4]) < 0.5:
        return False
    if abs(matrix[2]) > 0.5 or abs(matrix[5]) > 0.5:
        return False
    return abs(matrix[0]) + abs(matrix[8]) > 0.5


def select_workram_pose(slots: list[list[float]]) -> list[float] | None:
    """
    Pick a workram 0x5E3E00 pose for static export.

    Car-select captures: slot 0 is often 2D (Z column zero); slot 2 may be an axis
    swap. Prefer yaw-like 3D, else translation-only from the first usable slot.
    """
    for matrix in slots:
        if _pose_is_yaw_like(matrix):
            return matrix
    for matrix in slots:
        tx, ty, tz = matrix[9], matrix[10], matrix[11]
        if _translation_ok(tx, ty, tz):
            return translation_matrix(tx, ty, tz)
    return slots[0] if slots else None


def load_workram_pose_matrices(capture_dir: Path) -> list[list[float]]:
    """
    Load per-slot 4×4 pose matrices from optional workram dump (draw_car_primary @ 0x44F84).

    Each slot is 16 words; player index selects slot via ``r3 * 16``.
    """
    path = capture_dir / "workram_5e3e00.bin"
    if not path.is_file():
        return []
    words = list(struct.unpack(f"<{path.stat().st_size // 4}I", path.read_bytes()))
    slots: list[list[float]] = []
    for base in range(0, len(words) - 15, 16):
        chunk = words[base : base + 16]
        matrix = matrix_4x4_words_to_geo12(chunk)
        if _matrix_ok(matrix):
            slots.append(matrix)
    return slots


def catalog_polygon_offsets(
    catalog_entries,
    catalog_indices: list[int] | None = None,
) -> dict[int, CatalogPolygonOffsets]:
    """
    field_a / field_b from the master catalog @ 0x2864B40 (not a separate instance table).

    Index 60 begins @ main_data 0x2864F00 — same stride-4 layout as every catalog row.
    """
    indices = catalog_indices if catalog_indices is not None else range(len(catalog_entries))
    out: dict[int, CatalogPolygonOffsets] = {}
    for idx in indices:
        if idx < 0 or idx >= len(catalog_entries):
            continue
        entry = catalog_entries[idx]
        out[idx] = CatalogPolygonOffsets(
            catalog_index=idx,
            field_a=entry.field_a,
            field_b=entry.field_b,
            oba=entry.oba,
            obc=entry.obc,
            rom_offset=entry.rom_offset,
        )
    return out


def _pose_preserves_depth(matrix: list[float]) -> bool:
    """True when the 3×3 block maps Z (workram 0x5E3E00 car-select poses often do not)."""
    return abs(matrix[2]) + abs(matrix[5]) + abs(matrix[8]) > 1e-4


def apply_group_pose(
    vertices: list[tuple[float, float, float]],
    pose_matrix: list[float],
) -> list[tuple[float, float, float]]:
    """Apply workram pose once to a combined assembly (not per-part)."""
    if _pose_preserves_depth(pose_matrix):
        return transform_vertices(vertices, pose_matrix)
    tx, ty, tz = pose_matrix[9], pose_matrix[10], pose_matrix[11]
    if _translation_ok(tx, ty, tz):
        return transform_vertices(vertices, translation_matrix(tx, ty, tz))
    return vertices


def transform_vertices(
    vertices: list[tuple[float, float, float]],
    matrix: list[float],
) -> list[tuple[float, float, float]]:
    out: list[tuple[float, float, float]] = []
    for x, y, z in vertices:
        point = PolyVertex(x, y, z)
        transform_point(point, matrix)
        out.append((point.x, point.y, point.pz))
    return out


def load_vehicle_main_data(rom_dir=None) -> list[int]:
    rom_dir = resolve_rom_dir(rom_dir)
    raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def build_race_assembly_vertices(
    *,
    body_catalog_index: int,
    catalog_entries,
    polygon_rom: list[int],
    main_data: list[int] | None = None,
    rom_dir=None,
    include_panels: bool = True,
    pose_matrix: list[float] | None = None,
) -> tuple[list[tuple[float, float, float]], list[dict[str, object]]]:
    """
  Assemble body + trim + wheels with descriptor main_data transforms.

  When ``pose_matrix`` is set (from workram 0x5E3E00 capture), it is applied
  after each part transform — matching draw_car_primary @ 0x44F84.

  Returns combined vertices and per-part metadata for export.
    """
    rom_dir = resolve_rom_dir(rom_dir)
    if main_data is None:
        main_data = load_vehicle_main_data(rom_dir)

    descriptors = parse_rom_vehicle_descriptors(rom_dir)
    descriptor_lookup = build_descriptor_part_lookup(descriptors)
    assembly = next(t for t in parse_vehicle_catalog_tables(rom_dir) if t.name == "assembly_parts")

    wheel_ids = WHEEL_INDICES if include_panels else WHEEL_HUB_INDICES
    draw_ids = [body_catalog_index, *TRIM_INDICES, *wheel_ids]
    combined: list[tuple[float, float, float]] = []
    parts: list[dict[str, object]] = []

    for part_idx in draw_ids:
        entry = catalog_entries[part_idx]
        local = load_catalog_vertices(
            polygon_rom,
            rom_offset=entry.rom_offset,
            obc=entry.obc,
        )
        if not local:
            continue

        matrix, ref = resolve_part_transform(
            part_idx,
            body_catalog_index=body_catalog_index,
            main_data=main_data,
            descriptor_lookup=descriptor_lookup,
            assembly_indices=assembly.catalog_indices,
        )
        world = transform_vertices(local, matrix)
        base = len(combined)
        combined.extend(world)
        parts.append(
            {
                "catalog_index": part_idx,
                "vertex_offset": base,
                "vertex_count": len(world),
                "rom_offset": entry.rom_offset,
                "transform": {
                    "matrix": [round(v, 6) for v in matrix],
                    "translation": [round(matrix[9], 6), round(matrix[10], 6), round(matrix[11], 6)],
                    "main_data_vaddr": f"0x{ref.main_data_vaddr:08x}" if ref else None,
                    "part_index": ref.part_index if ref else None,
                    "source": ref.source if ref else "identity",
                },
            }
        )

    if pose_matrix is not None and combined:
        combined = apply_group_pose(combined, pose_matrix)

    return combined, parts
