"""Scene placement tables in main_data (matrix + geo_object_data parameters)."""

from __future__ import annotations

import math
from dataclasses import dataclass

from tools.model2_float import u2f
from tools.model2_geo import (
    GeoParseError,
    GeoState,
    MeshCollector,
    geo_parse_np_ns_collect,
    identity_matrix,
    mame_polygon_exportable,
    try_parse_polygon_object,
)


def is_polygon_rom_oba(oba: int) -> bool:
    """Polygon ROM pointer — not a float misread as an address."""
    if oba & 0x0100_0000:
        return False
    return (oba & 0xFF80_0000) == 0x0080_0000


@dataclass
class PlacementRecord:
    main_data_word: int
    matrix: list[float]
    tpa: int
    tha: int
    oba: int
    obc: int
    rom_offset: int
    vertices: list[tuple[float, float, float]]
    placement_index: int = -1


def is_ambient_env_ring_placement(rec: PlacementRecord) -> bool:
    """
    Detect sky/ambient environment-map anchor rings in track exports.

    Championship placement 456 (ROM ``0x9ACA84``) decodes to two coplanar decagons
    (10 points, 36° steps) at radius ~8000 and Y ≈ 3284.9 / -200 — not drivable track.
    """
    hi = lo = 0
    for x, y, z in rec.vertices:
        if math.hypot(x, z) < 2000:
            continue
        if abs(y - 3284.9) < 5:
            hi += 1
        if abs(y + 200.0) < 5:
            lo += 1
    return hi >= 8 and lo >= 8


def _matrix_ok(values: list[float]) -> bool:
    if len(values) != 12:
        return False
    if not all(math.isfinite(v) and abs(v) < 10_000 for v in values):
        return False
    if all(abs(v) < 1e-7 for v in values):
        return False
    return True


def _try_matrix_at(words: list[int], index: int) -> list[float] | None:
    if index + 12 > len(words):
        return None
    values = [u2f(words[index + i]) for i in range(12)]
    return values if _matrix_ok(values) else None


def _find_matrix_before(words: list[int], index: int, lookback: int = 24) -> list[float] | None:
    mat_ops = (0x0B << 23, 0x1B << 23)
    start = max(0, index - lookback)
    for back in range(index - 1, start - 1, -1):
        if words[back] in mat_ops:
            matrix = _try_matrix_at(words, back + 1)
            if matrix:
                return matrix
    for back in range(index - 12, start - 1, -1):
        matrix = _try_matrix_at(words, back)
        if matrix:
            return matrix
    return None


def _apply_placement(
    polygon_rom: list[int],
    *,
    matrix: list[float],
    rom_offset: int,
    obc: int,
) -> list[tuple[float, float, float]] | None:
    """Placement-stream vertex decode (matches i960 placement cursor indexing)."""
    geo = GeoState(matrix=list(matrix))
    collector = MeshCollector()
    count = obc if obc else 0xFFFFF
    try:
        geo_parse_np_ns_collect(geo, polygon_rom, rom_offset, count, collector)
    except GeoParseError:
        return None
    if len(collector.vertices) < 8:
        return None
    m = max(max(abs(v[0]), abs(v[1]), abs(v[2])) for v in collector.vertices)
    if m < 2.0 or m > 40_000:
        return None
    return collector.vertices


def _triangle_normal(
    vertices: list[tuple[float, float, float]],
    indices: tuple[int, ...],
) -> tuple[float, float, float]:
    if len(indices) < 3:
        return (0.0, 0.0, 1.0)
    ax, ay, az = vertices[indices[0]]
    bx, by, bz = vertices[indices[1]]
    cx, cy, cz = vertices[indices[2]]
    ab = (bx - ax, by - ay, bz - az)
    ac = (cx - ax, cy - ay, cz - az)
    nx = ab[1] * ac[2] - ab[2] * ac[1]
    ny = ab[2] * ac[0] - ab[0] * ac[2]
    nz = ab[0] * ac[1] - ab[1] * ac[0]
    length = math.sqrt((nx * nx) + (ny * ny) + (nz * nz))
    if length < 1e-12:
        return (0.0, 0.0, 1.0)
    inv = 1.0 / length
    return (nx * inv, ny * inv, nz * inv)


def _resolve_face_normal(
    prim,
    vertices: list[tuple[float, float, float]],
) -> tuple[float, float, float]:
    if prim.normal is not None:
        nx, ny, nz = prim.normal
        length = math.sqrt((nx * nx) + (ny * ny) + (nz * nz))
        if length >= 1e-6:
            inv = 1.0 / length
            return (nx * inv, ny * inv, nz * inv)
    return _triangle_normal(vertices, prim.indices)


def apply_placement_mesh(
    polygon_rom: list[int],
    *,
    matrix: list[float],
    rom_offset: int,
    obc: int,
    mame_cull: bool = True,
) -> tuple[
    list[tuple[float, float, float]],
    list[tuple[int, ...]],
    list[tuple[float, float, float]],
] | None:
    """Vertices + faces + face normals using MAME rasterizer visibility rules."""
    count = obc if obc else 0xFFFFF
    parsed = try_parse_polygon_object(
        polygon_rom, rom_offset, count=count, matrix=matrix
    )
    if parsed is None:
        return None
    faces: list[tuple[int, ...]] = []
    face_normals: list[tuple[float, float, float]] = []
    for prim in parsed.primitives:
        if len(prim.indices) < 3:
            continue
        if mame_cull and not mame_polygon_exportable(prim.attr):
            continue
        faces.append(prim.indices)
        face_normals.append(_resolve_face_normal(prim, parsed.vertices))
    if not faces:
        return None
    return parsed.vertices, faces, face_normals


def discover_placements(
    main_data: list[int],
    polygon_rom: list[int],
    *,
    polygon_rom_mask: int,
) -> list[PlacementRecord]:
    """Find (tpa, tha, oba, obc) tuples with polygon-ROM oba and a preceding matrix."""
    records: list[PlacementRecord] = []
    seen: set[tuple[int, int, tuple[float, ...]]] = set()

    for i in range(len(main_data) - 3):
        tpa, tha, oba, obc = main_data[i : i + 4]
        if not is_polygon_rom_oba(oba):
            continue
        if obc <= 0 or obc > 200_000:
            continue
        rom_offset = oba & polygon_rom_mask
        matrix = _find_matrix_before(main_data, i)
        if matrix is None:
            matrix = identity_matrix()
        key = (rom_offset, obc, tuple(round(v, 4) for v in matrix))
        if key in seen:
            continue
        verts = _apply_placement(polygon_rom, matrix=matrix, rom_offset=rom_offset, obc=obc)
        if verts is None:
            continue
        seen.add(key)
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
            )
        )
    records.sort(key=lambda r: r.main_data_word)
    return records


def group_placements(
    records: list[PlacementRecord],
    *,
    gap_words: int = 512,
) -> list[list[PlacementRecord]]:
    if not records:
        return []
    groups: list[list[PlacementRecord]] = [[records[0]]]
    for rec in records[1:]:
        if rec.main_data_word - groups[-1][-1].main_data_word <= gap_words:
            groups[-1].append(rec)
        else:
            groups.append([rec])
    return groups
