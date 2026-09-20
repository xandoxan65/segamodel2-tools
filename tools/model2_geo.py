"""Sega Model 2 geometry engine polygon parsers (ported from MAME model2_v.cpp)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable

from tools.model2_float import u2f


class GeoMode(IntEnum):
    NP_NS = 0  # normals present, no specular
    NP_S = 1
    NN_NS = 2  # no normals in stream
    NN_S = 3


@dataclass
class PolyVertex:
    x: float = 0.0
    y: float = 0.0
    pz: float = 0.0

    def copy(self) -> PolyVertex:
        return PolyVertex(self.x, self.y, self.pz)


@dataclass
class TextureParameter:
    diffuse: float = 128.0
    ambient: float = 0.0
    specular_control: int = 0
    specular_scale: float = 0.0


@dataclass
class GeoState:
    mode: int = 0
    matrix: list[float] = field(default_factory=list)
    focus: PolyVertex = field(default_factory=lambda: PolyVertex(1.0, 1.0, 0.0))
    light: PolyVertex = field(default_factory=lambda: PolyVertex(0.0, 0.0, 1.0))
    lod: float = 1.0
    texture_parameters: list[TextureParameter] = field(default_factory=list)
    coef_table: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.matrix:
            self.matrix = identity_matrix()
        if not self.texture_parameters:
            self.texture_parameters = [TextureParameter() for _ in range(32)]
        if not self.coef_table:
            self.coef_table = [1.0] * 32


@dataclass
class MeshPrimitive:
    indices: tuple[int, ...]
    attr: int
    normal: tuple[float, float, float] | None = None
    front: bool = True


@dataclass
class ParsedObject:
    rom_offset: int
    mode: GeoMode
    words_consumed: int
    vertices: list[tuple[float, float, float]]
    primitives: list[MeshPrimitive]


def identity_matrix() -> list[float]:
    return [
        1.0, 0.0, 0.0,
        0.0, 1.0, 0.0,
        0.0, 0.0, 1.0,
        0.0, 0.0, 0.0,
    ]


def transform_point(point: PolyVertex, matrix: list[float]) -> None:
    x, y, pz = point.x, point.y, point.pz
    point.x = (x * matrix[0]) + (y * matrix[3]) + (pz * matrix[6]) + matrix[9]
    point.y = (x * matrix[1]) + (y * matrix[4]) + (pz * matrix[7]) + matrix[10]
    point.pz = (x * matrix[2]) + (y * matrix[5]) + (pz * matrix[8]) + matrix[11]


def transform_vector(vector: PolyVertex, matrix: list[float]) -> None:
    x, y, pz = vector.x, vector.y, vector.pz
    vector.x = (x * matrix[0]) + (y * matrix[3]) + (pz * matrix[6])
    vector.y = (x * matrix[1]) + (y * matrix[4]) + (pz * matrix[7])
    vector.pz = (x * matrix[2]) + (y * matrix[5]) + (pz * matrix[8])


def normalize_vector(vector: PolyVertex) -> None:
    n = math.sqrt((vector.x * vector.x) + (vector.y * vector.y) + (vector.pz * vector.pz))
    if n:
        oon = 1.0 / n
        vector.x *= oon
        vector.y *= oon
        vector.pz *= oon


def dot_product(v1: PolyVertex, v2: PolyVertex) -> float:
    return (v1.x * v2.x) + (v1.y * v2.y) + (v1.pz * v2.pz)


def vector_cross3(v0: PolyVertex, v1: PolyVertex, v2: PolyVertex) -> PolyVertex:
    p1x, p1y, p1z = v1.x - v0.x, v1.y - v0.y, v1.pz - v0.pz
    p2x, p2y, p2z = v2.x - v0.x, v2.y - v0.y, v2.pz - v0.pz
    return PolyVertex(
        (p1y * p2z) - (p1z * p2y),
        (p1z * p2x) - (p1x * p2z),
        (p1x * p2y) - (p1y * p2x),
    )


def apply_focus(geo: GeoState, point: PolyVertex) -> None:
    point.x *= geo.focus.x
    point.y *= geo.focus.y


class GeoParseError(Exception):
    pass


class MeshCollector:
    def __init__(self) -> None:
        self.vertices: list[tuple[float, float, float]] = []
        self.primitives: list[MeshPrimitive] = []

    def add_vertex(self, point: PolyVertex) -> int:
        idx = len(self.vertices)
        self.vertices.append((point.x, point.y, point.pz))
        return idx

    def add_primitive(
        self,
        attr: int,
        indices: Iterable[int],
        *,
        normal: tuple[float, float, float] | None = None,
        front: bool = True,
    ) -> None:
        self.primitives.append(
            MeshPrimitive(tuple(indices), attr, normal=normal, front=front)
        )


def _read_point(words: list[int], index: int) -> tuple[PolyVertex, int]:
    if index + 2 >= len(words):
        raise GeoParseError("unexpected end of polygon stream")
    point = PolyVertex(u2f(words[index]), u2f(words[index + 1]), u2f(words[index + 2]))
    return point, index + 3


def _emit_point(geo: GeoState, collector: MeshCollector, point: PolyVertex) -> int:
    transform_point(point, geo.matrix)
    apply_focus(geo, point)
    return collector.add_vertex(point)


def _reasonable_vertex(point: PolyVertex) -> bool:
    for v in (point.x, point.y, point.pz):
        if not math.isfinite(v) or abs(v) > 25_000:
            return False
    return True


def mame_polygon_visible(attr: int, *, front: bool) -> bool:
    """
    Match model2_v.cpp check_culling() — polygons rejected here are never rasterized.

    Link type 0 faces only advance the strip; the hardware does not draw them.
    Single-sided primitives (attr bit 17 clear) cull back-facing links.
    """
    if ((attr >> 8) & 3) == 0:
        return False
    if ((attr >> 17) & 1) == 0 and not front:
        return False
    return True


def mame_polygon_exportable(attr: int) -> bool:
    """
    Polygons to include in static OBJ export for a free-orbit viewer.

    MAME also back-face and z-culls in view space; we only skip link-type-0 strip
    pads (never rasterized). Back faces are kept and drawn with DoubleSide materials.
    """
    return ((attr >> 8) & 3) != 0


def _object_is_plausible(parsed: ParsedObject) -> bool:
    if len(parsed.vertices) < 8:
        return False
    if parsed.words_consumed < 12:
        return False
    for x, y, z in parsed.vertices:
        if max(abs(x), abs(y), abs(z)) > 25_000:
            return False
    ys = [v[1] for v in parsed.vertices]
    xs = [v[0] for v in parsed.vertices]
    zs = [v[2] for v in parsed.vertices]
    y_span = max(ys) - min(ys)
    xz_span = max(max(xs) - min(xs), max(zs) - min(zs))
    # Misaligned walks often yield tiny objects with huge coordinate spread.
    if len(parsed.vertices) < 96 and y_span > 1200:
        return False
    if len(parsed.vertices) < 96 and xz_span > 12_000:
        return False
    return True


def _emit_link_point(
    geo: GeoState,
    collector: MeshCollector,
    point: PolyVertex,
    normal: PolyVertex,
) -> tuple[int, bool]:
    """Transform link point, apply MAME front/back test, then focus and store."""
    transform_point(point, geo.matrix)
    is_front = dot_product(normal, point) >= 0.0
    apply_focus(geo, point)
    return collector.add_vertex(point), is_front


def geo_parse_np_ns_collect(
    geo: GeoState, words: list[int], start: int, count: int, collector: MeshCollector
) -> int:
    """Normals present, no specular — MAME geo_parse_np_ns + rasterizer strip linkage."""
    index = start
    point, index = _read_point(words, index)
    if not _reasonable_vertex(point):
        raise GeoParseError("invalid seed vertex")
    v_p0_prev = _emit_point(geo, collector, point)

    point, index = _read_point(words, index)
    if not _reasonable_vertex(point):
        raise GeoParseError("invalid seed vertex")
    v_p1_prev = _emit_point(geo, collector, point)

    for _ in range(count):
        if index >= len(words):
            break
        attr = words[index]
        index += 1
        if (attr & 3) == 0:
            break

        normal, index = _read_point(words, index)
        transform_vector(normal, geo.matrix)
        normalize_vector(normal)
        normal_tuple = (normal.x, normal.y, normal.pz)

        point, index = _read_point(words, index)
        if not _reasonable_vertex(point):
            raise GeoParseError("invalid link vertex")
        v_p0, is_front = _emit_link_point(geo, collector, point, normal)

        if attr & 1:
            point, index = _read_point(words, index)
            if not _reasonable_vertex(point):
                raise GeoParseError("invalid quad vertex")
            transform_point(point, geo.matrix)
            apply_focus(geo, point)
            v_p1 = collector.add_vertex(point)
            collector.add_primitive(
                attr,
                (v_p1_prev, v_p0_prev, v_p0, v_p1),
                normal=normal_tuple,
                front=is_front,
            )
        else:
            index += 3
            # MAME model2_3d_process_polygon: for triangles P1(n) = P0(n) before link update.
            v_p1 = v_p0
            collector.add_primitive(
                attr,
                (v_p1_prev, v_p0_prev, v_p0),
                normal=normal_tuple,
                front=is_front,
            )

        link = (attr >> 8) & 3
        if link in (0, 2):
            v_p0_prev = v_p0
            v_p1_prev = v_p1
        elif link == 1:
            v_p1_prev = v_p0
        elif link == 3:
            v_p0_prev = v_p1

    return index


def geo_parse_np_s_collect(
    geo: GeoState, words: list[int], start: int, count: int, collector: MeshCollector
) -> int:
    """Normals present, specular — same vertex stream as np_ns."""
    return geo_parse_np_ns_collect(geo, words, start, count, collector)


def geo_parse_nn_ns_collect(
    geo: GeoState, words: list[int], start: int, count: int, collector: MeshCollector
) -> int:
    """No normals in stream — MAME geo_parse_nn_ns."""
    index = start
    point, index = _read_point(words, index)
    if not _reasonable_vertex(point):
        raise GeoParseError("invalid seed vertex")
    transform_point(point, geo.matrix)
    p0 = point.copy()
    apply_focus(geo, point)
    v0 = collector.add_vertex(point)

    point, index = _read_point(words, index)
    if not _reasonable_vertex(point):
        raise GeoParseError("invalid seed vertex")
    transform_point(point, geo.matrix)
    p1 = point.copy()
    apply_focus(geo, point)
    v1 = collector.add_vertex(point)

    for _ in range(count):
        if index >= len(words):
            break
        attr = words[index]
        index += 1
        if (attr & 3) == 0:
            break

        index += 3  # skip stored normal slot

        point, index = _read_point(words, index)
        if not _reasonable_vertex(point):
            raise GeoParseError("invalid link vertex")
        transform_point(point, geo.matrix)
        p2 = point.copy()
        normal = vector_cross3(p0, p1, p2)
        normalize_vector(normal)
        normal_tuple = (normal.x, normal.y, normal.pz)
        is_front = dot_product(normal, point) >= 0.0
        apply_focus(geo, point)
        v2 = collector.add_vertex(point)

        if attr & 1:
            point, index = _read_point(words, index)
            if not _reasonable_vertex(point):
                raise GeoParseError("invalid quad vertex")
            transform_point(point, geo.matrix)
            p3 = point.copy()
            apply_focus(geo, point)
            v3 = collector.add_vertex(point)
            collector.add_primitive(
                attr, (v0, v1, v2, v3), normal=normal_tuple, front=is_front
            )
        else:
            index += 3
            p3 = p2.copy()
            v3 = v2
            collector.add_primitive(
                attr, (v0, v1, v2), normal=normal_tuple, front=is_front
            )

        link = (attr >> 8) & 3
        if link in (0, 2):
            p0, p1 = p2.copy(), p3.copy()
            v0, v1 = v2, v3
        elif link == 1:
            p1 = p2.copy()
            v1 = v2
        elif link == 3:
            p0 = p3.copy()
            v0 = v3

    return index


def geo_parse_nn_s_collect(
    geo: GeoState, words: list[int], start: int, count: int, collector: MeshCollector
) -> int:
    return geo_parse_nn_ns_collect(geo, words, start, count, collector)


def parse_polygon_object(
    words: list[int],
    offset: int,
    *,
    count: int = 0xFFFFF,
    mode: GeoMode = GeoMode.NP_NS,
    geo: GeoState | None = None,
) -> ParsedObject:
    geo = geo or GeoState(mode=int(mode))
    collector = MeshCollector()
    parsers = {
        GeoMode.NP_NS: geo_parse_np_ns_collect,
        GeoMode.NP_S: geo_parse_np_s_collect,
        GeoMode.NN_NS: geo_parse_nn_ns_collect,
        GeoMode.NN_S: geo_parse_nn_s_collect,
    }
    end = parsers[mode](geo, words, offset, count, collector)
    if len(collector.vertices) < 2:
        raise GeoParseError("too few vertices")
    return ParsedObject(
        rom_offset=offset,
        mode=mode,
        words_consumed=end - offset,
        vertices=collector.vertices,
        primitives=collector.primitives,
    )


def try_parse_polygon_object(
    words: list[int],
    offset: int,
    *,
    count: int = 0xFFFFF,
    matrix: list[float] | None = None,
) -> ParsedObject | None:
    if offset + 6 >= len(words):
        return None
    geo = GeoState(matrix=list(matrix)) if matrix else None
    best: ParsedObject | None = None
    for mode in GeoMode:
        try:
            parsed = parse_polygon_object(words, offset, count=count, mode=mode, geo=geo)
        except GeoParseError:
            continue
        if parsed.words_consumed < 4:
            continue
        if not _object_is_plausible(parsed):
            continue
        if best is None or len(parsed.vertices) > len(best.vertices):
            best = parsed
    return best


def walk_polygon_rom(words: list[int], *, start: int = 0, end: int | None = None) -> list[ParsedObject]:
    """Walk contiguous polygon ROM objects using the geo parsers."""
    end = len(words) if end is None else end
    objects: list[ParsedObject] = []
    offset = start
    misses = 0
    while offset + 6 < end:
        parsed = try_parse_polygon_object(words, offset)
        if parsed is None or parsed.words_consumed <= 0:
            offset += 1
            misses += 1
            if misses > 4096:
                break
            continue
        misses = 0
        if _object_is_plausible(parsed):
            objects.append(parsed)
            offset += parsed.words_consumed
        else:
            offset += 1
            misses += 1
    return objects
