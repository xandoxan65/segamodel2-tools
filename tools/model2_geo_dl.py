"""Model 2 geometry display-list interpreter (MAME geo_parse / geo_process_command)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable

from tools.model2_float import u2f
from tools.model2_geo import (
    GeoMode,
    GeoParseError,
    GeoState,
    MeshCollector,
    PolyVertex,
    geo_parse_nn_ns_collect,
    geo_parse_nn_s_collect,
    geo_parse_np_ns_collect,
    geo_parse_np_s_collect,
    identity_matrix,
)

# i960 virtual addresses for main_data ROM (model2.cpp memory map).
MAIN_DATA_BASE_A = 0x0200_0000
MAIN_DATA_END_A = 0x03FF_FFFF
MAIN_DATA_BASE_B = 0x0600_0000
MAIN_DATA_END_B = 0x06FF_FFFF
MAIN_DATA_MIRROR_WORDS = 0x100_0000 // 4


class DisplayListError(Exception):
    pass


@dataclass
class DrawnObject:
    rom_offset: int
    oba: int
    obc: int
    vertex_count: int
    mode: GeoMode


@dataclass
class DisplayListResult:
    source: str
    start_word: int
    words_consumed: int
    vertices: list[tuple[float, float, float]]
    objects: list[DrawnObject]
    commands_executed: int


@dataclass
class GeoDisplayContext:
    """Runtime buffers available while executing a display list."""

    polygon_rom: list[int]
    polygon_rom_mask: int
    polygon_ram0: list[int] = field(default_factory=lambda: [0] * 0x8000)
    polygon_ram1: list[int] = field(default_factory=lambda: [0] * 0x8000)


def vaddr_to_main_data_word(vaddr: int) -> int | None:
    if MAIN_DATA_BASE_A <= vaddr <= MAIN_DATA_BASE_A + (MAIN_DATA_END_A - MAIN_DATA_BASE_A):
        return (vaddr - MAIN_DATA_BASE_A) // 4
    if MAIN_DATA_BASE_B <= vaddr <= MAIN_DATA_BASE_B + (MAIN_DATA_END_B - MAIN_DATA_BASE_B):
        return (vaddr - MAIN_DATA_BASE_B) // 4 + MAIN_DATA_MIRROR_WORDS
    return None


def fixed24_to_float(word: int) -> float:
    """Raster cmd-buffer pack (MAME: u2f(word<<8)). Poly-ROM verts use u2f."""
    return u2f((word & 0xFFFFFF) << 8)


def _copy_geo_state(state: GeoState) -> GeoState:
    return GeoState(
        mode=state.mode,
        matrix=list(state.matrix),
        focus=state.focus.copy(),
        light=state.light.copy(),
        lod=state.lod,
        texture_parameters=list(state.texture_parameters),
        coef_table=list(state.coef_table),
    )


class GeoDisplayListRunner:
    """Execute geo display lists and collect world-space vertices."""

    def __init__(self, ctx: GeoDisplayContext) -> None:
        self.ctx = ctx
        self._parsers = {
            GeoMode.NP_NS: geo_parse_np_ns_collect,
            GeoMode.NP_S: geo_parse_np_s_collect,
            GeoMode.NN_NS: geo_parse_nn_ns_collect,
            GeoMode.NN_S: geo_parse_nn_s_collect,
        }

    def run(
        self,
        words: list[int],
        start: int,
        *,
        source: str = "unknown",
        max_ops: int = 0x8000,
        max_words: int = 0x20000 // 4,
    ) -> DisplayListResult:
        geo = GeoState()
        collector = MeshCollector()
        drawn: list[DrawnObject] = []
        index = start
        end_limit = min(len(words), start + max_words)
        ops = 0
        finished = False

        while index < end_limit and ops < max_ops and not finished:
            opcode = words[index]
            index += 1
            ops += 1

            if opcode & 0x8000_0000:
                jump = (opcode & 0x1FFFF) // 4
                if jump >= len(words):
                    raise DisplayListError(f"jump out of range: {jump}")
                index = jump
                continue

            cmd = (opcode >> 23) & 0x1F
            index, done = self._dispatch(cmd, geo, words, index, end_limit, collector, drawn)
            if done:
                finished = True

        if not finished:
            raise DisplayListError("display list did not reach geo_end")

        return DisplayListResult(
            source=source,
            start_word=start,
            words_consumed=index - start,
            vertices=collector.vertices,
            objects=drawn,
            commands_executed=ops,
        )

    def _dispatch(
        self,
        cmd: int,
        geo: GeoState,
        words: list[int],
        index: int,
        end_limit: int,
        collector: MeshCollector,
        drawn: list[DrawnObject],
    ) -> tuple[int, bool]:
        if cmd in (0x01, 0x11):
            return self._object_data(geo, words, index, end_limit, collector, drawn), False
        if cmd in (0x02, 0x12):
            return self._direct_data(words, index, end_limit, geo, collector), False
        if cmd in (0x03, 0x13):
            return self._skip(words, index, 6, end_limit), False
        if cmd in (0x04,):
            return self._texture_data(words, index, end_limit), False
        if cmd in (0x05, 0x15):
            return self._polygon_data(words, index, end_limit), False
        if cmd in (0x06,):
            return self._texture_parameters(geo, words, index, end_limit), False
        if cmd in (0x07, 0x17):
            return self._set_mode(geo, words, index, end_limit), False
        if cmd in (0x08, 0x18):
            return self._skip(words, index, 1, end_limit), False
        if cmd in (0x09, 0x19):
            return self._focal_distance(geo, words, index, end_limit), False
        if cmd in (0x0A, 0x1A):
            return self._light_source(geo, words, index, end_limit), False
        if cmd in (0x0B, 0x1B):
            return self._matrix_write(geo, words, index, end_limit), False
        if cmd in (0x0C, 0x1C):
            return self._translate_write(geo, words, index, end_limit), False
        if cmd in (0x0D,):
            return self._data_mem_push(words, index, end_limit), False
        if cmd in (0x0E,):
            return self._geo_test(words, index, end_limit), False
        if cmd in (0x0F, 0x1F):
            return index, True
        if cmd in (0x10,):
            return self._skip(words, index, 1, end_limit), False
        if cmd in (0x14,):
            return self._log_data(words, index, end_limit), False
        if cmd in (0x16,):
            return self._lod(geo, words, index, end_limit), False
        if cmd in (0x1D,):
            return self._code_upload(words, index, end_limit), False
        if cmd in (0x1E,):
            return self._skip(words, index, 1, end_limit), False
        if cmd in (0x00,):
            return index, False
        raise DisplayListError(f"unknown geo command {cmd:#x}")

    def _require(self, index: int, count: int, end_limit: int) -> None:
        if index + count > end_limit:
            raise DisplayListError("display list overflow")

    def _skip(self, words: list[int], index: int, count: int, end_limit: int) -> int:
        self._require(index, count, end_limit)
        return index + count

    def _object_data(
        self,
        geo: GeoState,
        words: list[int],
        index: int,
        end_limit: int,
        collector: MeshCollector,
        drawn: list[DrawnObject],
    ) -> int:
        self._require(index, 4, end_limit)
        _tpa, _tha, oba, obc = words[index : index + 4]
        index += 4

        if oba & 0x0100_0000:
            base = oba & 0x7FFF
            rom = self.ctx.polygon_ram1
        elif oba & 0x0080_0000:
            base = oba & self.ctx.polygon_rom_mask
            rom = self.ctx.polygon_rom
        else:
            base = oba & 0x7FFF
            rom = self.ctx.polygon_ram0

        count = 0xFFFFF if obc == 0 else obc
        mode = GeoMode(geo.mode & 3)
        parser = self._parsers[mode]
        local = MeshCollector()
        try:
            parser(_copy_geo_state(geo), rom, base, count, local)
        except GeoParseError as exc:
            raise DisplayListError(f"polygon parse failed at rom {base:#x}: {exc}") from exc

        if not local.vertices:
            raise DisplayListError(f"polygon object at {base:#x} produced no vertices")

        base_index = len(collector.vertices)
        collector.vertices.extend(local.vertices)
        collector.primitives.extend(local.primitives)
        drawn.append(
            DrawnObject(
                rom_offset=base,
                oba=oba,
                obc=obc,
                vertex_count=len(local.vertices),
                mode=mode,
            )
        )
        return index

    def _direct_data(
        self,
        words: list[int],
        index: int,
        end_limit: int,
        geo: GeoState,
        collector: MeshCollector,
    ) -> int:
        self._require(index, 8, end_limit)
        index += 2  # tpa, tha
        for _ in range(2):
            p = PolyVertex(
                u2f(words[index]),
                u2f(words[index + 1]),
                u2f(words[index + 2]),
            )
            index += 3
            from tools.model2_geo import apply_focus, transform_point

            transform_point(p, geo.matrix)
            apply_focus(geo, p)
            collector.add_vertex(p)

        while index < end_limit:
            attr = words[index]
            index += 1
            if (attr & 3) == 0:
                break
            self._require(index, 5, end_limit)
            index += 2  # luma, distance
            p = PolyVertex(
                u2f(words[index]),
                u2f(words[index + 1]),
                u2f(words[index + 2]),
            )
            index += 3
            from tools.model2_geo import apply_focus, transform_point

            transform_point(p, geo.matrix)
            apply_focus(geo, p)
            collector.add_vertex(p)
            if attr & 1:
                self._require(index, 3, end_limit)
                p = PolyVertex(
                    u2f(words[index]),
                    u2f(words[index + 1]),
                    u2f(words[index + 2]),
                )
                index += 3
                transform_point(p, geo.matrix)
                apply_focus(geo, p)
                collector.add_vertex(p)
        return index

    def _texture_data(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        count = words[index + 1]
        return self._skip(words, index, 2 + count, end_limit)

    def _polygon_data(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        address, count = words[index], words[index + 1]
        index += 2
        if address & 0x0100_0000:
            dest = self.ctx.polygon_ram1
            addr = address & 0x7FFF
        else:
            dest = self.ctx.polygon_ram0
            addr = address & 0x7FFF
        self._require(index, count, end_limit)
        if addr + count > len(dest):
            raise DisplayListError("polygon_data write out of polygon RAM")
        for i in range(count):
            dest[addr + i] = words[index + i]
        return index + count

    def _texture_parameters(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        tex_index = words[index] >> 2
        count = words[index + 1]
        index += 2
        self._require(index, count * 2, end_limit)
        for _ in range(count):
            param = words[index]
            index += 1
            geo.coef_table[tex_index] = u2f(words[index])
            index += 1
            tp = geo.texture_parameters[tex_index]
            tp.diffuse = float(param & 0xFF)
            tp.ambient = float((param >> 8) & 0xFF)
            tp.specular_scale = float((param >> 16) & 0xFF)
            tp.specular_control = (param >> 24) & 0xFF
            tex_index = (tex_index + 1) & 0x1F
        return index

    def _set_mode(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 1, end_limit)
        geo.mode = words[index]
        return index + 1

    def _focal_distance(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        geo.focus.x = u2f(words[index])
        geo.focus.y = u2f(words[index + 1])
        return index + 2

    def _light_source(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 3, end_limit)
        geo.light.x = u2f(words[index])
        geo.light.y = u2f(words[index + 1])
        geo.light.pz = u2f(words[index + 2])
        return index + 3

    def _matrix_write(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 12, end_limit)
        for i in range(12):
            geo.matrix[i] = u2f(words[index + i])
        return index + 12

    def _translate_write(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 3, end_limit)
        geo.matrix[9] = u2f(words[index])
        geo.matrix[10] = u2f(words[index + 1])
        geo.matrix[11] = u2f(words[index + 2])
        return index + 3

    def _data_mem_push(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        count = words[index + 1]
        return self._skip(words, index, 2 + count, end_limit)

    def _geo_test(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 34, end_limit)
        index += 33  # fifo test words
        blocks = words[index]
        index += 1
        for _ in range(blocks):
            self._require(index, 3, end_limit)
            count = words[index + 1]
            index += 3
            index += count
        return index

    def _log_data(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        count = words[index + 1]
        return self._skip(words, index, 2 + count, end_limit)

    def _lod(self, geo: GeoState, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 1, end_limit)
        geo.lod = u2f(words[index])
        return index + 1

    def _code_upload(self, words: list[int], index: int, end_limit: int) -> int:
        self._require(index, 2, end_limit)
        count = words[index + 1]
        return self._skip(words, index, 2 + count * 3, end_limit)


def is_polygon_rom_oba(oba: int) -> bool:
    if oba & 0x0100_0000:
        return False
    return (oba & 0xFF80_0000) == 0x0080_0000


def try_run_display_list(
    runner: GeoDisplayListRunner,
    words: list[int],
    start: int,
    *,
    source: str,
    require_rom_object: bool = False,
) -> DisplayListResult | None:
    try:
        result = runner.run(words, start, source=source)
    except DisplayListError:
        return None
    if not result.vertices:
        return None
    if require_rom_object and not any(is_polygon_rom_oba(o.oba) for o in result.objects):
        return None
    for x, y, z in result.vertices:
        if not math.isfinite(x) or not math.isfinite(y) or not math.isfinite(z):
            return None
        if max(abs(x), abs(y), abs(z)) > 80_000:
            return None
    peak = max(max(abs(v[0]), abs(v[1]), abs(v[2])) for v in result.vertices)
    if peak < 1.0:
        return None
    return result


def discover_display_list_starts(maincpu_words: list[int], main_data_words: list[int]) -> list[tuple[int, str]]:
    """Find candidate display-list offsets via i960 pointers into main_data."""
    seen: set[int] = set()
    out: list[tuple[int, str]] = []
    for w in maincpu_words:
        off = vaddr_to_main_data_word(w)
        if off is None or off < 0 or off >= len(main_data_words):
            continue
        if off in seen:
            continue
        seen.add(off)
        out.append((off, f"maincpu_ptr_{w:#010x}"))
    out.sort(key=lambda item: item[0])
    return out
