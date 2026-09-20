"""Model 2 texture point / header decoding for static mesh export."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from tools.model2_geo import (
    GeoParseError,
    GeoState,
    MeshCollector,
    geo_parse_np_ns_collect,
    mame_polygon_exportable,
)
from tools.model2_texel_map import texel_map_id


LOGICAL_SHEET_W = 2048
LOGICAL_SHEET_H = 1024

# MAME model2rd.ipp: translucent textured polys treat texel 0xF (<<4 → 0xF0) as transparent.
TRANSPARENT_TEXEL = 0x0F


def texture_u16_mask(texture_rom_u32_words: int) -> int:
    """MAME raster uses u16 indices: mask = (texture_rom_bytes / 2) - 1."""
    return (texture_rom_u32_words * 2) - 1


def texture_addr_mask(addr: int, mask: int) -> int:
    if addr & 0x800000:
        raise ValueError("texture RAM addresses are not available in static ROM export")
    return addr & mask


def texture_read_u16(texture_rom: list[int], u16_index: int) -> int:
    """Read one u16 from texture ROM stored as a little-endian u32 word stream."""
    word = texture_rom[u16_index >> 1]
    return (word >> 16) & 0xFFFF if u16_index & 1 else word & 0xFFFF


def header_tho_words(attr: int) -> int:
    tho = (attr >> 12) & 0x1F
    if tho & 0x10:
        tho |= -16
    return tho


@dataclass(frozen=True)
class TexHeader:
    words: tuple[int, int, int, int]

    @property
    def valid(self) -> bool:
        if self.words[0] == 0xFFFFFFFF:
            return False
        if self.words[0] == 0 and self.words[2] == 0:
            return False
        return True

    @property
    def renderer(self) -> int:
        """MAME: (texheader[0] >> 13) & 3 — 0/1 solid, 2/3 textured."""
        return (self.words[0] >> 13) & 3 if self.valid else 0

    @property
    def textured(self) -> bool:
        return bool(self.renderer & 2)

    @property
    def translucent(self) -> bool:
        """MAME model2_v.cpp: bit 13 of renderer — cutout / alpha texels."""
        return bool(self.renderer & 1)

    @property
    def checker(self) -> bool:
        """MAME: (texheader[0] >> 15) & 1 — interleaved pixel transparency."""
        return bool((self.words[0] >> 15) & 1) if self.valid else False

    @property
    def texwidth(self) -> int:
        return 32 << (self.words[0] & 7)

    @property
    def texheight(self) -> int:
        return 32 << ((self.words[0] >> 3) & 7)

    @property
    def texx(self) -> int:
        return 32 * (self.words[2] & 0x3F)

    @property
    def texy(self) -> int:
        return 32 * ((self.words[2] >> 6) & 0x1F)

    @property
    def sheet_index(self) -> int:
        return 1 if (self.words[2] & 0x1000) else 0

    @property
    def colorbase(self) -> int:
        """MAME: (texheader[3] >> 6) & 0x3ff."""
        return (self.words[3] >> 6) & 0x3FF

    @property
    def mirror_x(self) -> bool:
        return bool((self.words[0] >> 8) & 1) if self.valid else False

    @property
    def mirror_y(self) -> bool:
        return bool((self.words[0] >> 9) & 1) if self.valid else False

    @property
    def lumabase(self) -> int:
        """MAME: (texheader[1] & 0xff) << 7."""
        return (self.words[1] & 0xFF) << 7

    @property
    def tex_wrap_x(self) -> bool:
        """MAME model2rd.ipp: wrap disabled when mirroring is enabled."""
        return bool((self.words[0] >> 6) & 1) and not self.mirror_x if self.valid else False

    @property
    def tex_wrap_y(self) -> bool:
        return bool((self.words[0] >> 7) & 1) and not self.mirror_y if self.valid else False


def _s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def mame_mirror_uv_fixed(
    u: int,
    v: int,
    *,
    tw: int,
    th: int,
    mirror_x: bool,
    mirror_y: bool,
) -> tuple[int, int]:
    """model2rd.ipp fetch_bilinear_texel() mirror (8.8 fixed patch-local u/v)."""
    u = _s32(u)
    v = _s32(v)
    if mirror_x and (u & (tw << 8)):
        u = _s32(~u & 0xFFFFFFFF)
    if mirror_y and (v & (th << 8)):
        v = _s32(~v & 0xFFFFFFFF)
    return u, v


def mame_patch_pixels_from_pairs(
    pairs: list[tuple[int, int]], *, pzs: list[float] | None = None
) -> tuple[list[float], list[float]]:
    """Patch-local pixels after model2_v.cpp pu/pv perspective divide (× inv_z / 8)."""
    return _patch_offsets_from_pairs(pairs, pzs=pzs)


def polygon_palette_colorbase(attr: int, header: TexHeader) -> int:
    """Colorbase for palette lookup (texheader[3] >> 6, else polygon attr >> 16)."""
    if header.valid and (header.words[3] >> 6):
        return header.colorbase
    return (attr >> 16) & 0x3FF


def polygon_palette_lumabase(attr: int, header: TexHeader) -> int:
    """Lumabase for palette lookup — ``(texheader[1] & 0xff) << 7`` only."""
    del attr
    if header.valid:
        return header.lumabase
    return 0


def palette_binding_from_texheader(
    attr: int, header: TexHeader
) -> tuple[int, int, str]:
    """Return (colorbase, lumabase, source) from textures-ROM texheader + attr."""
    if header.valid and (header.words[3] >> 6):
        return header.colorbase, polygon_palette_lumabase(attr, header), "texheader"
    return (attr >> 16) & 0x3FF, polygon_palette_lumabase(attr, header), "attr"


def resolve_uv_header(attr: int, header: TexHeader) -> TexHeader:
    """Resolve texheader[2] for atlas UV base (MAME texx/texy + srally static-ROM bank remap)."""
    del attr
    if not header.valid:
        return header
    w2 = header.words[2]
    if not (w2 & 0x1000):
        return header
    base = w2 & ~0x1000
    # Srally border billboards: Y index is +4 vs the sheet0 art slot (0x1ba4 vs 0x2a4).
    if header.words[0] & 0x4000 and header.texwidth <= 64:
        y_idx = ((base >> 6) & 0x1F) - 4
        if y_idx >= 0:
            w2 = (base & 0x3F) | ((y_idx & 0x1F) << 6)
            return TexHeader((header.words[0], header.words[1], w2, header.words[3]))
    # MAME swaps textureram banks when bit 0x1000 is set; srally static ROM maps art to bank0.
    return TexHeader((header.words[0], header.words[1], base, header.words[3]))


def polygon_renderer(attr: int, header: TexHeader) -> int:
    """MAME model2_v.cpp: (texheader[0] >> 13) & 3 — including renderer 0 solid."""
    if header.valid:
        return header.renderer
    attr_renderer = (attr >> 13) & 3
    if attr_renderer & 2:
        return attr_renderer
    return 0


def polygon_translucent(attr: int, header: TexHeader) -> bool:
    return bool(polygon_renderer(attr, header) & 1)


def read_tex_header(texture_rom: list[int], u16_offset: int, u16_mask: int) -> TexHeader:
    idx = u16_offset & u16_mask
    if (idx >> 1) + 2 > len(texture_rom):
        return TexHeader((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF))
    return TexHeader(
        tuple(texture_read_u16(texture_rom, idx + i) for i in range(4))
    )


def stored_to_logical(px: int, py: int) -> tuple[int, int]:
    """Invert Model 2 texture sheet fold (2048x1024 logical, 1024x2048 stored)."""
    px &= 0x7FF
    py &= 0x7FF
    if px < 1024:
        return px, py & 0x3FF
    return px + 1024, (py ^ 1024) & 0x3FF


def _unwrap_patch_offsets(values: list[float], period: int) -> None:
    """Unwrap patch-local offsets so GPU UV interpolation does not collapse wrap seams."""
    if len(values) < 2 or period <= 1:
        return
    half = period / 2.0
    for i in range(1, len(values)):
        value = values[i]
        while value - values[i - 1] > half:
            value -= period
        while value - values[i - 1] < -half:
            value += period
        values[i] = value


def _patch_offsets_from_pairs(
    pairs: list[tuple[int, int]], *, pzs: list[float] | None = None
) -> tuple[list[float], list[float]]:
    """Patch-local u/v before header base offset (MAME 13.3 fixed point, optional 1/pz)."""
    us: list[float] = []
    vs: list[float] = []
    for i, (pu, pv) in enumerate(pairs):
        pu16 = pu & 0xFFFF
        pv16 = pv & 0xFFFF
        if pzs is not None:
            # MAME model2_v.cpp: pz = 1/(pz+eps); pu *= pz; pu *= 1/8
            inv_z = 1.0 / (pzs[i] + 1e-30)
            us.append(pu16 * inv_z / 8.0)
            vs.append(pv16 * inv_z / 8.0)
        else:
            us.append(pu16 / 8.0)
            vs.append(pv16 / 8.0)
    return us, vs


def _is_billboard_header(header: TexHeader) -> bool:
    """Srally sign/billboard patches: texheader[0] bit 14 (renderer textured path)."""
    return header.valid and bool(header.words[0] & 0x4000)


def _billboard_axis_uvs(count: int, twf: float, thf: float, *, axis: str) -> tuple[list[float], list[float]]:
    """Full-patch corners when tp stream is degenerate (static ROM omits corner coords)."""
    if count == 4:
        if axis == "u":
            return [0.0, 0.0, twf, twf], [0.0, thf, thf, 0.0]
        return [0.0, twf, twf, 0.0], [0.0, 0.0, thf, thf]
    if count == 3:
        if axis == "u":
            return [0.0, 0.0, twf], [0.0, thf, 0.0]
        return [0.0, twf, 0.0], [0.0, 0.0, thf]
    return [0.0] * count, [0.0] * count


def _billboard_patch_offsets(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """Map billboard tp stream to patch-local UVs (direct rect when coords fit)."""
    twf = float(tw)
    thf = float(th)

    def fits_patch(u_list: list[float], v_list: list[float]) -> bool:
        if not u_list or not v_list:
            return False
        u_rng = max(u_list) - min(u_list)
        v_rng = max(v_list) - min(v_list)
        return (
            u_rng > 1e-3
            and v_rng > 1e-3
            and min(u_list) >= -0.5
            and min(v_list) >= -0.5
            and max(u_list) <= twf + 0.5
            and max(v_list) <= thf + 0.5
        )

    if fits_patch(us, vs):
        return us, vs

    us_norm = [u - min(us) for u in us]
    vs_norm = [v - min(vs) for v in vs]
    if fits_patch(us_norm, vs_norm):
        return us_norm, vs_norm

    return _rank_patch_offsets(us, vs, tw, th)


def _rank_patch_offsets(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """Rank-interpolate tp offsets to patch corners (preserves stream vertex order)."""
    u0, u1 = min(us), max(us)
    v0, v1 = min(vs), max(vs)
    ur = u1 - u0
    vr = v1 - v0
    twf = max(float(tw) - 1e-3, 0.0)
    thf = max(float(th) - 1e-3, 0.0)
    count = len(us)
    if ur < 1e-3 and vr < 1e-3:
        return _billboard_axis_uvs(count, twf, thf, axis="u")
    if ur < 1e-3:
        ranked_v = [(v - v0) / max(vr, 1e-6) * thf for v in vs]
        ranked_u, _ = _billboard_axis_uvs(count, twf, thf, axis="u")
        return ranked_u, ranked_v
    if vr < 1e-3:
        ranked_u = [(u - u0) / max(ur, 1e-6) * twf for u in us]
        _, ranked_v = _billboard_axis_uvs(count, twf, thf, axis="v")
        return ranked_u, ranked_v
    return (
        [(u - u0) / ur * twf for u in us],
        [(v - v0) / vr * thf for v in vs],
    )


def _billboard_degenerate_portrait_uvs(
    positions: list[tuple[float, float, float]], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """Degenerate trefoil arms: map world width→U and world Y→V (v=0 at foliage top)."""
    twf = max(float(tw) - 1e-3, 0.0)
    thf = max(float(th) - 1e-3, 0.0)
    wcoord, hcoord = _billboard_width_coords(positions)
    w0, w1 = min(wcoord), max(wcoord)
    h0, h1 = min(hcoord), max(hcoord)
    wr = max(w1 - w0, 1e-6)
    hr = max(h1 - h0, 1e-6)
    us = [(wcoord[i] - w0) / wr * twf for i in range(4)]
    vs = [(h1 - hcoord[i]) / hr * thf for i in range(4)]
    return us, vs


def _billboard_quad_degenerate(
    positions: list[tuple[float, float, float]],
) -> bool:
    """True when billboard corners collapse (trefoil arms often share an edge)."""
    if len(positions) < 4:
        return True
    wcoord, hcoord = _billboard_width_coords(positions)
    return (max(wcoord) - min(wcoord) < 1e-3) or (max(hcoord) - min(hcoord) < 1e-3)


def _expand_square_patch_u(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """Stretch collapsed rank-interp U to full patch width on square signs."""
    twf = max(float(tw) - 1e-3, 0.0)
    u_span = max(us) - min(us) if us else 0.0
    if tw <= 0 or th <= 0 or tw != th or u_span >= twf * 0.85:
        return us, vs
    u0 = min(us)
    return [(u - u0) / max(u_span, 1e-6) * twf for u in us], vs


def _billboard_mirror_u_if_high_to_low(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """
    Mirror patch U when tp rank order runs high-to-low.

    i960 @ 0x29C10 selects mirrored tp templates from workram 0x1000000 (+0x8000)
    vs 0x1004000 (geo_cluster placement feeder @ 0x23CC8). Rank-interpolated
    billboard streams preserve vertex order, so one road side maps U as tw→0.
    """
    if len(us) < 2 or tw <= 0:
        return us, vs
    twf = float(tw)
    u_span = max(us) - min(us)
    first = us[0] + (us[1] if len(us) > 1 else us[0])
    last = us[-1] + (us[-2] if len(us) > 2 else us[-1])
    high_leading = us[0] >= twf * 0.5 and min(us) <= twf * 0.15
    high_both_ends = (
        us[0] >= twf * 0.85
        and us[-1] >= twf * 0.85
        and min(us) <= twf * 0.1
    )
    if high_both_ends:
        return [twf - u for u in us], vs
    if high_leading and (first > last + 1e-3 or us[-1] >= twf * 0.85):
        return [twf - u for u in us], vs
    if u_span >= twf * 0.85 and first > last + 1e-3:
        return [twf - u for u in us], vs
    return us, vs


def _billboard_diagonal_u_flip(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """
    Mirror U when rank mapping assigns patch corners diagonally (1,0,0,1).

    Opposite road-side placements permute tp stream vertex order (geo feeder
    orientation @ 0x23CC8 +0x51); rank-interpolation then maps U high at vtx0/3
    instead of vtx1/2. Equivalent to the 0x1000000 vs 0x1004000 tp template flip
    @ 0x29C10 when high-to-low detection alone does not fire.
    """
    if len(us) < 4 or tw <= 0:
        return us, vs
    twf = float(tw)
    lu = [u / twf for u in us[:4]]
    if lu[0] > 0.5 and lu[1] < 0.5 and lu[2] < 0.5 and lu[3] > 0.5:
        return [twf - u for u in us], vs
    return us, vs


def _billboard_diagonal_v_flip(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """
    Mirror V when rank mapping assigns patch corners diagonally on portrait billboards.

    Patch pixels use v=0 at the art top; OBJ patch-local V is flipped in export
    (``atlas_uv_to_patch_local``), so the reversed tree pattern appears as pixel
    (0,1,1,0) — not atlas-local (1,0,0,1). Landscape signs (tw >= th) are skipped.
    """
    if len(vs) < 4 or th <= 0 or tw <= 0 or tw >= th:
        return us, vs
    thf = float(th)
    lv = [v / thf for v in vs[:4]]
    if lv[0] < 0.5 and lv[1] > 0.5 and lv[2] > 0.5 and lv[3] < 0.5:
        return us, [thf - v for v in vs]
    return us, vs


def _billboard_orient_patch_uvs(
    us: list[float], vs: list[float], tw: int, th: int
) -> tuple[list[float], list[float]]:
    us, vs = _billboard_mirror_u_if_high_to_low(us, vs, tw, th)
    us, vs = _billboard_diagonal_u_flip(us, vs, tw, th)
    # V diagonal flip removed: trefoil tree arms share placement yaw but differ in
    # tp vertex order; flipping V mirrored one arm while the other two were correct.
    return us, vs


def _billboard_width_coords(
    positions: list[tuple[float, float, float]],
) -> tuple[list[float], list[float]]:
    """Per-vertex width (quad horizontal axis) and height (Y) for a billboard."""
    pts = positions[:4]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    zs = [p[2] for p in pts]
    best_span = 0.0
    wcoord = xs
    for i in range(4):
        for j in range(i + 1, 4):
            dx = xs[j] - xs[i]
            dz = zs[j] - zs[i]
            span = (dx * dx + dz * dz) ** 0.5
            if span > best_span:
                best_span = span
                wcoord = xs if abs(dx) >= abs(dz) else zs
    if best_span < 1e-6:
        wcoord = xs if max(xs) - min(xs) >= max(zs) - min(zs) else zs
    return wcoord, ys


def _billboard_geometry_rect_uvs(
    positions: list[tuple[float, float, float]], tw: int, th: int
) -> tuple[list[float], list[float]]:
    """
    Assign full-patch UV corners from quad vertex positions.

    tp streams preserve vertex order from placement orientation (geo feeder
    @ 0x23CC8); rank interpolation can diagonally cross corners and show half
    the art twice. Geometry width/height axes match the exported mesh quad.
    """
    twf = max(float(tw) - 1e-3, 0.0)
    thf = max(float(th) - 1e-3, 0.0)
    wcoord, hcoord = _billboard_width_coords(positions)
    w0, w1 = min(wcoord), max(wcoord)
    h0, h1 = min(hcoord), max(hcoord)
    wr = max(w1 - w0, 1e-6)
    hr = max(h1 - h0, 1e-6)
    us = [(wcoord[i] - w0) / wr * twf for i in range(4)]
    # Trefoil tree arms share a patch but tp vertex order can run high→low on the
    # chosen width axis; canonicalize so u=0 anchors vtx0's side (matches MAME).
    if wcoord[0] > wcoord[2] + 1e-6:
        us = [twf - u for u in us]
    # Patch v=0 is the top of the art (MAME / model2rd); map max world Y → v=0.
    if th > tw:
        vs = [(h1 - hcoord[i]) / hr * thf for i in range(4)]
        lo = min(range(4), key=lambda i: hcoord[i])
        hi = max(range(4), key=lambda i: hcoord[i])
        if vs[lo] < vs[hi]:
            vs = [thf - v for v in vs]
    else:
        vs = [(hcoord[i] - h0) / hr * thf for i in range(4)]
    return us, vs


def _billboard_mirror_uv_from_geometry(
    us: list[float],
    vs: list[float],
    tw: int,
    th: int,
    positions: list[tuple[float, float, float]],
) -> tuple[list[float], list[float]]:
    """Flip patch U/V when tp rank order disagrees with quad width/height."""
    if len(positions) < 4 or len(us) < 4 or tw <= 0 or th <= 0:
        return us, vs
    twf = float(tw)
    thf = float(th)
    wcoord, hcoord = _billboard_width_coords(positions)
    wmid = (min(wcoord) + max(wcoord)) * 0.5
    low_u = high_u = low_n = high_n = 0.0
    for i in range(4):
        if wcoord[i] <= wmid:
            low_u += us[i]
            low_n += 1.0
        else:
            high_u += us[i]
            high_n += 1.0
    if low_n > 0 and high_n > 0:
        low_u /= low_n
        high_u /= high_n
        if low_u > high_u + 1e-3:
            us = [twf - u for u in us]
    return us, vs


def _billboard_patch_uvs_from_pairs(
    pairs: list[tuple[int, int]],
    header: TexHeader,
    *,
    pzs: list[float] | None = None,
    positions: list[tuple[float, float, float]] | None = None,
) -> tuple[list[float], list[float]]:
    tw, th = header.texwidth, header.texheight
    us, vs = mame_patch_pixels_from_pairs(pairs, pzs=pzs)
    us, vs = _billboard_patch_offsets(us, vs, tw, th)
    twf = max(float(tw) - 1e-3, 0.0)
    thf = max(float(th) - 1e-3, 0.0)
    u_span = max(us) - min(us) if us else 0.0
    v_span = max(vs) - min(vs) if vs else 0.0
    full_patch = u_span >= twf * 0.85 and v_span >= thf * 0.85
    portrait = th > tw
    square = tw == th
    if positions and len(positions) >= 4 and portrait:
        return _billboard_geometry_rect_uvs(positions, tw, th)
    if positions and len(positions) >= 4 and square and tw > 64:
        return _billboard_geometry_rect_uvs(positions, tw, th)
    if positions and len(positions) >= 4 and full_patch and not square:
        us, vs = _billboard_geometry_rect_uvs(positions, tw, th)
        return us, vs
    if square:
        us, vs = _expand_square_patch_u(us, vs, tw, th)
    us, vs = _billboard_orient_patch_uvs(us, vs, tw, th)
    return us, vs


def _logical_xy_from_patch_pixels(
    us: list[float],
    vs: list[float],
    header: TexHeader,
    *,
    base_x: int,
    base_y: int,
    tw: int,
    th: int,
) -> list[tuple[float, float]]:
    """Patch-local pixels → logical atlas xy, applying model2rd.ipp mirror."""
    coords: list[tuple[float, float]] = []
    for u, v in zip(us, vs):
        u_fixed, v_fixed = mame_mirror_uv_fixed(
            int(u * 256.0),
            int(v * 256.0),
            tw=tw,
            th=th,
            mirror_x=header.mirror_x,
            mirror_y=header.mirror_y,
        )
        lx = base_x + u_fixed / 256.0
        ly = base_y + v_fixed / 256.0
        coords.append(
            (
                float(min(max(lx, 0.0), LOGICAL_SHEET_W - 1e-6)),
                float(min(max(ly, 0.0), LOGICAL_SHEET_H - 1e-6)),
            )
        )
    return coords


def _logical_xy_from_pairs(
    pairs: list[tuple[int, int]],
    header: TexHeader | None,
    *,
    pzs: list[float] | None = None,
    billboard_expand: bool = False,
    positions: list[tuple[float, float, float]] | None = None,
) -> list[tuple[float, float]]:
    if header is not None and header.valid:
        base_x = (header.texx - 2048) & 2047
        base_y = (header.texy - 1024) & 1023
        tw, th = header.texwidth, header.texheight
        if billboard_expand and tw > 0 and th > 0:
            us, vs = _billboard_patch_uvs_from_pairs(
                pairs, header, pzs=pzs, positions=positions
            )
        else:
            us, vs = mame_patch_pixels_from_pairs(pairs, pzs=pzs)
            unwrap_limit = min(tw // 2, 64)
            vrap_limit = min(th // 2, 64)
            u_span = max(us) - min(us) if len(us) >= 2 else 0.0
            v_span = max(vs) - min(vs) if len(vs) >= 2 else 0.0
            if header.tex_wrap_x and len(us) >= 2:
                _unwrap_patch_offsets(us, tw)
            elif u_span > unwrap_limit or (us and max(us) >= tw):
                u0 = min(us)
                us = [u - u0 for u in us]
            elif len(us) >= 2:
                _unwrap_patch_offsets(us, tw)
            if header.tex_wrap_y and len(vs) >= 2:
                _unwrap_patch_offsets(vs, th)
            elif v_span > vrap_limit or (vs and max(vs) >= th):
                v0 = min(vs)
                vs = [v - v0 for v in vs]
            elif len(vs) >= 2:
                _unwrap_patch_offsets(vs, th)
            if tw == th and 0 < tw <= 64:
                us, vs = _expand_square_patch_u(us, vs, tw, th)
                us, vs = _billboard_orient_patch_uvs(us, vs, tw, th)
        return _logical_xy_from_patch_pixels(
            us, vs, header, base_x=base_x, base_y=base_y, tw=tw, th=th
        )

    coords = []
    for pu_word, pv_word in pairs:
        pu = pu_word & 0xFFFF
        pv = pv_word & 0xFFFF
        lx, ly = stored_to_logical(pu & 0x7FF, pv & 0x3FF)
        coords.append((float(lx & (LOGICAL_SHEET_W - 1)), float(ly & (LOGICAL_SHEET_H - 1))))
    return coords


def _xy_to_uv(lx: float, ly: float) -> tuple[float, float]:
    u = lx / LOGICAL_SHEET_W
    v = 1.0 - (ly / LOGICAL_SHEET_H)
    return u, v


def patch_origin_from_header(header: TexHeader) -> tuple[int, int, int, int]:
    """Logical atlas origin + patch size from a resolved texheader."""
    base_x = (header.texx - 2048) & 2047
    base_y = (header.texy - 1024) & 1023
    return base_x, base_y, header.texwidth, header.texheight


def atlas_uv_to_patch_local(
    u: float,
    v: float,
    *,
    patch_x: int,
    patch_y: int,
    patch_w: int,
    patch_h: int,
) -> tuple[float, float]:
    """Convert full-sheet normalized UVs to patch-local 0..1 (for cropped map_Kd)."""
    if patch_w <= 0 or patch_h <= 0:
        return u, v
    lx = u * LOGICAL_SHEET_W
    ly = (1.0 - v) * LOGICAL_SHEET_H
    lu = (lx - patch_x) / float(patch_w)
    lv = 1.0 - (ly - patch_y) / float(patch_h)
    return (max(0.0, min(1.0, lu)), max(0.0, min(1.0, lv)))


def atlas_uvs_from_texel_pairs(
    pairs: list[tuple[int, int]],
    header: TexHeader | None,
    *,
    pzs: list[float] | None = None,
    billboard_expand: bool = False,
    positions: list[tuple[float, float, float]] | None = None,
) -> list[tuple[float, float]]:
    """Map per-vertex texture point words to normalized UVs on a logical 2048x1024 sheet."""
    return [
        _xy_to_uv(lx, ly)
        for lx, ly in _logical_xy_from_pairs(
            pairs,
            header,
            pzs=pzs,
            billboard_expand=billboard_expand,
            positions=positions,
        )
    ]


def atlas_uv_from_texels(pu_word: int, pv_word: int, header: TexHeader | None) -> tuple[float, float]:
    """Map one texture point word pair to normalized UV on a logical 2048x1024 sheet."""
    return atlas_uvs_from_texel_pairs([(pu_word, pv_word)], header)[0]


@dataclass
class TexturedPrimitive:
    indices: tuple[int, ...]
    attr: int
    uvs: tuple[tuple[float, float], ...]
    sheet_index: int
    colorbase: int = 0
    lumabase: int = 0
    renderer: int = 2
    translucent: bool = False
    checker: bool = False
    patch_x: int = 0
    patch_y: int = 0
    patch_w: int = 0
    patch_h: int = 0
    texel_map_id: str = ""


@dataclass
class TextureState:
    texture_rom: list[int]
    mask: int
    tpa: int
    tha: int

    def read_header(self, attr: int) -> TexHeader:
        off = texture_addr_mask(self.tha, self.mask)
        header = read_tex_header(self.texture_rom, off, self.mask)
        tho = header_tho_words(attr)
        self.tha = texture_addr_mask(self.tha + tho * 4, self.mask)
        return header

    def consume_vertices(self, attr: int, count: int) -> tuple[TexHeader, list[tuple[int, int]]]:
        pairs: list[tuple[int, int]] = []
        for _ in range(count):
            idx = texture_addr_mask(self.tpa, self.mask)
            if (idx >> 1) + 1 >= len(self.texture_rom):
                pairs.append((0, 0))
                break
            pv = texture_read_u16(self.texture_rom, idx)
            pu = texture_read_u16(self.texture_rom, idx + 1)
            pairs.append((pu, pv))
            self.tpa = texture_addr_mask(self.tpa + 2, self.mask)
        header = self.read_header(attr)
        return header, pairs


def _patch_corner_uvs(header: TexHeader) -> list[tuple[float, float]]:
    twf = max(float(header.texwidth) - 1e-3, 0.0)
    thf = max(float(header.texheight) - 1e-3, 0.0)
    base_x = (header.texx - 2048) & 2047
    base_y = (header.texy - 1024) & 1023
    corners = [(0.0, 0.0), (twf, 0.0), (twf, thf), (0.0, thf)]
    return [
        _xy_to_uv(min(base_x + cu, LOGICAL_SHEET_W - 1e-6), min(base_y + cv, LOGICAL_SHEET_H - 1e-6))
        for cu, cv in corners
    ]


def _complete_cutout_triangle_quad(
    idx: tuple[int, ...],
    vertices: list[tuple[float, float, float]],
    pairs: list[tuple[int, int]],
    header: TexHeader,
) -> tuple[tuple[int, ...], list[tuple[float, float]], int] | None:
    """Turn a 3-vert cutout tri into a quad for OBJ export (MAME renders one triangle)."""
    if len(idx) != 3 or not header.valid:
        return None
    tw, th = header.texwidth, header.texheight
    if tw <= 0 or th <= 0:
        return None
    us, vs = _billboard_patch_offsets(*mame_patch_pixels_from_pairs(pairs), tw, th)
    corners = [(0.0, 0.0), (float(tw), 0.0), (float(tw), float(th)), (0.0, float(th))]
    used: set[int] = set()
    for u, v in zip(us, vs):
        best = min(range(4), key=lambda i: (u - corners[i][0]) ** 2 + (v - corners[i][1]) ** 2)
        used.add(best)
    if len(used) >= 4:
        return None
    corner_uvs = _patch_corner_uvs(header)
    missing = next(i for i in range(4) if i not in used)
    i0, i1, i2 = idx
    v0 = vertices[i0]
    v1 = vertices[i1]
    v2 = vertices[i2]
    # P1(n) = P0(n) + P1(n-1) - P0(n-1) in MAME strip order (idx = P1_prev, P0_prev, P0).
    v3 = (v2[0] + v0[0] - v1[0], v2[1] + v0[1] - v1[1], v2[2] + v0[2] - v1[2])
    i3 = len(vertices)
    vertices.append(v3)
    positions = [v0, v1, v2, v3]
    uvs = list(
        atlas_uvs_from_texel_pairs(
            pairs, header, billboard_expand=True, positions=positions
        )
    )
    uvs.append(corner_uvs[missing])
    return (i0, i1, i2, i3), uvs, i3


class TexturedMeshCollector(MeshCollector):
    """MeshCollector that also records UVs from placement tpa/tha streams."""

    def __init__(self, *, texture: TextureState | None = None) -> None:
        super().__init__()
        self.texture = texture
        self.textured_primitives: list[TexturedPrimitive] = []
        self.audit_records: list[dict[str, object]] | None = None

    def add_primitive(
        self,
        attr: int,
        indices: Iterable[int],
        *,
        normal: tuple[float, float, float] | None = None,
        front: bool = True,
    ) -> None:
        idx = tuple(indices)
        count = 4 if attr & 1 else 3
        header: TexHeader | None = None
        pairs: list[tuple[int, int]] = []
        if self.texture is not None:
            # MAME model2_3d_process_polygon reads tp/th before check_culling(), so
            # culled polys (link type 0, back faces, z clip) still advance tpa/tha.
            header, pairs = self.texture.consume_vertices(attr, count)
        if not mame_polygon_exportable(attr):
            return
        super().add_primitive(attr, idx, normal=normal, front=front)
        if self.texture is None or header is None:
            return
        # Static export: skip 1/pz on billboards/cutouts — model-space pz != rasterizer depth.
        uv_header = resolve_uv_header(attr, header)
        cutout = polygon_translucent(attr, header)
        billboard = cutout or _is_billboard_header(uv_header)
        completed = None
        pzs: list[float] | None = None
        if cutout and count == 3 and billboard:
            completed = _complete_cutout_triangle_quad(idx, self.vertices, pairs, uv_header)
        if completed is not None:
            quad_idx, uvs, _ = completed
            idx = quad_idx
            count = 4
        else:
            pzs = None
            if not billboard:
                skip_pz_rank = (
                    uv_header.valid
                    and uv_header.texwidth == uv_header.texheight
                    and 0 < uv_header.texwidth <= 64
                )
                if not skip_pz_rank:
                    pzs_raw = [self.vertices[i][2] for i in idx]
                    if pzs_raw and all(p > 1e-6 for p in pzs_raw):
                        pzs = pzs_raw
            positions = (
                [self.vertices[i] for i in idx]
                if billboard and count >= 4
                else None
            )
            uvs = atlas_uvs_from_texel_pairs(
                pairs,
                uv_header,
                pzs=pzs,
                billboard_expand=billboard,
                positions=positions,
            )
        if len(uvs) < count:
            uvs = list(uvs) + [(0.0, 0.0)] * (count - len(uvs))
        patch_x = patch_y = patch_w = patch_h = 0
        if uv_header.valid and uv_header.texwidth > 0 and uv_header.texheight > 0:
            patch_x, patch_y, patch_w, patch_h = patch_origin_from_header(uv_header)
        colorbase, lumabase, palette_source = palette_binding_from_texheader(attr, header)
        sheet_index = header.sheet_index if header.valid else 0
        cutout = polygon_translucent(attr, header)
        checker = header.checker if header.valid else False
        prim = TexturedPrimitive(
            indices=idx,
            attr=attr,
            uvs=tuple(uvs[:count]),
            sheet_index=sheet_index,
            colorbase=colorbase,
            lumabase=lumabase,
            renderer=polygon_renderer(attr, header),
            translucent=cutout,
            checker=checker,
            patch_x=patch_x,
            patch_y=patch_y,
            patch_w=patch_w,
            patch_h=patch_h,
            texel_map_id=texel_map_id(
                sheet_index,
                patch_x,
                patch_y,
                patch_w,
                patch_h,
                colorbase,
                lumabase,
                cutout=cutout or checker,
                checker=checker,
            ),
        )
        self.textured_primitives.append(prim)
        if self.audit_records is not None:
            self.audit_records.append(
                {
                    "attr": attr,
                    "vert_count": count,
                    "header_raw": list(header.words),
                    "header_resolved": list(uv_header.words),
                    "tp_pairs": [list(p) for p in pairs],
                    "colorbase": colorbase,
                    "lumabase": lumabase,
                    "texel_map_id": prim.texel_map_id,
                    "palette_source": palette_source,
                    "palette_from_attr": palette_source == "attr",
                    "lumabase_heuristic": False,
                    "billboard_path": billboard,
                    "cutout_completed_quad": completed is not None,
                    "used_perspective_pz": pzs is not None,
                    "sheet_index": header.sheet_index if header.valid else 0,
                    "patch_x": patch_x,
                    "patch_y": patch_y,
                    "patch_w": patch_w,
                    "patch_h": patch_h,
                    "uvs": [list(uv) for uv in uvs[:count]],
                }
            )


def parse_textured_placement(
    polygon_rom: list[int],
    texture_rom: list[int],
    *,
    matrix: list[float],
    rom_offset: int,
    obc: int,
    tpa: int,
    tha: int,
    texture_mask: int | None = None,
    collect_audit: bool = False,
) -> TexturedMeshCollector | None:
    mask = texture_u16_mask(len(texture_rom)) if texture_mask is None else texture_mask
    geo = GeoState(matrix=list(matrix))
    texture = TextureState(
        texture_rom=texture_rom,
        mask=mask,
        tpa=texture_addr_mask(tpa, mask),
        tha=texture_addr_mask(tha, mask),
    )
    collector = TexturedMeshCollector(texture=texture)
    if collect_audit:
        collector.audit_records = []
    count = obc if obc else 0xFFFFF
    try:
        geo_parse_np_ns_collect(geo, polygon_rom, rom_offset, count, collector)
    except GeoParseError:
        return None
    if len(collector.vertices) < 8:
        return None
    peak = max(max(abs(v[0]), abs(v[1]), abs(v[2])) for v in collector.vertices)
    if peak < 2.0 or peak > 40_000:
        return None
    return collector
