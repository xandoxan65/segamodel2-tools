"""Code-identified texel maps: stable ids for texheader patch + palette bindings."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.model2_texture import TexturedPrimitive


def texel_map_id(
    sheet_index: int,
    x: int,
    y: int,
    w: int,
    h: int,
    colorbase: int,
    lumabase: int,
    *,
    cutout: bool,
    checker: bool,
) -> str:
    """Stable id for one code-defined texel map (matches ``catalog/atlas_regions.json``)."""
    suffix = ""
    if cutout:
        suffix += "_cut"
    if checker:
        suffix += "_chk"
    return (
        f"tex_s{sheet_index}_x{x}_y{y}_w{w}_h{h}"
        f"_cb{colorbase}_lb{lumabase}{suffix}"
    )


def cutout_flags_for_primitive(prim: TexturedPrimitive) -> tuple[bool, bool]:
    cutout = bool(prim.translucent or prim.checker)
    return cutout, bool(prim.checker)


def texel_map_id_for_primitive(prim: TexturedPrimitive) -> str:
    cutout, checker = cutout_flags_for_primitive(prim)
    return texel_map_id(
        prim.sheet_index,
        prim.patch_x,
        prim.patch_y,
        prim.patch_w,
        prim.patch_h,
        prim.colorbase,
        prim.lumabase,
        cutout=cutout,
        checker=checker,
    )


def texel_map_key(prim: TexturedPrimitive) -> tuple[int, int, int, int, int, int, int, bool, bool]:
    """Hashable binding key for deduplicating texel maps in export/cache."""
    cutout, checker = cutout_flags_for_primitive(prim)
    return (
        prim.sheet_index,
        prim.patch_x,
        prim.patch_y,
        prim.patch_w,
        prim.patch_h,
        prim.colorbase,
        prim.lumabase,
        cutout,
        checker,
    )
