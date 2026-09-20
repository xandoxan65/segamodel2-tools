#!/usr/bin/env python3
"""Bake viewer palette_cache PNGs from a decomp_lift palette dump.

Preferred entry: lifted C harness (single path):

  cd decomp && make lift-viewer
  # ./build/lift/decomp_lift --viewer track --course desert --out ../out

This module is invoked by ``track_viewer_export.c`` until mesh/palette bake is ported to C.
Uses tier-validated lift palette only (``lift_cgm_apply``) — not ``palette_re`` ROM DEF.

Manual usage:
  cd decomp && ./build/lift/decomp_lift --viewer track --course desert --palette-only \\
      --palette-dump build/lift/palette_state
  PYTHONPATH=. python3 -m tools.decomp.lift_palette_export \\
      --dump decomp/build/lift/palette_state --course desert \\
      -o out/textures/palette_cache/desert --refresh-track-obj
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.decomp.lift_cgm_apply import apply_cgm_to_lift_state
from tools.decomp.lift_palette_state import load_lift_palette_state
from tools.extract.textures import load_sheet_banks_from_main_data
from tools.i960_tracks import COURSE_TRACK_EXPORTS, collect_course_textured_mesh
from tools.model2_catalog import parse_placement_stream
from tools.model2_palette import PALRAM_COLORBASE_WORD
from tools.model2_texel_map import texel_map_key
from tools.model2_texture import texture_u16_mask
from tools.obj_export import build_palette_material_maps, palette_material_name, write_textured_obj
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


def _words_from_bytes(data: bytes) -> list[int]:
    n = len(data) // 4
    import struct

    return list(struct.unpack(f"<{n}I", data[: n * 4]))


def export_palette_cache_for_course(
    *,
    dump_dir: Path,
    out_dir: Path,
    rom_dir: Path,
    course_id: str,
    scenes_dir: Path | None = None,
    refresh_track_obj: bool = False,
) -> dict:
    state, manifest = load_lift_palette_state(dump_dir)
    main_data_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    cgm_summary = apply_cgm_to_lift_state(state, main_data_raw, course_id=course_id)
    main_data = _words_from_bytes(main_data_raw)
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = _words_from_bytes(poly_raw)
    tex_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    texture_rom = _words_from_bytes(tex_raw)
    texture_sheets = load_sheet_banks_from_main_data(main_data_raw)
    tex_mask = texture_u16_mask(len(texture_rom))

    spec = COURSE_TRACK_EXPORTS.get(course_id)
    if spec is None:
        raise SystemExit(f"unknown course: {course_id}")

    placements = parse_placement_stream(
        main_data,
        polygon_rom,
        polygon_rom_mask=len(polygon_rom) - 1,
    )
    ranges = [(int(a), int(b)) for a, b in spec["placement_ranges"]]
    tex_verts, tex_prims, _ = collect_course_textured_mesh(
        placements,
        polygon_rom,
        texture_rom,
        ranges,
        exclude_ambient_env=bool(spec.get("exclude_ambient_env")),
        texture_mask=tex_mask,
    )
    if not tex_prims:
        raise SystemExit(f"no textured primitives for course {course_id}")

    scenes_root = (scenes_dir or Path("out/scenes")).resolve()
    tracks_dir = scenes_root / "tracks"
    track_obj = tracks_dir / f"track_{course_id}_textured.obj"
    out_root = scenes_root.parent

    out_dir.mkdir(parents=True, exist_ok=True)

    materials = build_palette_material_maps(
        tex_prims,
        palette=state,
        texture_sheets=texture_sheets,
        cache_dir=out_dir,
        obj_path=track_obj,
        out_root=out_root,
    )

    required_mats = {
        palette_material_name(
            prim.sheet_index,
            prim.colorbase,
            prim.lumabase,
            translucent=bool(prim.translucent or prim.checker),
            checker=prim.checker,
            patch_x=prim.patch_x,
            patch_y=prim.patch_y,
            patch_w=prim.patch_w,
            patch_h=prim.patch_h,
        )
        for prim in tex_prims
        if len(prim.indices) >= 3 and (prim.renderer & 2)
    }
    missing_pngs = sorted(required_mats - set(materials))
    texel_map_count = len({texel_map_key(p) for p in tex_prims if len(p.indices) >= 3 and (p.renderer & 2)})

    track_obj_written = None
    if refresh_track_obj:
        tracks_dir.mkdir(parents=True, exist_ok=True)
        write_textured_obj(
            track_obj,
            tex_verts,
            tex_prims,
            mtl_name="sheet0",
            material_by_sheet={0: "sheet0", 1: "sheet1"},
            palette=state,
            texture_sheets=texture_sheets,
            palette_cache_dir=out_dir,
            out_root=out_root,
            index_sheets_only=False,
        )
        track_obj_written = str(track_obj)

    colorbase_slots = sum(
        1 for slot in range(0x400) if state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
    )
    colorxlat_nz = sum(1 for w in state.colorxlat if w)
    return {
        "course": course_id,
        "dump_dir": str(dump_dir),
        "manifest": manifest,
        "palette_cache_dir": str(out_dir),
        "materials_baked": len(materials),
        "texel_maps_required": len(required_mats),
        "texel_maps_unique": texel_map_count,
        "missing_material_pngs": missing_pngs[:16],
        "colorbase_slots": colorbase_slots,
        "colorxlat_nonzero_words": colorxlat_nz,
        "colorxlat_source": cgm_summary.get("colorxlat_source"),
        "lumaram_source": cgm_summary.get("lumaram_source"),
        "lumaram_nonzero_bytes": cgm_summary.get("nonzero_bytes"),
        "track_obj": track_obj_written,
        "textured_primitives": len(tex_prims),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", type=Path, required=True, help="I960_PALETTE_DUMP directory")
    ap.add_argument("--course", default="desert", help="course id (default desert)")
    ap.add_argument("-o", "--out", type=Path, required=True, help="palette_cache output directory")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument(
        "--refresh-track-obj",
        action="store_true",
        help="re-export track OBJ/MTL using the same lift-validated palette state",
    )
    ap.add_argument("--scenes-dir", type=Path, default=Path("out/scenes"))
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)

    summary = export_palette_cache_for_course(
        dump_dir=args.dump.resolve(),
        out_dir=args.out.resolve(),
        rom_dir=rom_dir,
        course_id=args.course,
        scenes_dir=args.scenes_dir,
        refresh_track_obj=args.refresh_track_obj,
    )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(
        f"lift_palette_export: {summary['materials_baked']} PNGs → {args.out} "
        f"(colorxlat={summary.get('colorxlat_source', '?')}, "
        f"lumaram={summary.get('lumaram_source', '?')}, "
        f"colorbase_slots={summary['colorbase_slots']}, "
        f"colorxlat_nz={summary['colorxlat_nonzero_words']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
