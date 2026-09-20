"""Export placement/scene geometry with texture UVs from tpa/tha streams."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from tools.model2_catalog import parse_placement_stream
from tools.model2_scenes import placement_segments_from_draw_layers, parse_draw_script, slice_placements
from tools.model2_texture import TexturedMeshCollector, parse_textured_placement, texture_u16_mask
from tools.obj_export import write_mtl, write_textured_obj
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


def _merge_collectors(collectors: list[TexturedMeshCollector]) -> tuple[list, list]:
    vertices: list[tuple[float, float, float]] = []
    primitives = []
    for col in collectors:
        base = len(vertices)
        vertices.extend(col.vertices)
        for prim in col.textured_primitives:
            primitives.append(
                type(prim)(
                    indices=tuple(base + i for i in prim.indices),
                    attr=prim.attr,
                    uvs=prim.uvs,
                    sheet_index=prim.sheet_index,
                )
            )
    return vertices, primitives


def _texture_rel_paths(out_dir: Path, out_root: Path) -> dict[str, str]:
    tex0 = out_root / "textures" / "sheet0_logical_2048x1024.png"
    tex1 = out_root / "textures" / "sheet1_logical_2048x1024.png"
    return {
        "sheet0": Path(os_relpath(tex0, out_dir)),
        "sheet1": Path(os_relpath(tex1, out_dir)),
    }


def os_relpath(target: Path, start: Path) -> str:
    try:
        return Path(target).resolve().relative_to(start.resolve()).as_posix()
    except ValueError:
        return Path("..") / Path(target).name


def extract_textured_meshes(
    rom_dir: Path,
    out_dir: Path,
    *,
    out_root: Path | None = None,
    max_faces_per_file: int = 400_000,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_root = out_root or out_dir.parent

    main_data = list(
        struct.unpack(
            f"<{len(load32_word_region(rom_dir, SRALLY_DATA_ROMS['main_data'])) // 4}I",
            load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]),
        )
    )
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = list(struct.unpack(f"<{len(poly_raw) // 4}I", poly_raw))
    tex_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    texture_rom = list(struct.unpack(f"<{len(tex_raw) // 4}I", tex_raw))
    poly_mask = len(polygon_rom) - 1
    tex_mask = texture_u16_mask(len(texture_rom))

    placements = parse_placement_stream(
        main_data, polygon_rom, polygon_rom_mask=poly_mask
    )
    draw_layers = parse_draw_script(main_data)
    segments = placement_segments_from_draw_layers(
        draw_layers, max_placement_index=len(placements)
    )

    tex_rels = _texture_rel_paths(out_dir, out_root)
    mtl_path = out_dir / "segamod2_textured.mtl"
    write_mtl(
        mtl_path,
        {
            "sheet0": tex_rels["sheet0"],
            "sheet1": tex_rels["sheet1"],
        },
    )

    written: list[Path] = [mtl_path]
    catalog: list[dict[str, object]] = []

    # Vehicle-scale banks: first placements in stream are often car parts.
    vehicle_collectors: list[TexturedMeshCollector] = []
    for rec in placements[:48]:
        col = parse_textured_placement(
            polygon_rom,
            texture_rom,
            matrix=rec.matrix,
            rom_offset=rec.rom_offset,
            obc=rec.obc,
            tpa=rec.tpa,
            tha=rec.tha,
            texture_mask=tex_mask,
        )
        if col and col.textured_primitives:
            vehicle_collectors.append(col)

    if vehicle_collectors:
        verts, prims = _merge_collectors(vehicle_collectors)
        if len(prims) <= max_faces_per_file:
            obj_path = out_dir / "vehicles_textured.obj"
            write_textured_obj(
                obj_path,
                verts,
                prims,
                mtl_name="sheet0",
                material_by_sheet={0: "sheet0", 1: "sheet1"},
            )
            written.append(obj_path)
            catalog.append(
                {
                    "file": obj_path.name,
                    "kind": "vehicles",
                    "placements": len(vehicle_collectors),
                    "vertices": len(verts),
                    "faces": len(prims),
                }
            )

    seg_dir = out_dir / "placement_segments"
    seg_dir.mkdir(parents=True, exist_ok=True)
    for si, (start, end, layer_idx) in enumerate(segments):
        batch = slice_placements(placements, start, end)
        if not batch:
            continue
        collectors: list[TexturedMeshCollector] = []
        for rec in batch:
            col = parse_textured_placement(
                polygon_rom,
                texture_rom,
                matrix=rec.matrix,
                rom_offset=rec.rom_offset,
                obc=rec.obc,
                tpa=rec.tpa,
                tha=rec.tha,
                texture_mask=tex_mask,
            )
            if col and col.textured_primitives:
                collectors.append(col)
        if not collectors:
            continue
        verts, prims = _merge_collectors(collectors)
        if len(prims) > max_faces_per_file:
            prims = prims[:max_faces_per_file]
        obj_path = seg_dir / f"segment_{si:02d}_textured_{start:03d}_{end:03d}.obj"
        write_textured_obj(
            obj_path,
            verts,
            prims,
            mtl_name="sheet0",
            material_by_sheet={0: "sheet0", 1: "sheet1"},
        )
        written.append(obj_path)
        catalog.append(
            {
                "file": obj_path.relative_to(out_dir).as_posix(),
                "kind": "placement_segment",
                "segment_index": si,
                "placement_range": [start, end],
                "draw_layer_index": layer_idx,
                "placements": len(collectors),
                "vertices": len(verts),
                "faces": len(prims),
            }
        )

    meta = out_dir / "textured_meshes_meta.json"
    meta.write_text(
        json.dumps(
            {
                "notes": [
                    "UVs from placement tpa/tha streams (MAME model2_3d_process_polygon order).",
                    "ROM texture headers are often 0xffffffff; atlas position falls back to pu/pv low bits.",
                    "Grayscale sheet PNGs — palette/colorbase from runtime RAM not applied yet.",
                ],
                "entries": catalog,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(meta)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export textured placement meshes.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/textured_meshes"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_textured_meshes(rom_dir, args.out)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
