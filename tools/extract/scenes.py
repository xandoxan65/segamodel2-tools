"""Execute Model 2 display lists and export world-space scene meshes."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from tools.model2_geo_dl import (
    DisplayListResult,
    GeoDisplayContext,
    GeoDisplayListRunner,
    discover_display_list_starts,
    try_run_display_list,
)
from tools.i960_memory import CATALOG_VADDR, PLACEMENT_STREAM_VADDR
from tools.i960_tracks import (
    COURSE_TRACK_EXPORTS,
    COURSE_TRACK_SUPPLEMENTS,
    UI_COURSE_ORDER,
    build_course_track_catalog,
    build_track_report,
    classify_placement_segment,
    collect_course_textured_mesh,
    collect_course_track_mesh,
    collect_course_track_point_cloud,
    load_workram_captures,
)
from tools.model2_palette import load_palette_from_main_data
from tools.model2_texture import texture_u16_mask
from tools.obj_export import texture_sheet_materials, write_mtl, write_obj, write_textured_obj
from tools.model2_placements import is_ambient_env_ring_placement
from tools.model2_catalog import parse_catalog, parse_placement_stream
from tools.model2_scenes import (
    CPU_SCENE_ANCHORS,
    DRAW_SCRIPT_VADDR,
    parse_draw_script,
    placement_segments_from_draw_layers,
    slice_placements,
)
from tools.model2_placements import discover_placements, group_placements
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

_DL_START_CMDS = frozenset({0x00, 0x01, 0x02, 0x03, 0x05, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x11, 0x12, 0x13, 0x15, 0x17})


def _load_maincpu(rom_dir: Path) -> list[int]:
    raw = load32_word_region(rom_dir, [("epr-17888b.12", "epr-17889b.13")])
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def _plausible_list_start(words: list[int], offset: int) -> bool:
    if offset < 0 or offset >= len(words):
        return False
    w = words[offset]
    if w & 0x8000_0000:
        return False
    cmd = (w >> 23) & 0x1F
    return cmd in _DL_START_CMDS and (w & 0x007F_FFFF) == 0


def _write_obj(
    path: Path,
    vertices: list[tuple[float, float, float]],
    faces: list[tuple[int, ...]] | None = None,
    *,
    face_normals: list[tuple[float, float, float]] | None = None,
) -> None:
    write_obj(path, vertices, faces if faces else None, face_normals=face_normals)


def _run_bufferram_display_lists(
    runner: GeoDisplayListRunner,
    words: list[int],
    *,
    source: str,
) -> list[DisplayListResult]:
    """Run geo_parse on a bufferram snapshot (128 KiB / 0x20000 bytes typical)."""
    results: list[DisplayListResult] = []
    for start in range(0, min(len(words), 0x20000 // 4), 4):
        if not _plausible_list_start(words, start):
            continue
        hit = try_run_display_list(runner, words, start, source=f"{source}@{start:#x}")
        if hit is not None:
            results.append(hit)
    return results


def _discover_maincpu_lists(maincpu: list[int], main_data: list[int]) -> list[tuple[int, str]]:
    return [
        (off, src)
        for off, src in discover_display_list_starts(maincpu, main_data)
        if _plausible_list_start(main_data, off)
    ]


def extract_scenes(
    rom_dir: Path,
    out_dir: Path,
    *,
    bufferram_path: Path | None = None,
    max_dl_attempts: int = 128,
    max_vertices: int = 500_000,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    main_data_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    main_data = list(struct.unpack(f"<{len(main_data_raw) // 4}I", main_data_raw))
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = list(struct.unpack(f"<{len(poly_raw) // 4}I", poly_raw))
    tex_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    texture_rom = list(struct.unpack(f"<{len(tex_raw) // 4}I", tex_raw))
    mask = len(polygon_rom) - 1
    tex_mask = texture_u16_mask(len(texture_rom))
    tex_half = len(texture_rom) // 2
    texture_sheets = (texture_rom[:tex_half], texture_rom[tex_half:])
    palette_state = load_palette_from_main_data(main_data_raw)

    ctx = GeoDisplayContext(polygon_rom=polygon_rom, polygon_rom_mask=mask)
    runner = GeoDisplayListRunner(ctx)

    written: list[Path] = []
    catalog: list[dict[str, object]] = []
    all_vertices: list[tuple[float, float, float]] = []

    # --- RE-anchored master catalog + placement stream (main_data @ 0x02864b40) ---
    object_catalog = parse_catalog(main_data, mask=mask)
    master_placements = parse_placement_stream(
        main_data, polygon_rom, polygon_rom_mask=mask
    )
    catalog_json = out_dir / "object_catalog.json"
    catalog_json.write_text(
        json.dumps(
            [
                {
                    "index": e.index,
                    "vaddr": f"0x{e.vaddr:08x}",
                    "field_a": e.field_a,
                    "field_b": e.field_b,
                    "oba": f"0x{e.oba:08x}",
                    "obc": e.obc,
                    "rom_offset": e.rom_offset,
                }
                for e in object_catalog
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(catalog_json)

    if master_placements:
        master_verts: list[tuple[float, float, float]] = []
        for rec in master_placements:
            master_verts.extend(rec.vertices)
        master_path = out_dir / "master_placement_stream.obj"
        _write_obj(master_path, master_verts)
        written.append(master_path)
        catalog.insert(
            0,
            {
                "file": master_path.name,
                "kind": "master_placement_stream",
                "catalog_vaddr": f"0x{CATALOG_VADDR:08x}",
                "placement_vaddr": f"0x{PLACEMENT_STREAM_VADDR:08x}",
                "catalog_entries": len(object_catalog),
                "placements": len(master_placements),
                "vertices": len(master_verts),
            },
        )
        all_vertices.extend(master_verts)

    draw_layers = parse_draw_script(main_data)
    for layer in draw_layers:
        layer.rom_offset = layer.oba & mask
    draw_path = out_dir / "draw_script.json"
    draw_path.write_text(
        json.dumps(
            [
                {
                    "index": layer.index,
                    "vaddr": f"0x{layer.vaddr:08x}",
                    "field_a": layer.field_a,
                    "field_b": layer.field_b,
                    "oba": f"0x{layer.oba:08x}",
                    "obc": layer.obc,
                    "rom_offset": layer.rom_offset,
                }
                for layer in draw_layers
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(draw_path)

    segments = placement_segments_from_draw_layers(
        draw_layers, max_placement_index=len(master_placements)
    )
    seg_dir = out_dir / "placement_segments"
    seg_dir.mkdir(parents=True, exist_ok=True)
    capture_dir = out_dir.parent / "i960"
    workram = load_workram_captures(capture_dir)
    segment_catalog: list[dict[str, object]] = []
    for si, (start, end, layer_idx) in enumerate(segments):
        batch = slice_placements(master_placements, start, end)
        if not batch:
            continue
        verts: list[tuple[float, float, float]] = []
        for rec in batch:
            verts.extend(rec.vertices)
        labels = classify_placement_segment(
            segment_index=si,
            placement_range=(start, end),
            vertices=len(verts),
            draw_layer_index=layer_idx,
            workram=workram,
        )
        label_suffix = f"_{labels['label']}" if labels.get("label") else ""
        seg_path = seg_dir / f"segment_{si:02d}{label_suffix}_placements_{start:03d}_{end:03d}.obj"
        for stale in seg_dir.glob(f"segment_{si:02d}_*_placements_{start:03d}_{end:03d}.obj"):
            if stale != seg_path and stale.is_file():
                stale.unlink()
        _write_obj(seg_path, verts)
        written.append(seg_path)
        segment_catalog.append(
            {
                "file": seg_path.relative_to(out_dir).as_posix(),
                "placement_range": [start, end],
                "count": len(batch),
                "vertices": len(verts),
                "draw_layer_index": layer_idx,
                **labels,
            }
        )
    (out_dir / "placement_segments.json").write_text(
        json.dumps(segment_catalog, indent=2) + "\n", encoding="utf-8"
    )

    course_track_catalog = build_course_track_catalog(segment_catalog)
    tracks_dir = out_dir / "tracks"
    tracks_dir.mkdir(parents=True, exist_ok=True)
    for course_id in UI_COURSE_ORDER:
        spec = COURSE_TRACK_EXPORTS[course_id]
        ranges = [(int(a), int(b)) for a, b in spec["placement_ranges"]]
        course_verts, course_faces, course_normals, excluded = collect_course_track_mesh(
            master_placements,
            polygon_rom,
            ranges,
            exclude_ambient_env=bool(spec.get("exclude_ambient_env")),
        )
        point_cloud, point_excluded = collect_course_track_point_cloud(
            master_placements,
            polygon_rom,
            ranges,
            exclude_ambient_env=bool(spec.get("exclude_ambient_env")),
        )
        entry = next(e for e in course_track_catalog if e.get("course_id") == course_id)
        obj_name = f"{entry['id']}.obj"
        obj_path = tracks_dir / obj_name
        _write_obj(obj_path, course_verts, course_faces, face_normals=course_normals)
        written.append(obj_path)
        points_name = f"{entry['id']}_points.obj"
        points_path = tracks_dir / points_name
        _write_obj(points_path, point_cloud)
        written.append(points_path)
        entry["file"] = f"tracks/{obj_name}"
        entry["points_file"] = f"tracks/{points_name}"
        entry["vertices"] = len(course_verts)
        entry["point_vertices"] = len(point_cloud)
        entry["faces"] = len(course_faces)
        if excluded:
            entry["excluded_placements"] = excluded
        if point_excluded and not excluded:
            entry["excluded_placements"] = point_excluded
        tex_verts, tex_prims, tex_excluded = collect_course_textured_mesh(
            master_placements,
            polygon_rom,
            texture_rom,
            ranges,
            exclude_ambient_env=bool(spec.get("exclude_ambient_env")),
            texture_mask=tex_mask,
        )
        if tex_prims:
            tex_name = f"{entry['id']}_textured.obj"
            tex_path = tracks_dir / tex_name
            palette_cache = out_dir.parent / "textures" / "palette_cache" / course_id
            write_textured_obj(
                tex_path,
                tex_verts,
                tex_prims,
                mtl_name="sheet0",
                material_by_sheet={0: "sheet0", 1: "sheet1"},
                palette=palette_state,
                texture_sheets=texture_sheets,
                palette_cache_dir=palette_cache,
                out_root=out_dir.parent,
                index_sheets_only=False,
            )
            entry["textured_palette_variants"] = len(
                {
                    (p.sheet_index, p.colorbase, p.lumabase, p.translucent, p.checker)
                    for p in tex_prims
                    if len(p.indices) >= 3 and (p.renderer & 2)
                }
            )
            written.append(tex_path)
            written.append(tex_path.with_suffix(".mtl"))
            entry["textured_file"] = f"tracks/{tex_name}"
            entry["textured_vertices"] = len(tex_verts)
            entry["textured_faces"] = len(tex_prims)
            if tex_excluded and not entry.get("excluded_placements"):
                entry["excluded_placements"] = tex_excluded
    supplement_catalog: list[dict[str, object]] = []
    for course_id, supplements in COURSE_TRACK_SUPPLEMENTS.items():
        for spec in supplements:
            ranges = [(int(a), int(b)) for a, b in spec["placement_ranges"]]
            sup_verts, sup_faces, sup_normals, _ = collect_course_track_mesh(
                master_placements, polygon_rom, ranges
            )
            if not sup_verts:
                continue
            obj_name = f"{spec['id']}.obj"
            obj_path = tracks_dir / obj_name
            _write_obj(obj_path, sup_verts, sup_faces, face_normals=sup_normals)
            written.append(obj_path)
            lo = min(r[0] for r in ranges)
            hi = max(r[1] for r in ranges)
            supplement_catalog.append(
                {
                    "id": spec["id"],
                    "course_id": course_id,
                    "parent_course": course_id,
                    "title": spec["title"],
                    "track_object": spec.get("track_object"),
                    "placement_ranges": ranges,
                    "placement_range": [lo, hi],
                    "draw_batches": spec.get("draw_batches", []),
                    "role": spec.get("role", "detached_segment"),
                    "confidence": spec.get("confidence", "heuristic"),
                    "note": spec.get("note"),
                    "file": f"tracks/{obj_name}",
                    "vertices": len(sup_verts),
                    "faces": len(sup_faces),
                }
            )
    ambient_verts: list[tuple[float, float, float]] = []
    ambient_faces: list[tuple[int, ...]] = []
    ambient_normals: list[tuple[float, float, float]] = []
    for rec in master_placements:
        if is_ambient_env_ring_placement(rec):
            from tools.model2_placements import apply_placement_mesh

            hit = apply_placement_mesh(
                polygon_rom,
                matrix=rec.matrix,
                rom_offset=rec.rom_offset,
                obc=rec.obc,
            )
            if hit:
                local_verts, local_faces, local_normals = hit
                base = len(ambient_verts)
                ambient_verts.extend(local_verts)
                for face, normal in zip(local_faces, local_normals):
                    if len(face) >= 3:
                        ambient_faces.append(tuple(base + i for i in face))
                        ambient_normals.append(normal)
            else:
                ambient_verts.extend(rec.vertices)
    if ambient_verts:
        ambient_path = tracks_dir / "track_ambient_env_rings.obj"
        _write_obj(ambient_path, ambient_verts, ambient_faces, face_normals=ambient_normals)
        written.append(ambient_path)
    (out_dir / "course_tracks.json").write_text(
        json.dumps(course_track_catalog, indent=2) + "\n", encoding="utf-8"
    )
    if supplement_catalog:
        (out_dir / "course_track_supplements.json").write_text(
            json.dumps(supplement_catalog, indent=2) + "\n", encoding="utf-8"
        )

    track_report_path = capture_dir / "track_report.json"
    track_report_path.parent.mkdir(parents=True, exist_ok=True)
    track_report_path.write_text(
        json.dumps(
            build_track_report(
                rom_dir=rom_dir,
                capture_dir=capture_dir,
                placement_segments=segment_catalog,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(track_report_path)

    anchors = {
        name: f"0x{vaddr:08x}"
        for name, vaddr in CPU_SCENE_ANCHORS.items()
    }
    (out_dir / "scene_cpu_anchors.json").write_text(
        json.dumps(anchors, indent=2) + "\n", encoding="utf-8"
    )

    # --- Heuristic placement scan (legacy; noisy singleton groups) ---
    placements = discover_placements(main_data, polygon_rom, polygon_rom_mask=mask)
    placement_groups = group_placements(placements)

    for gi, group in enumerate(placement_groups):
        verts: list[tuple[float, float, float]] = []
        for rec in group:
            verts.extend(rec.vertices)
        if not verts:
            continue
        path = out_dir / f"placement_group_{gi:03d}.obj"
        _write_obj(path, verts)
        written.append(path)
        catalog.append(
            {
                "file": path.name,
                "kind": "placement_table",
                "main_data_word_start": group[0].main_data_word,
                "vaddr": f"0x{0x0200_0000 + group[0].main_data_word * 4:08x}",
                "placements": len(group),
                "vertices": len(verts),
                "objects": [
                    {
                        "word": r.main_data_word,
                        "rom_offset": r.rom_offset,
                        "oba": f"0x{r.oba:08x}",
                        "obc": r.obc,
                        "vertices": len(r.vertices),
                    }
                    for r in group
                ],
            }
        )
        all_vertices.extend(verts)

    # --- Display lists referenced from maincpu (when valid) ---
    maincpu = _load_maincpu(rom_dir)
    dl_candidates = _discover_maincpu_lists(maincpu, main_data)[:max_dl_attempts]
    dl_count = 0
    for offset, source in dl_candidates:
        hit = try_run_display_list(runner, main_data, offset, source=source)
        if hit is None:
            continue
        m = max(max(abs(v[0]), abs(v[1]), abs(v[2])) for v in hit.vertices)
        if m < 2.0:
            continue
        path = out_dir / f"display_list_{dl_count:04d}.obj"
        _write_obj(path, hit.vertices)
        written.append(path)
        catalog.append(
            {
                "file": path.name,
                "kind": "display_list",
                "source": source,
                "start_word": offset,
                "vertices": len(hit.vertices),
                "objects": len(hit.objects),
            }
        )
        all_vertices.extend(hit.vertices)
        dl_count += 1

    # --- Optional bufferram snapshot (from MAME debugger save) ---
    if bufferram_path and bufferram_path.is_file():
        raw = bufferram_path.read_bytes()
        buff = list(struct.unpack(f"<{len(raw) // 4}I", raw))
        for idx, hit in enumerate(_run_bufferram_display_lists(runner, buff, source=bufferram_path.name)):
            path = out_dir / f"bufferram_dl_{idx:04d}.obj"
            _write_obj(path, hit.vertices)
            written.append(path)
            catalog.append(
                {
                    "file": path.name,
                    "kind": "bufferram",
                    "start_word": hit.start_word,
                    "vertices": len(hit.vertices),
                }
            )
            all_vertices.extend(hit.vertices)

    if len(all_vertices) > max_vertices:
        step = max(1, len(all_vertices) // max_vertices)
        combined = all_vertices[::step]
    else:
        combined = all_vertices

    if combined:
        combined_path = out_dir / "scenes_combined.obj"
        _write_obj(combined_path, combined)
        written.append(combined_path)

    catalog_path = out_dir / "scenes.json"
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    written.append(catalog_path)

    meta = {
        "draw_script_vaddr": f"0x{DRAW_SCRIPT_VADDR:08x}",
        "draw_script_layers": len(draw_layers),
        "placement_segments": len(segment_catalog),
        "master_catalog_entries": len(object_catalog),
        "master_placement_records": len(master_placements),
        "heuristic_placement_records": len(placements),
        "placement_groups": len(placement_groups),
        "display_list_candidates": len(dl_candidates),
        "display_lists_exported": dl_count,
        "combined_vertices": len(combined),
        "notes": [
            "Master table: 782× catalog @ 0x02864b40, then stride-4 placements @ 0x02867c20 (i960-confirmed).",
            "Geo display lists are built at runtime in bufferram (0x00900000).",
            "Heuristic placement_group_* exports are legacy noise except where they overlap the master stream.",
            "Pass --bufferram to parse a 128KB bufferram dump from MAME for frame-accurate lists.",
        ],
    }
    meta_path = out_dir / "scenes_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    written.append(meta_path)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export world-space scenes (placements + display lists).")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/scenes"))
    parser.add_argument("--bufferram", type=Path, default=None, help="128KB bufferram dump from MAME")
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_scenes(rom_dir, args.out, bufferram_path=args.bufferram)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
