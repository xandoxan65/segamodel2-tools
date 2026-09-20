"""Build a categorized asset index for the point-map viewer (P1)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.i960_tracks import (
    COURSE_TRACK_EXPORTS,
    COURSE_TRACK_SUPPLEMENTS,
    UI_COURSE_ORDER,
    build_course_track_catalog,
)


def _segment_title(seg: dict[str, object]) -> str:
    label = seg.get("label")
    start, end = seg.get("placement_range", [0, 0])
    verts = seg.get("vertices", 0)
    phase = seg.get("phase")
    layer = seg.get("draw_layer_index")
    idx = seg.get("segment_index", "?")
    name = label if label else f"segment_{idx:02d}"
    phase_tag = f" · {phase}" if phase else ""
    layer_tag = f" · layer {layer}" if layer is not None else ""
    return f"{name} [{start}:{end}]{phase_tag}{layer_tag} · {verts:,} pts"


def _merge_obj_files(paths: list[Path], out_path: Path) -> int:
    """Concatenate Wavefront OBJ vertex lines; returns vertex count."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_path.open("w", encoding="utf-8") as out:
        out.write("# segamod2 merged placement-stream export\n")
        for path in paths:
            if not path.is_file():
                continue
            out.write(f"# include {path.name}\n")
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("v "):
                    out.write(line + "\n")
                    count += 1
    return count


def _build_track_composites(out_root: Path, segments: list[dict[str, object]]) -> list[dict[str, object]]:
    """Merge placement-segment OBJs for viewer overview entries."""
    scene_root = out_root / "scenes"
    entries: list[dict[str, object]] = []

    def paths_for(tiers: set[str] | None = None, phases: set[str] | None = None) -> list[Path]:
        out: list[Path] = []
        for seg in segments:
            if tiers is not None and str(seg.get("tier", "")) not in tiers:
                continue
            if phases is not None and str(seg.get("phase", "")) not in phases:
                continue
            rel = str(seg.get("file", ""))
            if rel:
                out.append(scene_root / rel)
        return out

    composites = [
        (
            "track_race_combined",
            "Race draw script (major + medium batches)",
            paths_for(tiers={"major_geometry", "medium_geometry"}),
            "placement_stream",
            "track",
            "Merged RE-backed segments from draw script @ 0x28656C0 (placements 9–511).",
        ),
        (
            "track_phase_a",
            "Race phase A (draw layers 0–20)",
            paths_for(phases={"phase_a"}, tiers={"major_geometry", "medium_geometry"}),
            "placement_stream",
            "track",
            "Phase A placement batches before draw-layer jump @ segment 7.",
        ),
        (
            "track_phase_b",
            "Race phase B (draw layers 125+)",
            paths_for(phases={"phase_b"}, tiers={"major_geometry", "medium_geometry"}),
            "placement_stream",
            "track",
            "Phase B placement batches (geometry_batch_b/c).",
        ),
    ]

    for asset_id, title, paths, source, category, note in composites:
        if not paths:
            continue
        out_rel = f"scenes/{asset_id}.obj"
        verts = _merge_obj_files(paths, out_root / out_rel)
        if verts == 0:
            continue
        entries.append(
            {
                "id": asset_id,
                "category": category,
                "name": f"{title} · {verts:,} pts",
                "path": out_rel,
                "vertices": verts,
                "source": source,
                "note": note,
                "merged_from": [str(p.relative_to(scene_root)) for p in paths],
            }
        )
    return entries


def build_asset_index(out_root: Path) -> Path:
    out_root = out_root.resolve()
    entries: list[dict[str, object]] = []

    vehicles_index_path = out_root / "vehicles" / "vehicles_index.json"
    if vehicles_index_path.is_file():
        vehicles_index = json.loads(vehicles_index_path.read_text(encoding="utf-8"))
        for asset in vehicles_index.get("assets", []):
            if isinstance(asset, dict) and asset.get("path"):
                entries.append(dict(asset))
        default_vehicle_id = vehicles_index.get("default_asset_id")
    else:
        default_vehicle_id = None

    seg_json = out_root / "scenes" / "placement_segments.json"
    segments: list[dict[str, object]] = []
    if seg_json.is_file():
        segments = json.loads(seg_json.read_text(encoding="utf-8"))

    course_tracks_json = out_root / "scenes" / "course_tracks.json"
    course_tracks: list[dict[str, object]] = []
    if course_tracks_json.is_file():
        course_tracks = json.loads(course_tracks_json.read_text(encoding="utf-8"))
    elif segments:
        course_tracks = build_course_track_catalog(segments)

    supplements_json = out_root / "scenes" / "course_track_supplements.json"
    supplements: list[dict[str, object]] = []
    if supplements_json.is_file():
        supplements = json.loads(supplements_json.read_text(encoding="utf-8"))
    viewer_includes_by_course: dict[str, list[str]] = {}
    viewer_include_verts: dict[str, int] = {}
    for sup in supplements:
        if not isinstance(sup, dict):
            continue
        course_id = str(sup.get("parent_course") or sup.get("course_id") or "")
        rel = str(sup.get("file", ""))
        if not course_id or not rel:
            continue
        path = f"scenes/{rel}"
        viewer_includes_by_course.setdefault(course_id, []).append(path)
        viewer_include_verts[course_id] = viewer_include_verts.get(course_id, 0) + int(
            sup.get("vertices", 0)
        )
    viewer_include_faces: dict[str, int] = {}
    for sup in supplements:
        if not isinstance(sup, dict):
            continue
        course_id = str(sup.get("parent_course") or sup.get("course_id") or "")
        if course_id:
            viewer_include_faces[course_id] = viewer_include_faces.get(course_id, 0) + int(
                sup.get("faces", 0)
            )

    if course_tracks:
        scene_root = out_root / "scenes"
        for course in course_tracks:
            if not isinstance(course, dict):
                continue
            rel = str(course.get("file", ""))
            if not rel:
                continue
            obj_path = scene_root / rel
            if not obj_path.is_file():
                seg_files = [scene_root / str(f) for f in course.get("segment_files", [])]
                paths = [p for p in seg_files if p.is_file()]
                if paths:
                    out_rel = rel
                    verts = _merge_obj_files(paths, out_root / "scenes" / out_rel)
                    course["vertices"] = verts
                else:
                    continue
            verts = int(course.get("vertices", 0))
            if verts == 0 and obj_path.is_file():
                verts = sum(
                    1 for line in obj_path.read_text(encoding="utf-8").splitlines() if line.startswith("v ")
                )
            point_verts = int(course.get("point_vertices", 0))
            if point_verts == 0:
                points_rel = str(course.get("points_file", ""))
                if points_rel:
                    points_path = scene_root / points_rel
                    if points_path.is_file():
                        point_verts = sum(
                            1
                            for line in points_path.read_text(encoding="utf-8").splitlines()
                            if line.startswith("v ")
                        )
            title = str(course.get("title", course.get("course_id", "Course")))
            course_id = str(course.get("course_id", ""))
            includes = viewer_includes_by_course.get(course_id, [])
            display_verts = verts + viewer_include_verts.get(course_id, 0)
            faces = int(course.get("faces", 0))
            display_faces = faces + viewer_include_faces.get(course_id, 0)
            point_label = (
                f"{point_verts:,} face-corner pts · {display_verts:,} strip verts"
                if point_verts
                else f"{display_verts:,} pts"
            )
            entry: dict[str, object] = {
                "id": str(course.get("id", f"track_{course.get('course_id')}")),
                "category": "track",
                "name": (
                    f"{title} · {point_label} · {display_faces:,} faces"
                    if display_faces
                    else f"{title} · {point_label}"
                ),
                "path": f"scenes/{rel}",
                "vertices": verts,
                "point_vertices": point_verts or None,
                "points_path": f"scenes/{course['points_file']}" if course.get("points_file") else None,
                "faces": faces,
                "viewer_faces": display_faces if includes else faces,
                "viewer_vertices": display_verts if includes else verts,
                "course_id": course.get("course_id"),
                "track_object": course.get("track_object"),
                "placement_range": course.get("placement_range"),
                "placement_ranges": course.get("placement_ranges"),
                "draw_batches": course.get("draw_batches"),
                "confidence": course.get("confidence"),
                "source": "placement_stream",
                "note": course.get("note"),
                "merged_from": course.get("segment_files"),
                "excluded_placements": course.get("excluded_placements"),
                "excluded_placement_ranges": course.get("excluded_placement_ranges"),
            }
            textured_rel = str(course.get("textured_file", ""))
            if textured_rel:
                tex_path = scene_root / textured_rel
                if tex_path.is_file():
                    entry["textured_path"] = f"scenes/{textured_rel}"
                    entry["textured_faces"] = int(course.get("textured_faces", 0))
                    variants = course.get("textured_palette_variants")
                    course_id = course.get("course_id")
                    if not variants and course_id:
                        cache = out_root / "textures" / "palette_cache" / str(course_id)
                        if cache.is_dir():
                            variants = len(list(cache.glob("*.png")))
                    if variants:
                        entry["textured_palette_variants"] = int(variants)
            if includes:
                entry["viewer_includes"] = includes
                entry["supplementary_assets"] = course.get("supplementary_assets")
            entries.append(entry)

    if not supplements and COURSE_TRACK_SUPPLEMENTS:
        for course_id, specs in COURSE_TRACK_SUPPLEMENTS.items():
            for spec in specs:
                supplements.append({**spec, "course_id": course_id, "parent_course": course_id})

    for sup in supplements:
        if not isinstance(sup, dict):
            continue
        rel = str(sup.get("file", f"tracks/{sup.get('id')}.obj"))
        obj_path = out_root / "scenes" / rel
        if not obj_path.is_file():
            continue
        verts = int(sup.get("vertices", 0))
        if verts == 0:
            verts = sum(
                1 for line in obj_path.read_text(encoding="utf-8").splitlines() if line.startswith("v ")
            )
        title = str(sup.get("title", sup.get("id", "Supplement")))
        course_id = sup.get("parent_course") or sup.get("course_id")
        sup_faces = int(sup.get("faces", 0))
        entries.append(
            {
                "id": str(sup.get("id")),
                "category": "track",
                "name": (
                    f"{title} · {verts:,} pts · {sup_faces:,} faces"
                    if sup_faces
                    else f"{title} · {verts:,} pts"
                ),
                "path": f"scenes/{rel}",
                "vertices": verts,
                "faces": sup_faces,
                "course_id": course_id,
                "parent_course": course_id,
                "track_object": sup.get("track_object"),
                "placement_range": sup.get("placement_range"),
                "placement_ranges": sup.get("placement_ranges"),
                "draw_batches": sup.get("draw_batches"),
                "role": sup.get("role", "detached_segment"),
                "confidence": sup.get("confidence"),
                "source": "placement_stream",
                "note": sup.get("note"),
            }
        )

    ambient_path = out_root / "scenes" / "tracks" / "track_ambient_env_rings.obj"
    if ambient_path.is_file():
        verts = sum(
            1 for line in ambient_path.read_text(encoding="utf-8").splitlines() if line.startswith("v ")
        )
        entries.append(
            {
                "id": "track_ambient_env_rings",
                "category": "props",
                "name": f"Ambient env-map rings (championship) · {verts:,} pts",
                "path": "scenes/tracks/track_ambient_env_rings.obj",
                "vertices": verts,
                "source": "placement_stream",
                "role": "ambient_env_ring",
                "confidence": "confirmed",
                "note": (
                    "Placement 456 @ ROM 0x9ACA84: two decagons (r≈8000, Y≈3284.9 and Y≈-200) "
                    "for sky/ambient texture sampling — not track surface geometry."
                ),
            }
        )

    if segments:
        entries.extend(_build_track_composites(out_root, segments))
        for i, seg in enumerate(segments):
            if not isinstance(seg, dict):
                continue
            file_rel = str(seg.get("file", ""))
            if not file_rel:
                continue
            obj_path = out_root / "scenes" / file_rel
            if not obj_path.is_file():
                continue
            label = seg.get("label")
            tier = str(seg.get("tier", "minor"))
            if label == "shared_props" or tier == "minor":
                category = "props"
            elif tier in ("major_geometry", "medium_geometry"):
                category = "track"
            else:
                category = "other"
            seg_entry = {**seg, "segment_index": i}
            entries.append(
                {
                    "id": f"segment_{i:02d}",
                    "category": category,
                    "name": _segment_title(seg_entry),
                    "path": f"scenes/{file_rel}",
                    "vertices": seg.get("vertices", 0),
                    "placement_range": seg.get("placement_range"),
                    "draw_layer_index": seg.get("draw_layer_index"),
                    "label": label,
                    "tier": tier,
                    "phase": seg.get("phase"),
                    "source": "placement_stream",
                    "note": "RE-backed draw-script segment (object-local; no runtime matrix).",
                }
            )

    for special in (
        ("scenes/master_placement_stream.obj", "overview", "Full placement stream (518 instances)"),
    ):
        rel, category, title = special
        path = out_root / rel
        if not path.is_file():
            continue
        verts = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("v "))
        entries.append(
            {
                "id": rel.replace("/", "_").replace(".obj", ""),
                "category": category,
                "name": f"{title} · {verts:,} pts",
                "path": rel,
                "vertices": verts,
                "source": "placement_stream",
                "note": "All 518 placement instances — useful sanity check; not one assembled course.",
            }
        )

    meshes_meta_path = out_root / "meshes" / "meshes_meta.json"
    if meshes_meta_path.is_file():
        meshes_meta = json.loads(meshes_meta_path.read_text(encoding="utf-8"))
        for region in meshes_meta.get("regions", []):
            if not isinstance(region, dict):
                continue
            name = str(region.get("name", ""))
            file_name = str(region.get("file", ""))
            if not file_name:
                continue
            # ROM bank dumps are legacy heuristics — not track identity.
            if name in ("bank2", "bank3", "full"):
                category = "other"
                note = "Deprecated ROM bank walk — misleading for tracks; use placement segments."
            elif name in ("bank0", "bank1"):
                category = "other"
                note = "Vehicle ROM quarter — use vehicles/ exports instead."
            else:
                category = "other"
                note = "Polygon ROM region export."
            entries.append(
                {
                    "id": f"mesh_{name}",
                    "category": category,
                    "name": f"{name} · {region.get('points', 0):,} pts (legacy ROM bank)",
                    "path": f"meshes/{file_name}",
                    "vertices": region.get("points", 0),
                    "bounds": region.get("bounds"),
                    "source": "polygon_rom_bank",
                    "bank": name,
                    "deprecated": True,
                    "note": note,
                }
            )

    categories = {
        "track": {
            "title": "Track geometry",
            "description": (
                "Four menu courses (Desert / Forest / Mountain / Championship). "
                "Course entries auto-merge detached supplementary spans in the viewer (object-local coords). "
                "Placement slices are heuristic until workram confirms per-course dispatch."
            ),
        },
        "vehicles": {
            "title": "Vehicles",
            "description": "RE-backed catalog meshes (body shells 96–107) and race assemblies (body+trim+wheels).",
        },
        "props": {
            "title": "Props & minor",
            "description": "Small placement batches (shared props, tail placements 511–517, etc.).",
        },
        "overview": {
            "title": "Overview",
            "description": "Full 518-instance placement stream dump.",
        },
        "other": {
            "title": "Legacy / debug",
            "description": "Deprecated ROM bank walks — do not use for track or vehicle identification.",
        },
    }

    default_track_id = next(
        (e["id"] for e in entries if e.get("id") == "track_desert"),
        next(
            (e["id"] for e in entries if e.get("id") == "track_race_combined"),
            next(
                (e["id"] for e in entries if e.get("label") == "geometry_batch_a"),
                next((e["id"] for e in entries if e.get("tier") == "major_geometry"), None),
            ),
        ),
    )

    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "notes": [
            "Track data is from placement_stream + draw_script_segments (i960 RE), not ROM bank quarters.",
            "Four course exports (track_desert/forest/mountain/championship) split major draw-script batches heuristically.",
            "Coordinates are object-local; runtime placement matrices are not applied in these exports.",
        ],
        "course_tracks": {
            course_id: {
                "title": COURSE_TRACK_EXPORTS[course_id]["title"],
                "track_object": COURSE_TRACK_EXPORTS[course_id]["track_object"],
                "placement_ranges": COURSE_TRACK_EXPORTS[course_id]["placement_ranges"],
                "confidence": COURSE_TRACK_EXPORTS[course_id]["confidence"],
            }
            for course_id in UI_COURSE_ORDER
        },
        "categories": categories,
        "assets": entries,
        "default_asset_id": default_track_id,
        "default_vehicle_asset_id": default_vehicle_id,
    }

    out_path = out_root / "asset_index.json"
    out_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build out/asset_index.json for the viewer.")
    parser.add_argument("--out", type=Path, default=Path("out"))
    args = parser.parse_args()
    path = build_asset_index(args.out)
    print(path.resolve())


if __name__ == "__main__":
    main()
