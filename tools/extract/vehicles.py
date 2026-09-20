"""Export vehicle point maps from RE-backed catalog indices (not ROM span heuristics)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from tools.i960_vehicles import (
    BODY_SHELL_INDICES,
    TRIM_INDICES,
    WHEEL_INDICES,
    build_vehicle_geo_chain,
    build_vehicle_report,
    mesh_geometry_fingerprint,
    parse_vehicle_catalog_tables,
)
from tools.model2_catalog import parse_catalog
from tools.model2_geo import try_parse_polygon_object
from tools.model2_vehicle_transforms import (
    _pose_is_yaw_like,
    build_race_assembly_vertices,
    catalog_polygon_offsets,
    load_vehicle_main_data,
    load_workram_pose_matrices,
    select_workram_pose,
)
from tools.obj_export import write_obj
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


def extract_vehicles(
    rom_dir: Path,
    out_dir: Path,
    *,
    capture_dir: Path | None = None,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_vehicle_report(rom_dir)
    tables = parse_vehicle_catalog_tables(rom_dir)

    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = list(struct.unpack(f"<{len(poly_raw) // 4}I", poly_raw))
    mask = len(polygon_rom) - 1
    main_data = list(
        struct.unpack(
            f"<{len(load32_word_region(rom_dir, SRALLY_DATA_ROMS['main_data'])) // 4}I",
            load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]),
        )
    )
    catalog = parse_catalog(main_data, mask=mask)
    catalog_by_index = {e.index: e for e in catalog}
    mesh_by_index = {int(m["catalog_index"]): m for m in report["catalog_meshes"] if "catalog_index" in m}

    written: list[Path] = []
    index_entries: list[dict[str, object]] = []
    exported: set[int] = set()
    geometry_canonical: dict[str, int] = {}

    for table in tables:
        for order, cat_index in enumerate(table.catalog_indices):
            if cat_index in exported:
                continue
            exported.add(cat_index)
            entry = catalog[cat_index]
            parsed = try_parse_polygon_object(polygon_rom, entry.rom_offset)
            if parsed is None:
                continue
            meta = mesh_by_index.get(cat_index, {})
            role = meta.get("role", "other")
            file_name = f"catalog_{cat_index:03d}_{role}_off{entry.rom_offset:06x}.obj"
            obj_path = out_dir / file_name
            faces = [prim.indices for prim in parsed.primitives if len(prim.indices) >= 3]
            write_obj(obj_path, parsed.vertices, faces or None)
            written.append(obj_path)

            span = meta.get("span_max", "?")
            verts = len(parsed.vertices)
            geometry_id = mesh_geometry_fingerprint(parsed)
            canonical = geometry_canonical.setdefault(geometry_id, cat_index)
            name = f"catalog {cat_index} ({role}) · ROM 0x{entry.rom_offset:06x} · {verts:,} pts"
            if span != "?":
                name += f" · span {span}"
            if canonical != cat_index and role == "body_shell":
                name += f" · same mesh as {canonical}"

            entry_meta: dict[str, object] = {
                "id": f"catalog_{cat_index:03d}",
                "category": "vehicles",
                "name": name,
                "path": str(obj_path.relative_to(out_dir.parent)),
                "vertices": verts,
                "span": span,
                "rom_offset": entry.rom_offset,
                "catalog_index": cat_index,
                "catalog_indices": [cat_index],
                "role": role,
                "draw_table": table.name,
                "draw_order": order,
                "source": "re_catalog_index",
                "obc": entry.obc,
                "geometry_id": geometry_id,
                "geometry_canonical_catalog": canonical,
            }
            if canonical != cat_index:
                entry_meta["geometry_note"] = (
                    f"Identical mesh to catalog {canonical}. ROM stores duplicate blobs; "
                    "per-car look comes from textures, trim, and wheels."
                )
            index_entries.append(entry_meta)

    index_entries.sort(key=lambda e: (str(e.get("role")), int(e["catalog_index"])))

    # Per-car race assemblies: descriptor main_data transforms (+ optional workram pose).
    geo_chain = build_vehicle_geo_chain(rom_dir)
    vehicle_main_data = load_vehicle_main_data(rom_dir)
    vehicle_catalog_indices = sorted(
        set(BODY_SHELL_INDICES) | set(TRIM_INDICES) | set(WHEEL_INDICES)
    )
    polygon_offsets = catalog_polygon_offsets(catalog, vehicle_catalog_indices)
    pose_slots = load_workram_pose_matrices(capture_dir) if capture_dir else []
    pose_matrix = select_workram_pose(pose_slots)

    assembly_entries: list[dict[str, object]] = []
    for car in geo_chain["body_cars"]:
        cat_index = int(car["catalog_index"])

        def export_assembly(
            *,
            suffix: str,
            asset_suffix: str,
            name: str,
            include_panels: bool,
            pose: list[float] | None,
            transform_source: str,
        ) -> None:
            combined_verts, parts = build_race_assembly_vertices(
                body_catalog_index=cat_index,
                catalog_entries=catalog_by_index,
                polygon_rom=polygon_rom,
                main_data=vehicle_main_data,
                rom_dir=rom_dir,
                include_panels=include_panels,
                pose_matrix=pose,
            )
            if not combined_verts:
                return
            xs = [v[0] for v in combined_verts]
            ys = [v[1] for v in combined_verts]
            zs = [v[2] for v in combined_verts]
            span_max = round(
                max(max(xs) - min(xs), max(ys) - min(ys), max(zs) - min(zs)),
                2,
            )
            asm_name = f"car_{cat_index:03d}_{suffix}.obj"
            asm_path = out_dir / asm_name
            write_obj(asm_path, combined_verts)
            written.append(asm_path)
            assembly_entries.append(
                {
                    "id": f"car_{cat_index:03d}_{asset_suffix}",
                    "category": "vehicles",
                    "name": name,
                    "path": str(asm_path.relative_to(out_dir.parent)),
                    "vertices": len(combined_verts),
                    "span": span_max,
                    "body_catalog_index": cat_index,
                    "parts": parts,
                    "source": "rom_race_draw_sequence",
                    "transform_source": transform_source,
                    "include_panels": include_panels,
                }
            )

        export_assembly(
            suffix="race_assembly",
            asset_suffix="assembly",
            name=f"car catalog {cat_index} race assembly (body+trim+wheels)",
            include_panels=True,
            pose=None,
            transform_source="descriptor_main_data",
        )
        export_assembly(
            suffix="race_core_assembly",
            asset_suffix="core_assembly",
            name=f"car catalog {cat_index} core assembly (body+trim+hubs)",
            include_panels=False,
            pose=None,
            transform_source="descriptor_main_data",
        )
        if pose_matrix is not None:
            export_assembly(
                suffix="posed_assembly",
                asset_suffix="posed_assembly",
                name=f"car catalog {cat_index} posed assembly (workram 0x5E3E00)",
                include_panels=True,
                pose=pose_matrix,
                transform_source="descriptor_main_data+workram_pose",
            )

    default_id = None
    for preferred_asm in ("car_096_core_assembly", "car_096_assembly", "car_097_assembly"):
        if any(e["id"] == preferred_asm for e in assembly_entries):
            default_id = preferred_asm
            break
    if default_id is None:
        for preferred in (96, 97, 98):
            if any(e["id"] == f"catalog_{preferred:03d}" for e in index_entries):
                default_id = f"catalog_{preferred:03d}"
                break
    if default_id is None and index_entries:
        default_id = str(index_entries[0]["id"])

    meta_path = out_dir / "vehicles_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "source": "i960_re_catalog_tables",
                "draw_fn": report["draw_path"]["fn"],
                "static_tables": report["static_catalog_tables"],
                "geo_chain": geo_chain,
                "catalog_polygon_offsets": {
                    str(k): {
                        "field_a": v.field_a,
                        "field_b": v.field_b,
                        "rom_offset": v.rom_offset,
                    }
                    for k, v in polygon_offsets.items()
                },
                "workram_pose_slots": len(pose_slots),
                "workram_pose_yaw": pose_matrix is not None and _pose_is_yaw_like(pose_matrix),
                "workram_pose_mode": (
                    "yaw_3d"
                    if pose_matrix and _pose_is_yaw_like(pose_matrix)
                    else "translation_only"
                    if pose_matrix
                    else "none"
                ),
                "assemblies": assembly_entries,
                "notes": report["notes"],
                "count": len(index_entries),
                "deprecated_heuristic_filter": (
                    "Span/vertex ROM walks are not used — see out/i960/vehicle_report.json"
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(meta_path)

    index_path = out_dir / "vehicles_index.json"
    index_path.write_text(
        json.dumps(
            {
                "assets": index_entries + assembly_entries,
                "default_asset_id": default_id or (
                    assembly_entries[0]["id"] if assembly_entries else None
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(index_path)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export RE-backed vehicle catalog meshes.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/vehicles"))
    parser.add_argument(
        "--capture-dir",
        type=Path,
        default=None,
        help="Optional workram dump dir (e.g. out/i960) for posed assemblies",
    )
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    capture_dir = args.capture_dir
    if capture_dir is None:
        default_capture = Path("out/i960")
        if (default_capture / "workram_5e3e00.bin").is_file():
            capture_dir = default_capture
    paths = extract_vehicles(rom_dir, args.out, capture_dir=capture_dir)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
