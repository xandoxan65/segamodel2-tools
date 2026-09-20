"""Export meshes from polygon ROM using the MAME Model 2 geo parsers."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from tools.model2_geo import ParsedObject, walk_polygon_rom
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, write_bytes


def write_obj(
    path: Path,
    vertices: list[tuple[float, float, float]],
    primitives: list[tuple[int, ...]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("# segamod2 Model 2 geo parser export\n")
        for x, y, z in vertices:
            f.write(f"v {x:.6f} {y:.6f} {z:.6f}\n")
        if primitives:
            for face in primitives:
                if len(face) == 3:
                    f.write(f"f {face[0] + 1} {face[1] + 1} {face[2] + 1}\n")
                elif len(face) == 4:
                    f.write(
                        f"f {face[0] + 1} {face[1] + 1} {face[2] + 1} {face[3] + 1}\n"
                    )


def _merge_objects(objects: list[ParsedObject]) -> tuple[list[tuple[float, float, float]], list[tuple[int, ...]]]:
    vertices: list[tuple[float, float, float]] = []
    faces: list[tuple[int, ...]] = []
    for obj in objects:
        base = len(vertices)
        vertices.extend(obj.vertices)
        for prim in obj.primitives:
            if len(prim.indices) >= 3:
                faces.append(tuple(base + i for i in prim.indices))
    return vertices, faces


def _object_summary(objects: list[ParsedObject]) -> dict[str, object]:
    mode_counts: dict[str, int] = {}
    for obj in objects:
        mode_counts[obj.mode.name] = mode_counts.get(obj.mode.name, 0) + 1
    return {
        "objects": len(objects),
        "modes": mode_counts,
        "total_vertices": sum(len(o.vertices) for o in objects),
        "largest_object": max((len(o.vertices) for o in objects), default=0),
    }


def extract_meshes(rom_dir: Path, out_dir: Path, max_points_per_region: int = 500_000) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    write_bytes(out_dir / "polygons_deinterleaved.bin", raw)
    words = list(struct.unpack(f"<{len(raw) // 4}I", raw))

    written: list[Path] = []
    quarter = len(words) // 4
    regions = [("full", 0, len(words))]
    for qi in range(4):
        regions.append((f"bank{qi}", qi * quarter, (qi + 1) * quarter))

    summary: dict[str, object] = {
        "parser": "mame_model2_geo",
        "notes": [
            "Vertices parsed with geo_parse_np_ns / geo_parse_nn_ns (MAME model2_v.cpp).",
            "Object-local coordinates (identity matrix); runtime matrix/translate from display lists not applied.",
        ],
        "regions": [],
    }

    for name, start, end in regions:
        objects = walk_polygon_rom(words, start=start, end=end)
        vertices, faces = _merge_objects(objects)
        if not vertices:
            continue
        if len(vertices) > max_points_per_region:
            step = len(vertices) // max_points_per_region
            keep = set(range(0, len(vertices), max(step, 1)))
            remap = {old: new for new, old in enumerate(sorted(keep))}
            vertices = [vertices[i] for i in sorted(keep)]
            faces = [
                tuple(remap[i] for i in face if i in remap)
                for face in faces
                if all(i in remap for i in face)
            ]

        obj_path = out_dir / f"{name}_points.obj"
        write_obj(obj_path, vertices, faces if faces else None)
        written.append(obj_path)

        xs = [p[0] for p in vertices]
        ys = [p[1] for p in vertices]
        zs = [p[2] for p in vertices]
        region_info = {
            "name": name,
            "points": len(vertices),
            "faces": len(faces),
            "file": obj_path.name,
            "bounds": {
                "x": [min(xs), max(xs)],
                "y": [min(ys), max(ys)],
                "z": [min(zs), max(zs)],
            },
            **_object_summary(objects),
        }
        summary["regions"].append(region_info)

        # Per-bank object catalog (offsets relative to bank start).
        catalog = []
        for obj in sorted(objects, key=lambda o: len(o.vertices), reverse=True)[:40]:
            ys_obj = [v[1] for v in obj.vertices]
            catalog.append(
                {
                    "offset": obj.rom_offset - start,
                    "mode": obj.mode.name,
                    "vertices": len(obj.vertices),
                    "words": obj.words_consumed,
                    "y": [min(ys_obj), max(ys_obj)],
                }
            )
        catalog_path = out_dir / f"{name}_objects.json"
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        written.append(catalog_path)

    meta = out_dir / "meshes_meta.json"
    meta.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    written.append(meta)
    return written


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export polygon ROM meshes via Model 2 geo parser.")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/meshes"))
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    paths = extract_meshes(rom_dir, args.out)
    print(f"Wrote {len(paths)} files to {args.out.resolve()}")


if __name__ == "__main__":
    main()
