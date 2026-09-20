"""Build viewer manifest.json from extracted assets."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def build_manifest(out_root: Path) -> Path:
    out_root = out_root.resolve()
    manifest: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(out_root),
        "textures": [],
        "heightmaps": [],
        "meshes": [],
        "samples": [],
        "labels": None,
    }

    tex_dir = out_root / "textures"
    if tex_dir.is_dir():
        for p in sorted(tex_dir.glob("*.png")):
            manifest["textures"].append({"name": p.stem, "path": str(p.relative_to(out_root))})

    hm_dir = out_root / "heightmaps"
    if hm_dir.is_dir():
        # Prefer u16 2048-wide grids for track overview.
        preferred = sorted(hm_dir.glob("*_u16_2048x*.png"))
        others = sorted(p for p in hm_dir.glob("*.png") if p not in preferred)
        for p in preferred + others:
            manifest["heightmaps"].append({"name": p.stem, "path": str(p.relative_to(out_root))})

    mesh_dir = out_root / "meshes"
    if mesh_dir.is_dir():
        for p in sorted(mesh_dir.glob("*.obj")):
            manifest["meshes"].append({"name": p.stem, "path": str(p.relative_to(out_root))})
        meta = mesh_dir / "meshes_meta.json"
        if meta.is_file():
            manifest["meshes_meta"] = json.loads(meta.read_text())

    scene_dir = out_root / "scenes"
    if scene_dir.is_dir():
        manifest["scenes"] = []
        scene_objs = sorted(scene_dir.glob("*.obj"))
        # Prefer combined + placement tables; skip stale scene_XXXX dumps if present.
        seg_objs = sorted((scene_dir / "placement_segments").glob("*.obj")) if (scene_dir / "placement_segments").is_dir() else []
        preferred = [
            p
            for p in scene_objs
            if p.name
            in ("master_placement_stream.obj", "scenes_combined.obj")
            or p.name.startswith("placement_group_")
        ]
        preferred = seg_objs + preferred
        for p in preferred or scene_objs:
            manifest["scenes"].append({"name": p.stem, "path": str(p.relative_to(out_root))})
        scenes_meta = scene_dir / "scenes_meta.json"
        if scenes_meta.is_file():
            manifest["scenes_meta"] = json.loads(scenes_meta.read_text())

    sample_dir = out_root / "samples"
    if sample_dir.is_dir():
        for p in sorted(sample_dir.glob("*_preview.wav")):
            manifest["samples"].append({"name": p.stem.replace("_preview", ""), "path": str(p.relative_to(out_root))})

    labels = out_root / "labels" / "labels.json"
    if labels.is_file():
        manifest["labels"] = json.loads(labels.read_text())

    asset_index = out_root / "asset_index.json"
    if asset_index.is_file():
        manifest["asset_index"] = json.loads(asset_index.read_text())

    seg_json = out_root / "scenes" / "placement_segments.json"
    if seg_json.is_file():
        manifest["placement_segments"] = json.loads(seg_json.read_text())

    out_path = out_root / "manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build out/manifest.json for the viewer.")
    parser.add_argument("--out", type=Path, default=Path("out"))
    args = parser.parse_args()
    path = build_manifest(args.out)
    print(path.resolve())


if __name__ == "__main__":
    main()
