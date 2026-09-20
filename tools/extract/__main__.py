"""Run all Sega Rally ROM extractors: python -m tools.extract"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.extract.heightmaps import extract_heightmaps
from tools.extract.labels import extract_labels
from tools.extract.asset_index import build_asset_index
from tools.extract.vehicles import extract_vehicles
from tools.extract.manifest import build_manifest
from tools.extract.meshes import extract_meshes
from tools.extract.scenes import extract_scenes
from tools.extract.polygons import extract_polygons
from tools.extract.samples import extract_samples
from tools.extract.strings import extract_strings
from tools.extract.textures import extract_textures
from tools.rom_io import resolve_rom_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract all Sega Rally assets from local ROMs.")
    parser.add_argument("--rom-dir", type=Path, default=None, help="Path to srallyc-b or srallyc-c ROM folder")
    parser.add_argument("--out", type=Path, default=Path("out"), help="Output root directory")
    parser.add_argument("--skip-samples", action="store_true", help="Skip large PCM/WAV export")
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    out = args.out
    print(f"ROM dir: {rom_dir}")
    print(f"Output:  {out.resolve()}\n")

    steps = [
        ("textures", lambda: extract_textures(rom_dir, out / "textures")),
        ("heightmaps", lambda: extract_heightmaps(rom_dir, out / "heightmaps")),
        ("strings", lambda: [extract_strings(rom_dir, out / "strings")]),
        ("labels", lambda: [extract_labels(rom_dir, out / "labels")]),
        ("polygons", lambda: extract_polygons(rom_dir, out / "polygons")),
        ("meshes", lambda: extract_meshes(rom_dir, out / "meshes")),
        ("vehicles", lambda: extract_vehicles(rom_dir, out / "vehicles")),
        ("scenes", lambda: extract_scenes(rom_dir, out / "scenes")),
    ]
    if not args.skip_samples:
        steps.append(("samples", lambda: extract_samples(rom_dir, out / "samples")))

    for name, fn in steps:
        print(f"=== {name} ===")
        result = fn()
        print(f"    {len(result)} file(s)\n")

    asset_index_path = build_asset_index(out)
    print(f"=== asset_index ===\n    {asset_index_path}\n")

    manifest_path = build_manifest(out)
    print(f"=== manifest ===\n    {manifest_path}\n")
    print("Done.")


if __name__ == "__main__":
    main()
