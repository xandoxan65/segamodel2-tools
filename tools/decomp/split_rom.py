#!/usr/bin/env python3
"""Extract layout sections from reference ROM images."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.decomp.layout import iter_image_sections, load_layout, section_bounds
from tools.rom_io import load32_word_region, resolve_rom_dir, write_bytes
from tools.i960_scan import load_maincpu_words


def load_reference_image(
    image_name: str,
    layout: dict,
    rom_dir: Path | None,
    repo_root: Path,
) -> bytes:
    image = layout["images"][image_name]
    ref = repo_root / image["reference"]
    if ref.is_file():
        return ref.read_bytes()
    if image_name == "maincpu":
        raw, _ = load_maincpu_words(resolve_rom_dir(rom_dir))
        return raw
    if image_name == "main_data":
        from tools.rom_io import SRALLY_DATA_ROMS

        return load32_word_region(resolve_rom_dir(rom_dir), SRALLY_DATA_ROMS["main_data"])
    raise ValueError(f"Unknown image {image_name}")


def split_image(
    image_name: str,
    rom: bytes,
    layout: dict,
    decomp_root: Path,
    base_vaddr: int,
) -> list[dict]:
    written: list[dict] = []
    for section in iter_image_sections(layout, image_name):
        start, end = section_bounds(section)
        file_rel = section["file"]
        # Layout uses VMA; convert to file offset for main_data.
        fstart = start - base_vaddr if image_name == "main_data" else start
        fend = end - base_vaddr if image_name == "main_data" else end
        blob = rom[fstart:fend]
        out_path = decomp_root / file_rel
        write_bytes(out_path, blob)
        written.append(
            {
                "image": image_name,
                "name": section["name"],
                "start": section["start"],
                "end": section["end"],
                "bytes": len(blob),
                "file": str(out_path),
            }
        )
    return written


def split_all(
    layout: dict,
    decomp_root: Path,
    rom_dir: Path | None,
    repo_root: Path,
) -> dict:
    results: dict[str, list] = {}
    for image_name, image in layout.get("images", {}).items():
        base = int(str(image["base"]), 0)
        rom = load_reference_image(image_name, layout, rom_dir, repo_root)
        results[image_name] = split_image(image_name, rom, layout, decomp_root, base)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Split reference ROMs into decomp section blobs")
    ap.add_argument("--decomp-root", type=Path, default=Path("decomp"))
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--maincpu-map", type=Path, default=Path("out/i960/section_map.json"))
    ap.add_argument("--main-data-map", type=Path, default=Path("out/i960/section_map_main_data.json"))
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--report", type=Path, default=Path("out/decomp/split_report.json"))
    args = ap.parse_args()

    layout = load_layout(
        args.decomp_root,
        maincpu_map_path=args.maincpu_map,
        main_data_map_path=args.main_data_map,
    )
    results = split_all(layout, args.decomp_root.resolve(), args.rom_dir, args.repo_root.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    total = sum(len(v) for v in results.values())
    print(f"Wrote {total} section blobs → {args.decomp_root}")


if __name__ == "__main__":
    main()
