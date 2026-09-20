#!/usr/bin/env python3
"""Relink decomp section blobs into ROM images and verify against reference dumps."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.layout import iter_image_sections, load_layout, section_bounds
from tools.decomp.split_rom import load_reference_image


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def link_image(
    image_name: str,
    layout: dict,
    decomp_root: Path,
    base_vaddr: int,
    image_size: int,
) -> tuple[bytes, list[dict]]:
    image = bytearray(image_size)
    section_rows: list[dict] = []

    for section in iter_image_sections(layout, image_name):
        start, end = section_bounds(section)
        fstart = start - base_vaddr if image_name == "main_data" else start
        fend = end - base_vaddr if image_name == "main_data" else end
        length = fend - fstart

        fill = section.get("fill")
        file_rel = section.get("file")
        if file_rel:
            blob = (decomp_root / file_rel).read_bytes()
            if len(blob) != length:
                raise ValueError(
                    f"{image_name}/{section['name']}: blob {len(blob)} != expected {length}"
                )
            image[fstart:fend] = blob
        elif fill is not None:
            image[fstart:fend] = bytes([fill & 0xFF]) * length
        else:
            raise ValueError(f"{image_name}/{section['name']}: no file or fill")

        section_rows.append(
            {
                "name": section["name"],
                "start": section["start"],
                "end": section["end"],
                "bytes": length,
                "sha256": sha256(bytes(image[fstart:fend])),
            }
        )

    return bytes(image), section_rows


def verify_all(
    layout: dict,
    decomp_root: Path,
    repo_root: Path,
    rom_dir: Path | None,
) -> dict:
    images_report: dict[str, dict] = {}
    all_ok = True

    for image_name, image in layout.get("images", {}).items():
        base = int(str(image["base"]), 0)
        size = int(str(image["size"]), 0)
        rebuilt, sections = link_image(image_name, layout, decomp_root, base, size)
        ref = load_reference_image(image_name, layout, rom_dir, repo_root)
        match = rebuilt == ref
        all_ok = all_ok and match
        images_report[image_name] = {
            "match": match,
            "size": size,
            "reference_sha256": sha256(ref),
            "rebuilt_sha256": sha256(rebuilt),
            "sections": sections,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": all_ok,
        "images": images_report,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Relink decomp sections and verify ROM identity")
    ap.add_argument("--decomp-root", type=Path, default=Path("decomp"))
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--maincpu-map", type=Path, default=Path("out/i960/section_map.json"))
    ap.add_argument("--main-data-map", type=Path, default=Path("out/i960/section_map_main_data.json"))
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=Path("out/decomp"))
    ap.add_argument("--report", type=Path, default=Path("out/decomp/verify_report.json"))
    args = ap.parse_args()

    layout = load_layout(
        args.decomp_root,
        maincpu_map_path=args.maincpu_map,
        main_data_map_path=args.main_data_map,
    )
    report = verify_all(layout, args.decomp_root.resolve(), args.repo_root.resolve(), args.rom_dir)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for image_name, image_info in report["images"].items():
        rebuilt, _ = link_image(
            image_name,
            layout,
            args.decomp_root.resolve(),
            int(str(layout["images"][image_name]["base"]), 0),
            int(str(layout["images"][image_name]["size"]), 0),
        )
        out_path = args.out_dir / f"{image_name}.rebuilt.bin"
        out_path.write_bytes(rebuilt)

    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    status = "PASS" if report["ok"] else "FAIL"
    print(f"Verify {status} → {args.report}")
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
