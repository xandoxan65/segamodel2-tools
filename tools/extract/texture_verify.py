"""Phase 1 texture verification: decode ROM sheets to PNG and crop known art regions.

Run before testing UV mapping in the viewer. Outputs live under out/textures/verify/.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

from tools.extract.textures import (
    decode_colored_logical_sheet,
    decode_logical_indices,
    decode_logical_sheet,
    extract_textures,
    load_sheet_banks_from_main_data,
)
from tools.model2_palette import PaletteState, load_palette_from_main_data
from tools.obj_export import palette_material_name
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

# Texheader-derived atlas slots (tools/model2_texture.py resolve_uv_header / texx/texy).
REFERENCE_PATCHES: tuple[dict[str, object], ...] = (
    {
        "id": "border_logo",
        "sheet": 0,
        "x": 1152,
        "y": 160,
        "w": 64,
        "h": 64,
        "colorbase": 0x007,
        "lumabase": 0x080,
        "cutout": False,
        "checker": False,
        "note": "Border billboard logo — texx=1152 texy=160 (64×64)",
    },
    {
        "id": "tree_foliage",
        "sheet": 0,
        "x": 640,
        "y": 416,
        "w": 64,
        "h": 128,
        "colorbase": 0x007,
        "lumabase": 0x080,
        "cutout": True,
        "checker": True,
        "note": "Trefoil tree cutout — texx=640 texy=416 (64×128, checker _tr)",
    },
    {
        "id": "road_surface",
        "sheet": 0,
        "x": 768,
        "y": 640,
        "w": 128,
        "h": 64,
        "colorbase": 0x007,
        "lumabase": 0x080,
        "cutout": False,
        "checker": False,
        "note": "Road surface patch (cb7, typical desert track)",
    },
)

UI_COURSES = ("desert", "forest", "mountain", "championship")
PREVIEW_SCALE = 8

DESERT_SAMPLE_VARIANTS: tuple[tuple[int, int, int, bool], ...] = (
    (0, 0x007, 0x080, False),
    (0, 0x007, 0x080, True),
    (0, 0x128, 0x080, True),
    (0, 0x001, 0x000, False),
)


def _sheet_diagnosis(words: list[int]) -> dict[str, float]:
    gray = decode_logical_sheet(words)
    return {
        "zero_fraction": float((gray == 0).mean()),
        "unique_gray": float(len(np.unique(gray))),
        "std": float(gray.std()),
    }


def _load_texture_sheets(rom_dir: Path) -> tuple[list[int], list[int]]:
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    return load_sheet_banks_from_main_data(main_data)


def _crop_rgba(rgba: np.ndarray, *, x: int, y: int, w: int, h: int) -> np.ndarray:
    return rgba[y : y + h, x : x + w].copy()


def _crop_gray(gray: np.ndarray, *, x: int, y: int, w: int, h: int) -> np.ndarray:
    return gray[y : y + h, x : x + w].copy()


def _patch_stats(rgba: np.ndarray) -> dict[str, object]:
    flat = rgba.reshape(-1, rgba.shape[-1])
    unique = {tuple(row) for row in flat}
    alpha = flat[:, 3] if rgba.shape[-1] == 4 else None
    return {
        "unique_colors": len(unique),
        "size": [int(rgba.shape[1]), int(rgba.shape[0])],
        "alpha_nonzero_fraction": float((alpha > 0).mean()) if alpha is not None else 1.0,
    }


def _write_png(path: Path, array: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(array).save(path)


def _gallery_href(verify_dir: Path, path: Path) -> str:
    return Path(os_path_relpath(path, verify_dir)).as_posix()


def os_path_relpath(path: Path, start: Path) -> str:
    import os

    return os.path.relpath(path.resolve(), start.resolve())


def _decode_patch_rgba(sheet: list[int], palette: PaletteState, patch: dict[str, object]) -> np.ndarray:
    return _crop_rgba(
        decode_colored_logical_sheet(
            sheet,
            palette,
            colorbase=int(patch["colorbase"]),
            lumabase=int(patch["lumabase"]),
            cutout_transparent=bool(patch.get("cutout")),
            checker_cutout=bool(patch.get("checker")),
        ),
        x=int(patch["x"]),
        y=int(patch["y"]),
        w=int(patch["w"]),
        h=int(patch["h"]),
    )


def _export_patches(
    sheets: tuple[list[int], list[int]],
    palette: PaletteState,
    out_dir: Path,
    patches: tuple[dict[str, object], ...] | list[dict[str, object]],
    *,
    subdir: str = "",
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for patch in patches:
        sheet_index = int(patch["sheet"])
        sheet = sheets[sheet_index]
        x, y, w, h = int(patch["x"]), int(patch["y"]), int(patch["w"]), int(patch["h"])
        prefix = f"{subdir}/" if subdir else ""
        patch_id = str(patch["id"])

        indices = decode_logical_indices(sheet)
        idx_crop = _crop_gray(indices, x=x, y=y, w=w, h=h)
        idx_path = out_dir / "patches" / f"{prefix}{patch_id}_indices.png"
        _write_png(idx_path, idx_crop * 17)

        paths: dict[str, str] = {
            "indices": _gallery_href(out_dir, idx_path),
        }
        stats: dict[str, object]

        if "colorbase" in patch:
            colored = _decode_patch_rgba(sheet, palette, patch)
            preview_path = out_dir / "preview" / f"{prefix}{patch_id}_8x.png"
            preview_img = Image.fromarray(colored).resize(
                (w * PREVIEW_SCALE, h * PREVIEW_SCALE), Image.NEAREST
            )
            _write_png(preview_path, np.array(preview_img))
            patch_path = out_dir / "patches" / f"{prefix}{patch_id}_palette.png"
            _write_png(patch_path, colored)
            paths["preview_8x"] = _gallery_href(out_dir, preview_path)
            paths["palette"] = _gallery_href(out_dir, patch_path)
            stats = _patch_stats(colored)
        else:
            preview_path = out_dir / "preview" / f"{prefix}{patch_id}_8x.png"
            preview_img = Image.fromarray(idx_crop * 17).resize(
                (w * PREVIEW_SCALE, h * PREVIEW_SCALE), Image.NEAREST
            )
            _write_png(preview_path, np.array(preview_img))
            paths["preview_8x"] = _gallery_href(out_dir, preview_path)
            stats = {"unique_colors": int(len(np.unique(idx_crop))), "palette": "indices_only"}

        rows.append({**patch, "paths": paths, "stats": stats})
    return rows


def _export_course_palette_samples(
    sheets: tuple[list[int], list[int]],
    palette: PaletteState,
    course_id: str,
    out_dir: Path,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    variants = DESERT_SAMPLE_VARIANTS if course_id == "desert" else DESERT_SAMPLE_VARIANTS[:2]
    for sheet_index, colorbase, lumabase, cutout in variants:
        name = palette_material_name(
            sheet_index,
            colorbase,
            lumabase,
            translucent=cutout,
            checker=cutout,
        )
        rgba = decode_colored_logical_sheet(
            sheets[sheet_index],
            palette,
            colorbase=colorbase,
            lumabase=lumabase,
            cutout_transparent=cutout,
            checker_cutout=cutout,
        )
        rel = f"palette_samples/{name}.png"
        path = out_dir / rel
        _write_png(path, rgba)
        rows.append(
            {
                "material": name,
                "sheet": sheet_index,
                "colorbase": colorbase,
                "lumabase": lumabase,
                "cutout": cutout,
                "gallery_src": _gallery_href(out_dir, path),
                "stats": _patch_stats(rgba),
            }
        )
    return rows


def _write_gallery_html(out_dir: Path, report: dict[str, object]) -> Path:
    html_path = out_dir / "index.html"
    sections: list[str] = []

    def img_block(title: str, src: str, meta: str = "") -> str:
        return (
            f'<figure><img src="{src}" alt="{title}" loading="lazy" />'
            f"<figcaption><strong>{title}</strong>"
            + (f"<br /><span class='meta'>{meta}</span>" if meta else "")
            + "</figcaption></figure>"
        )

    catalog_patches = report.get("catalog_patches", [])
    if catalog_patches:
        sections.append("<h2>Tagged catalog regions (8×)</h2>")
        sections.append(
            "<p class='hint'>From <code>catalog/atlas_regions.json</code> — labels set in the atlas tagger. "
            "UI/menu art without colorbase shows logical indices only.</p>"
        )
        sections.append("<div class='grid preview-grid'>")
        for patch in catalog_patches:
            src = patch.get("paths", {}).get("preview_8x")
            if src:
                title = str(patch.get("catalog_label") or patch["id"])
                sections.append(
                    img_block(
                        title,
                        str(src),
                        str(patch.get("note", "")),
                    )
                )
        sections.append("</div>")

    patches = report.get("patches", [])
    if patches:
        sections.append("<h2>Reference atlas patches (8×)</h2>")
        sections.append(
            "<p class='hint'>Geometry-linked desert slots tinted with palette "
            "(cb7 / lumabase 128). Zoomed 8× with nearest-neighbour.</p>"
        )
        sections.append("<div class='grid preview-grid'>")
        for patch in patches:
            src = patch.get("paths", {}).get("preview_8x")
            if src:
                sections.append(
                    img_block(
                        str(patch["id"]),
                        str(src),
                        str(patch.get("note", "")),
                    )
                )
        sections.append("</div>")

    samples = report.get("palette_samples", [])
    if samples:
        sections.append("<h2>Full sheets — palette tinted (not gray indices)</h2>")
        sections.append(
            "<p class='hint'>Sparse 2048×1024 atlas: mostly empty/black; art lives in small patches. "
            "Do <em>not</em> judge decode quality from the gray index sheets.</p>"
        )
        sections.append("<div class='grid'>")
        for sample in samples[:4]:
            sections.append(
                img_block(
                    str(sample["material"]),
                    str(sample["gallery_src"]),
                    json.dumps(sample["stats"]),
                )
            )
        sections.append("</div>")

    for sheet in report.get("sheets", []):
        prefix = f"sheet{sheet['sheet']}"
        sections.append(f"<h2>{prefix} — raw index map (debug only)</h2>")
        sections.append(
            "<p class='warn'>16-level grayscale = 4-bit texel indices × 17. "
            "This will look like TV static, not game art.</p>"
        )
        sections.append("<div class='grid'>")
        gray = sheet.get("logical_gray", {})
        if gray.get("gallery_src"):
            sections.append(img_block(gray["label"], gray["gallery_src"], gray.get("path", "")))
        cb0 = sheet.get("logical_palette_cb0", {})
        if cb0.get("gallery_src"):
            sections.append(img_block(cb0["label"], cb0["gallery_src"], cb0.get("path", "")))
        sections.append("</div>")

    blocked = report.get("blocked_reason")
    status_banner = (
        f"<div class=\"err\"><strong>Phase 1 blocked:</strong> {blocked}</div>"
        if blocked
        else f"<p class=\"hint\">Phase 1 decode OK — texel sheets from main_data "
        f"(status: <code>{report.get('phase1_status', 'unknown')}</code>).</p>"
    )
    body = "\n".join(sections)
    html_path.write_text(
        f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8" />
<title>Texture verify — {report.get("course_id", "all")}</title>
<style>
body {{ font: 14px/1.4 system-ui, sans-serif; margin: 1.5rem; max-width: 1200px; background: #1b1b1b; color: #eee; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }}
.preview-grid figure {{ max-width: 360px; }}
figure {{ margin: 0; background: #2a2a2a; padding: 0.5rem; border-radius: 4px; }}
img {{ width: 100%; height: auto; image-rendering: pixelated; background: #111; }}
.meta, code {{ font-size: 11px; word-break: break-word; color: #bbb; }}
.hint {{ color: #aaa; }}
.warn {{ color: #f5c542; }}
.err {{ color: #f88; border: 1px solid #a44; background: #2a1515; padding: 0.75rem 1rem; border-radius: 4px; }}
</style></head><body>
<h1>Texture verify — {report.get("course_id", "all")}</h1>
{status_banner}
<p><code>python3 -m tools.extract.texture_verify --course {report.get("course_id", "desert")}</code></p>
<ul>
  <li>Texel source: main_data @ 0x02200000 / 0x02400000 (upload via maincpu 0x003940)</li>
  <li>Status: <code>{report.get("phase1_status", "unknown")}</code></li>
</ul>
{body}
</body></html>""",
        encoding="utf-8",
    )
    return html_path


def build_verify_report(
    rom_dir: Path,
    out_root: Path,
    *,
    course_id: str = "desert",
    refresh_base_sheets: bool = False,
) -> dict[str, object]:
    """Decode textures and write verification PNGs + manifest."""
    verify_dir = out_root / "verify" / course_id
    verify_dir.mkdir(parents=True, exist_ok=True)

    textures_dir = out_root
    if refresh_base_sheets or not (textures_dir / "sheet0_logical_2048x1024.png").is_file():
        extract_textures(rom_dir, textures_dir)

    sheets = _load_texture_sheets(rom_dir)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    palette = load_palette_from_main_data(main_data)

    sheet_rows = []
    for index, prefix in enumerate(("sheet0", "sheet1")):
        gray_path = textures_dir / f"{prefix}_logical_2048x1024.png"
        cb0_path = textures_dir / f"{prefix}_logical_2048x1024_palette_cb0.png"
        sheet_rows.append(
            {
                "sheet": index,
                "logical_gray": {
                    "label": f"{prefix} index map (16 gray levels)",
                    "path": gray_path.relative_to(out_root).as_posix(),
                    "gallery_src": _gallery_href(verify_dir, gray_path),
                },
                "logical_palette_cb0": {
                    "label": f"{prefix} palette cb0 (sparse atlas)",
                    "path": cb0_path.relative_to(out_root).as_posix(),
                    "gallery_src": _gallery_href(verify_dir, cb0_path),
                },
            }
        )

    patches = _export_patches(sheets, palette, verify_dir, REFERENCE_PATCHES)
    from tools.extract.atlas_catalog import load_catalog_patches

    catalog_patches = _export_patches(
        sheets,
        palette,
        verify_dir,
        load_catalog_patches(),
        subdir="catalog",
    )
    palette_samples = _export_course_palette_samples(sheets, palette, course_id, verify_dir)

    rom_diag = [_sheet_diagnosis(s) for s in sheets]
    phase1_status = "main_data_decode"

    report: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "course_id": course_id,
        "phase": 1,
        "phase1_status": phase1_status,
        "texel_source": {
            "bank0_vaddr": "0x02200000",
            "bank1_vaddr": "0x02400000",
            "upload_fn": "0x003940",
            "metadata_rom": "mpr-17752/mpr-17753 (textures region — tp/th only)",
        },
        "blocked_reason": None,
        "next_steps": [
            "Phase 2: fix UV export degeneracies and bind atlas in viewer",
            "Palette/CGM RE for correct per-material colors (parallel track)",
        ],
        "rom_sheet_diagnosis": rom_diag,
        "notes": {
            "gray_sheet": (
                "16-level grayscale = 4-bit texel indices × 17. "
                "Sheets are decoded from main_data, not textures ROM."
            ),
        },
        "sheets": sheet_rows,
        "patches": patches,
        "catalog_patches": catalog_patches,
        "palette_samples": palette_samples,
        "viewer": {
            "gallery": f"textures/verify/{course_id}/index.html",
            "phase2_uv_atlas": "Viewer display mode: UV atlas (geometry mapping only)",
            "phase2_palette": "Viewer display mode: Textured (per-material palette cache)",
        },
    }

    manifest_path = verify_dir / "verify.json"
    manifest_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_gallery_html(verify_dir, report)
    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 1: decode texture ROM to PNG and write visual verification gallery."
    )
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("out/textures"))
    parser.add_argument("--course", choices=UI_COURSES, default="desert")
    parser.add_argument(
        "--refresh-sheets",
        action="store_true",
        help="Re-decode base sheet0/sheet1 PNGs before building verify gallery",
    )
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    report = build_verify_report(
        rom_dir,
        args.out.resolve(),
        course_id=args.course,
        refresh_base_sheets=args.refresh_sheets,
    )
    gallery = (args.out / "verify" / args.course / "index.html").resolve()
    gray = (args.out / "sheet0_logical_2048x1024.png").resolve()
    print(f"Phase 1 verify written for {args.course}")
    print(f"  Gallery (open this): {gallery}")
    print(f"  Viewer URL: http://localhost:5173/textures/verify/{args.course}/index.html")
    print(f"  Patches: {len(report['patches'])} reference + {len(report.get('catalog_patches', []))} catalog")
    print(f"  Phase 1 status: {report.get('phase1_status')}")
    if report.get("blocked_reason"):
        print()
        print(f"  BLOCKED: {report['blocked_reason']}")
    else:
        print("  Texel sheets: main_data @ 0x02200000 / 0x02400000")
        print(f"  Gray atlas: {gray}")


if __name__ == "__main__":
    main()
