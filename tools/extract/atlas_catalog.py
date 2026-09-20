"""Export atlas region catalog: crops from logical sheets + per-region palette.

Regions are **code-identified texel maps** from the placement stream + textures ROM
texheaders — one catalog entry per (patch rect, colorbase, lumabase, cutout, checker).

Re-seed with ``python3 -m tools.extract.atlas_catalog seed``. Optional labels via
``python3 -m tools.extract.atlas_tagger``.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

from tools.extract.texture_verify import _crop_gray, _crop_rgba, _decode_patch_rgba, _write_png
from tools.extract.textures import (
    decode_logical_sheet,
    load_sheet_banks_from_main_data,
)
from tools.i960_memory import TEXTURE_SHEET_BANK0_VADDR, TEXTURE_SHEET_BANK1_VADDR
from tools.model2_catalog import parse_placement_stream
from tools.model2_texture import parse_textured_placement, texture_u16_mask
from tools.model2_texel_map import texel_map_id
from tools.model2_palette import PaletteState, load_palette_from_main_data
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = REPO_ROOT / "catalog" / "atlas_regions.json"
DEFAULT_AUDIT_PATH = REPO_ROOT / "out" / "decomp" / "polygon_palette_audit.json"
BANK_VADDRS = (TEXTURE_SHEET_BANK0_VADDR, TEXTURE_SHEET_BANK1_VADDR)


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "region"


def catalog_labeled_patches(catalog: dict) -> list[dict[str, object]]:
    """Tagged catalog regions as texture_verify-style patch dicts."""
    patches: list[dict[str, object]] = []
    for bank in catalog.get("banks", []):
        sheet_index = int(bank["sheet_index"])
        for region in bank.get("regions", []):
            label = region.get("label")
            if not label:
                continue
            patch: dict[str, object] = {
                "id": str(region.get("id") or _slugify(label)),
                "sheet": sheet_index,
                "x": int(region["x"]),
                "y": int(region["y"]),
                "w": int(region["w"]),
                "h": int(region["h"]),
                "cutout": bool(region.get("cutout")),
                "checker": bool(region.get("checker")),
                "note": f"{label} — catalog tag",
                "catalog_label": label,
                "source": region.get("source", "manual"),
            }
            if region.get("colorbase") is not None:
                patch["colorbase"] = int(region["colorbase"])
                patch["lumabase"] = int(region.get("lumabase") or 0)
            patches.append(patch)
    return patches


def load_catalog(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_catalog_patches(catalog_path: Path = DEFAULT_CATALOG) -> list[dict[str, object]]:
    if not catalog_path.is_file():
        return []
    return catalog_labeled_patches(load_catalog(catalog_path))


def catalog_audit_index_from_report(report: dict[str, object]) -> dict[str, object]:
    """Index polygon_palette_audit catalog_regions for tagger / catalog tools."""
    by_id: dict[str, object] = {}
    by_rect: dict[str, object] = {}
    for entry in report.get("catalog_regions", []):
        if not isinstance(entry, dict):
            continue
        rid = entry.get("id")
        sheet = int(entry["sheet_index"])
        x, y, w, h = int(entry["x"]), int(entry["y"]), int(entry["w"]), int(entry["h"])
        bindings = entry.get("bindings") or []
        best = bindings[0] if bindings else {}
        payload: dict[str, object] = {
            "suggested_colorbase": entry.get("suggested_colorbase"),
            "suggested_lumabase": entry.get("suggested_lumabase"),
            "suggested_cutout": best.get("cutout", False),
            "suggested_checker": best.get("checker", False),
            "placement_hits": entry.get("placement_hits", 0),
            "binding_count": len(bindings),
            "bindings": bindings,
            "uv_flags": entry.get("uv_flags") or {},
        }
        rect_key = f"s{sheet}_x{x}_y{y}_w{w}_h{h}"
        cat_cb = entry.get("catalog_colorbase")
        if cat_cb is not None:
            rect_key += f"_cb{int(cat_cb)}_lb{int(entry.get('catalog_lumabase') or 0)}"
        by_rect[rect_key] = payload
        if rid:
            by_id[str(rid)] = payload
    return {"by_id": by_id, "by_rect": by_rect}


def load_catalog_audit_index(audit_path: Path = DEFAULT_AUDIT_PATH) -> dict[str, object]:
    if not audit_path.is_file():
        return {
            "available": False,
            "by_id": {},
            "by_rect": {},
            "hint": "Click Refresh audit or run: python3 -m tools.decomp.polygon_palette_audit",
        }
    report = json.loads(audit_path.read_text(encoding="utf-8"))
    index = catalog_audit_index_from_report(report)
    return {
        "available": True,
        "course_id": report.get("course_id"),
        "generated_at": report.get("generated_at"),
        "hint": None,
        **index,
    }


def _words_from_bytes(data: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(data) // 4}I", data))


def _geo_region_id(sheet_index: int, x: int, y: int, w: int, h: int) -> str:
    """Legacy rect-only id (deprecated — loses palette binding)."""
    return f"geo_s{sheet_index}_x{x}_y{y}_w{w}_h{h}"


def _texel_map_id(
    sheet_index: int,
    x: int,
    y: int,
    w: int,
    h: int,
    colorbase: int,
    lumabase: int,
    *,
    cutout: bool,
    checker: bool,
) -> str:
    """Deprecated alias — use ``tools.model2_texel_map.texel_map_id``."""
    return texel_map_id(
        sheet_index, x, y, w, h, colorbase, lumabase, cutout=cutout, checker=checker
    )


def collect_placement_texel_maps(rom_dir: Path) -> dict[int, list[dict[str, object]]]:
    """Unique texel maps from placement stream — one entry per texheader patch + binding.

    Sourced from textures ROM texheaders (via ``parse_textured_placement``), not visual
    similarity. Multiple bindings at the same atlas rect become separate catalog regions.
    """
    main = _words_from_bytes(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
    poly = _words_from_bytes(load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"]))
    tex = _words_from_bytes(load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"]))
    placements = parse_placement_stream(main, poly, polygon_rom_mask=len(poly) - 1)
    tex_mask = texture_u16_mask(len(tex))

    by_key: dict[tuple[object, ...], dict[str, object]] = {}
    for placement_index, rec in enumerate(placements):
        col = parse_textured_placement(
            poly,
            tex,
            matrix=rec.matrix,
            rom_offset=rec.rom_offset,
            obc=rec.obc,
            tpa=rec.tpa,
            tha=rec.tha,
            texture_mask=tex_mask,
            collect_audit=True,
        )
        if not col or not col.audit_records:
            continue
        for prim, audit in zip(col.textured_primitives, col.audit_records):
            if prim.patch_w <= 0 or prim.patch_h <= 0:
                continue
            cutout = bool(prim.translucent)
            checker = bool(prim.checker)
            key = (
                prim.sheet_index,
                prim.patch_x,
                prim.patch_y,
                prim.patch_w,
                prim.patch_h,
                prim.colorbase,
                prim.lumabase,
                cutout,
                checker,
            )
            entry = by_key.get(key)
            if entry is None:
                sheet_index = prim.sheet_index
                map_id = prim.texel_map_id or _texel_map_id(
                    sheet_index,
                    prim.patch_x,
                    prim.patch_y,
                    prim.patch_w,
                    prim.patch_h,
                    prim.colorbase,
                    prim.lumabase,
                    cutout=cutout,
                    checker=checker,
                )
                entry = {
                    "id": map_id,
                    "label": None,
                    "x": prim.patch_x,
                    "y": prim.patch_y,
                    "w": prim.patch_w,
                    "h": prim.patch_h,
                    "source": "placement_texheader",
                    "colorbase": prim.colorbase,
                    "lumabase": prim.lumabase,
                    "cutout": cutout,
                    "checker": checker,
                    "usage_count": 0,
                    "example_placement": placement_index,
                    "example_tha": f"0x{rec.tha:08x}",
                    "header_raw": audit.get("header_raw"),
                }
                by_key[key] = entry
            entry["usage_count"] = int(entry["usage_count"]) + 1

    per_sheet: dict[int, list[dict[str, object]]] = {0: [], 1: []}
    for key in sorted(by_key.keys()):
        sheet_index = int(key[0])
        per_sheet[sheet_index].append(by_key[key])
    return per_sheet


def collect_geometry_patch_rects(rom_dir: Path) -> dict[int, list[dict[str, object]]]:
    """Deprecated alias — use :func:`collect_placement_texel_maps`."""
    return collect_placement_texel_maps(rom_dir)


def seed_catalog_from_geometry(
    rom_dir: Path,
    catalog_path: Path,
) -> dict:
    """Replace catalog with placement-stream texheaders (code-identified texel maps)."""
    texel_maps = collect_placement_texel_maps(rom_dir)

    banks = []
    for sheet_index, vaddr in enumerate(BANK_VADDRS):
        regions = list(texel_maps[sheet_index])
        regions.sort(key=lambda r: (int(r["y"]), int(r["x"]), str(r["id"])))
        banks.append(
            {
                "vaddr": f"0x{vaddr:08x}",
                "sheet_index": sheet_index,
                "regions": regions,
            }
        )

    catalog = {
        "version": 1,
        "note": (
            "Code-identified texel maps from placement stream + textures ROM texheaders. "
            "Each region is one (patch rect, colorbase, lumabase) binding. "
            "Re-run seed to refresh; optional labels via atlas tagger."
        ),
        "banks": banks,
    }
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    return {
        "texel_maps_seeded": sum(len(texel_maps[i]) for i in (0, 1)),
        "total_regions": sum(len(b["regions"]) for b in banks),
    }


def _region_patch(region: dict) -> dict[str, object]:
    return {
        "x": int(region["x"]),
        "y": int(region["y"]),
        "w": int(region["w"]),
        "h": int(region["h"]),
        "colorbase": int(region["colorbase"]) if region.get("colorbase") is not None else 0,
        "lumabase": int(region["lumabase"]) if region.get("lumabase") is not None else 0,
        "cutout": bool(region.get("cutout")),
        "checker": bool(region.get("checker")),
    }


def export_catalog(
    rom_dir: Path,
    catalog_path: Path,
    out_dir: Path,
    *,
    course_id: str = "desert",
    scale: int = 4,
) -> Path:
    catalog = load_catalog(catalog_path)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    sheets = load_sheet_banks_from_main_data(main_data)
    palette = load_palette_from_main_data(main_data, course_id=course_id)

    out_dir.mkdir(parents=True, exist_ok=True)
    crops_dir = out_dir / "crops"
    crops_dir.mkdir(exist_ok=True)

    exported: list[dict[str, object]] = []

    for bank in catalog.get("banks", []):
        sheet_index = int(bank["sheet_index"])
        sheet = sheets[sheet_index]
        gray = decode_logical_sheet(sheet)
        vaddr = bank.get("vaddr", f"0x{BANK_VADDRS[sheet_index]:08x}")

        for region in bank.get("regions", []):
            rid = str(region["id"])
            patch = _region_patch(region)
            logical = _crop_gray(gray, **{k: patch[k] for k in ("x", "y", "w", "h")})
            logical_path = crops_dir / f"{rid}_logical.png"
            _write_png(logical_path, logical * 17)

            palette_path: Path | None = None
            if region.get("colorbase") is not None and region.get("lumabase") is not None:
                rgba = _decode_patch_rgba(sheet, palette, patch)
                palette_path = crops_dir / f"{rid}_palette.png"
                _write_png(palette_path, rgba)

            preview_path = crops_dir / f"{rid}_preview.png"
            _write_scaled_preview(logical, palette_path, preview_path, scale=scale)

            exported.append(
                {
                    "id": rid,
                    "label": region.get("label"),
                    "bank_vaddr": vaddr,
                    "sheet_index": sheet_index,
                    "x": patch["x"],
                    "y": patch["y"],
                    "w": patch["w"],
                    "h": patch["h"],
                    "source": region.get("source", "manual"),
                    "colorbase": region.get("colorbase"),
                    "lumabase": region.get("lumabase"),
                    "notes": region.get("notes"),
                    "logical_crop": str(logical_path.relative_to(out_dir)),
                    "palette_crop": str(palette_path.relative_to(out_dir)) if palette_path else None,
                    "preview": str(preview_path.relative_to(out_dir)),
                }
            )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": str(catalog_path.relative_to(REPO_ROOT)),
        "course_id": course_id,
        "region_count": len(exported),
        "regions": exported,
    }
    report_path = out_dir / "catalog_export.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    tagged = export_tagged_gallery(
        rom_dir,
        catalog,
        sheets,
        palette,
        out_dir,
        scale=max(scale * 2, 8),
    )
    report["tagged_count"] = len(tagged)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _write_index_html(out_dir, exported, tagged=tagged)
    return report_path


def export_tagged_gallery(
    rom_dir: Path,
    catalog: dict,
    sheets: tuple[list[int], list[int]],
    palette: PaletteState,
    out_dir: Path,
    *,
    scale: int = 8,
) -> list[dict[str, object]]:
    """8× previews for human-tagged catalog regions only."""
    del rom_dir
    tagged_dir = out_dir / "tagged"
    tagged_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []

    for patch in catalog_labeled_patches(catalog):
        sheet = sheets[int(patch["sheet"])]
        x, y, w, h = int(patch["x"]), int(patch["y"]), int(patch["w"]), int(patch["h"])
        gray = _crop_gray(decode_logical_sheet(sheet), x=x, y=y, w=w, h=h)
        logical_path = tagged_dir / f"{patch['id']}_logical.png"
        _write_png(logical_path, gray * 17)

        preview_path = tagged_dir / f"{patch['id']}_preview_{scale}x.png"
        preview_img = Image.fromarray(gray * 17).resize((w * scale, h * scale), Image.NEAREST)
        preview_img.save(preview_path)

        palette_path: Path | None = None
        if "colorbase" in patch:
            rgba = _decode_patch_rgba(sheet, palette, patch)
            palette_path = tagged_dir / f"{patch['id']}_palette.png"
            _write_png(palette_path, rgba)
            pal_preview = Image.fromarray(rgba).resize((w * scale, h * scale), Image.NEAREST)
            pal_preview.save(tagged_dir / f"{patch['id']}_palette_{scale}x.png")

        rows.append(
            {
                "id": patch["id"],
                "label": patch["catalog_label"],
                "sheet_index": patch["sheet"],
                "x": x,
                "y": y,
                "w": w,
                "h": h,
                "preview": str(preview_path.relative_to(out_dir)),
                "logical_crop": str(logical_path.relative_to(out_dir)),
                "palette_crop": str(palette_path.relative_to(out_dir)) if palette_path else None,
            }
        )

    _write_tagged_html(out_dir, rows, scale=scale)
    return rows


def _write_tagged_html(out_dir: Path, tagged: list[dict[str, object]], *, scale: int) -> None:
    cards = []
    for r in tagged:
        pal_link = (
            f" · <a href='tagged/{Path(r['palette_crop']).name}'>palette</a>"
            if r.get("palette_crop")
            else ""
        )
        cards.append(
            f"<article class='card'>"
            f"<img src='tagged/{Path(r['preview']).name}' alt='{r['label']}' />"
            f"<h2>{r['label']}</h2>"
            f"<p class='meta'>({r['x']},{r['y']}) {r['w']}×{r['h']} · sheet {r['sheet_index']}</p>"
            f"<p class='meta'><code>{r['id']}</code>"
            f" · <a href='tagged/{Path(r['logical_crop']).name}'>logical</a>{pal_link}</p>"
            f"</article>"
        )
    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<title>Tagged atlas regions</title>
<style>
body {{ font: 15px/1.45 system-ui, sans-serif; margin: 1.5rem; background: #141414; color: #eee; max-width: 1200px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.25rem; }}
.card {{ background: #222; padding: 1rem; border-radius: 8px; }}
.card img {{ width: 100%; image-rendering: pixelated; background: #000; }}
h1 {{ margin-top: 0; }}
.meta {{ font-size: 12px; color: #aaa; }}
code {{ color: #9cf; }}
</style></head><body>
<h1>Tagged atlas regions ({scale}×)</h1>
<p class="meta">From <code>catalog/atlas_regions.json</code> — labels you set in the atlas tagger.</p>
<div class="grid">{''.join(cards)}</div>
</body></html>"""
    (out_dir / "tagged.html").write_text(html, encoding="utf-8")


def _write_scaled_preview(
    logical: np.ndarray,
    palette_path: Path | None,
    out_path: Path,
    *,
    scale: int,
) -> None:
    gray = Image.fromarray(logical * 17, mode="L").resize(
        (logical.shape[1] * scale, logical.shape[0] * scale), Image.NEAREST
    )
    if palette_path and palette_path.is_file():
        color = Image.open(palette_path).convert("RGBA").resize(gray.size, Image.NEAREST)
        canvas = Image.new("RGBA", gray.size)
        canvas.paste(color, (0, 0))
        canvas.paste(gray.convert("RGBA"), (gray.width, 0))
        canvas.save(out_path)
    else:
        gray.save(out_path)


def _write_index_html(
    out_dir: Path,
    regions: list[dict[str, object]],
    *,
    tagged: list[dict[str, object]] | None = None,
) -> None:
    def card(r: dict[str, object]) -> str:
        label = r.get("label") or "(untagged)"
        cb = r.get("colorbase")
        lb = r.get("lumabase")
        pal = f"cb{cb} lb{lb}" if cb is not None else "logical only"
        notes_html = f"<p class='note'>{r['notes']}</p>" if r.get("notes") else ""
        preview = r.get("preview", "")
        logical = r.get("logical_crop", "")
        palette = r.get("palette_crop")
        return (
            f"<article class='card'>"
            f"<img src='{preview}' alt='{r['id']}' />"
            f"<h3>{label}</h3>"
            f"<p class='meta'><code>{r['id']}</code> · sheet {r['sheet_index']} · "
            f"({r['x']},{r['y']}) {r['w']}×{r['h']} · {pal}</p>"
            f"<p class='meta'>source: {r.get('source')} · "
            f"<a href='{logical}'>logical</a>"
            + (f" · <a href='{palette}'>palette</a>" if palette else "")
            + "</p>"
            f"{notes_html}"
            f"</article>"
        )

    tagged_section = ""
    if tagged:
        tagged_section = (
            "<h2>Your tags</h2>"
            f"<p class='meta'><a href='tagged.html'>Full tagged gallery</a> "
            f"({len(tagged)} regions)</p><div class='grid'>"
            + "".join(card(r) for r in tagged)
            + "</div><hr />"
        )

    rows = "".join(card(r) for r in regions)
    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<title>Atlas region catalog</title>
<style>
body {{ font: 14px/1.4 system-ui, sans-serif; margin: 1.5rem; background: #1b1b1b; color: #eee; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }}
.card {{ background: #2a2a2a; padding: 0.75rem; border-radius: 6px; }}
.card img {{ max-width: 100%; image-rendering: pixelated; background: #111; }}
.meta {{ font-size: 12px; color: #aaa; }}
.note {{ font-size: 12px; color: #ccc; }}
code {{ color: #9cf; }}
hr {{ border: none; border-top: 1px solid #333; margin: 2rem 0; }}
</style></head><body>
<h1>Atlas region catalog</h1>
<p class="meta">Tagged regions from <code>catalog/atlas_regions.json</code>. Re-run
<code>python -m tools.extract.atlas_catalog export</code> after editing in the tagger.</p>
{tagged_section}
<h2>All regions</h2>
<div class="grid">
{rows}
</div></body></html>"""
    (out_dir / "index.html").write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Atlas region catalog: seed from geometry, export crops")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "out/textures/atlas_catalog")
    parser.add_argument("--course", default="desert")
    parser.add_argument("--scale", type=int, default=4)
    sub = parser.add_subparsers(dest="command")

    seed_p = sub.add_parser(
        "seed",
        help="Replace catalog with placement-stream texheaders (one region per patch+binding)",
    )

    export_p = sub.add_parser("export", help="Export catalog crops and index.html")

    args = parser.parse_args()
    if args.command is None:
        args.command = "export"
    rom_dir = resolve_rom_dir(args.rom_dir)

    if args.command == "seed":
        stats = seed_catalog_from_geometry(rom_dir, args.catalog)
        print(
            f"Wrote {args.catalog}: "
            f"{stats['texel_maps_seeded']} placement_texheader maps "
            f"({stats['total_regions']} total)"
        )
        return

    report = export_catalog(
        rom_dir,
        args.catalog,
        args.out,
        course_id=args.course,
        scale=args.scale,
    )
    print(f"Wrote {report} ({json.loads(report.read_text())['region_count']} regions)")
    print(f"Open {args.out / 'index.html'}")


if __name__ == "__main__":
    main()
