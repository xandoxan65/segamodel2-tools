#!/usr/bin/env python3
"""Per-polygon palette + UV audit from static ROM (placement stream + texheaders).

Walks the full RE-backed placement stream, records every textured primitive's
colorbase/lumabase binding, atlas patch rect, texheader words, and UV path flags.
Surfaces rect-level palette conflicts (same atlas slot, different cb/lb).

No MAME capture — geometry and palette demand come from ROM only.

  python3 -m tools.decomp.polygon_palette_audit --course desert
  ./build polygon-audit
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from tools.extract.atlas_catalog import (
    DEFAULT_AUDIT_PATH,
    DEFAULT_CATALOG,
    catalog_audit_index_from_report,
    load_catalog,
    load_catalog_audit_index,
)
from tools.extract.textures import get_texel, load_sheet_banks_from_main_data
from tools.model2_catalog import parse_placement_stream
from tools.model2_cgm import CgmReplayState, missing_colorbase_slots, replay_course_cgm_blocks
from tools.model2_palette import (
    COURSE_CGM_VADDRS_BY_ID,
    PaletteState,
    find_cgm_blocks,
    load_palette_from_main_data,
)
from tools.model2_texture import (
    LOGICAL_SHEET_H,
    LOGICAL_SHEET_W,
    parse_textured_placement,
    texture_u16_mask,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]


def _words(raw: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def _uv_to_logical(u: float, v: float) -> tuple[int, int]:
    lx = int(u * LOGICAL_SHEET_W) % LOGICAL_SHEET_W
    ly = int((1.0 - v) * LOGICAL_SHEET_H) % LOGICAL_SHEET_H
    return lx, ly


def _corner_texels(
    sheet_words: list[int],
    uvs: list[list[float]],
) -> list[int]:
    texels: list[int] = []
    for u, v in uvs:
        lx, ly = _uv_to_logical(u, v)
        texels.append(get_texel(sheet_words, 0, 0, lx, ly))
    return texels


def collect_polygon_audit_rows(
    rom_dir: Path,
    *,
    course_id: str = "desert",
) -> list[dict[str, object]]:
    main = _words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
    poly = _words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"]))
    tex = _words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"]))
    tex_mask = texture_u16_mask(len(tex))
    placements = parse_placement_stream(main, poly, polygon_rom_mask=len(poly) - 1)
    sheets = load_sheet_banks_from_main_data(
        load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    )

    all_rows: list[dict[str, object]] = []
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
            row: dict[str, object] = {
                "placement_index": placement_index,
                "oba": rec.oba,
                "tpa": rec.tpa,
                "tha": rec.tha,
                "poly_verts": list(prim.indices),
                "sheet_index": prim.sheet_index,
                "patch_x": prim.patch_x,
                "patch_y": prim.patch_y,
                "patch_w": prim.patch_w,
                "patch_h": prim.patch_h,
                "colorbase": prim.colorbase,
                "lumabase": prim.lumabase,
                "texel_map_id": prim.texel_map_id,
                "translucent": prim.translucent,
                "checker": prim.checker,
                "renderer": prim.renderer,
                **audit,
            }
            uvs = row.get("uvs")
            if isinstance(uvs, list) and uvs:
                row["corner_texels"] = _corner_texels(sheets[prim.sheet_index], uvs)
            all_rows.append(row)
    return all_rows


def summarize_palette_conflicts(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Group by atlas patch rect; list distinct palette bindings."""
    by_rect: dict[tuple[int, int, int, int, int], Counter] = defaultdict(Counter)
    examples: dict[tuple[int, int, int, int, int], dict[tuple, int]] = defaultdict(dict)

    for row in rows:
        if int(row.get("patch_w") or 0) <= 0:
            continue
        rect = (
            int(row["sheet_index"]),
            int(row["patch_x"]),
            int(row["patch_y"]),
            int(row["patch_w"]),
            int(row["patch_h"]),
        )
        binding = (
            int(row["colorbase"]),
            int(row["lumabase"]),
            bool(row.get("translucent")),
            bool(row.get("checker")),
        )
        by_rect[rect][binding] += 1
        if binding not in examples[rect]:
            examples[rect][binding] = int(row["placement_index"])

    conflicts: list[dict[str, object]] = []
    for rect, combos in sorted(by_rect.items(), key=lambda kv: -sum(kv[1].values())):
        if len(combos) <= 1:
            continue
        sheet, x, y, w, h = rect
        bindings = []
        for (cb, lb, cutout, checker), count in combos.most_common():
            bindings.append(
                {
                    "colorbase": cb,
                    "lumabase": lb,
                    "cutout": cutout,
                    "checker": checker,
                    "poly_count": count,
                    "example_placement": examples[rect][(cb, lb, cutout, checker)],
                }
            )
        conflicts.append(
            {
                "sheet_index": sheet,
                "patch_x": x,
                "patch_y": y,
                "patch_w": w,
                "patch_h": h,
                "binding_count": len(bindings),
                "poly_count": sum(combos.values()),
                "bindings": bindings,
            }
        )
    return conflicts


def summarize_slot_demand(
    rows: list[dict[str, object]],
    main_data: bytes,
    *,
    course_id: str,
) -> dict[str, object]:
    cb_counts: Counter[int] = Counter()
    lb_counts: Counter[int] = Counter()
    for row in rows:
        cb_counts[int(row["colorbase"])] += 1
        lb_counts[int(row["lumabase"])] += 1

    needed = set(cb_counts.keys())
    vaddrs = set(COURSE_CGM_VADDRS_BY_ID.get(course_id, ()))
    blocks = tuple(b for b in find_cgm_blocks(main_data) if b.vaddr in vaddrs)
    replay = replay_course_cgm_blocks(PaletteState.with_defaults(), main_data, blocks)
    missing = missing_colorbase_slots(replay, needed)

    return {
        "unique_colorbases": len(cb_counts),
        "unique_lumabases": len(lb_counts),
        "top_colorbases": cb_counts.most_common(20),
        "top_lumabases": lb_counts.most_common(12),
        "missing_colorbase_slots": missing,
        "attr_fallback_polys": sum(1 for r in rows if r.get("palette_from_attr")),
        "lumabase_heuristic_polys": sum(1 for r in rows if r.get("lumabase_heuristic")),
        "billboard_path_polys": sum(1 for r in rows if r.get("billboard_path")),
    }


def match_catalog_regions(
    rows: list[dict[str, object]],
    catalog_path: Path,
) -> list[dict[str, object]]:
    """Attach palette binding histograms to tagged catalog regions."""
    if not catalog_path.is_file():
        return []
    catalog = load_catalog(catalog_path)
    matched: list[dict[str, object]] = []

    for bank in catalog.get("banks", []):
        sheet_index = int(bank["sheet_index"])
        for region in bank.get("regions", []):
            rx, ry = int(region["x"]), int(region["y"])
            rw, rh = int(region["w"]), int(region["h"])
            label = region.get("label")
            display = label or str(region.get("id"))
            bindings: Counter[tuple[int, int, bool, bool]] = Counter()
            uv_flags = Counter()

            for row in rows:
                if int(row["sheet_index"]) != sheet_index:
                    continue
                px, py = int(row["patch_x"]), int(row["patch_y"])
                if px != rx or py != ry:
                    continue
                pw, ph = int(row["patch_w"]), int(row["patch_h"])
                if pw != rw or ph != rh:
                    continue
                row_cb = int(row["colorbase"])
                row_lb = int(row["lumabase"])
                row_cut = bool(row.get("translucent"))
                row_chk = bool(row.get("checker"))
                cat_cb = region.get("colorbase")
                cat_lb = region.get("lumabase")
                if cat_cb is not None and row_cb != int(cat_cb):
                    continue
                if cat_lb is not None and row_lb != int(cat_lb):
                    continue
                if "cutout" in region and row_cut != bool(region["cutout"]):
                    continue
                if "checker" in region and row_chk != bool(region["checker"]):
                    continue
                binding = (row_cb, row_lb, row_cut, row_chk)
                bindings[binding] += 1
                if row.get("billboard_path"):
                    uv_flags["billboard"] += 1
                if row.get("palette_from_attr"):
                    uv_flags["attr_fallback"] += 1
                if row.get("lumabase_heuristic"):
                    uv_flags["lumabase_heuristic"] += 1

            entry: dict[str, object] = {
                "id": region.get("id"),
                "label": label,
                "display": display,
                "sheet_index": sheet_index,
                "x": rx,
                "y": ry,
                "w": rw,
                "h": rh,
                "catalog_colorbase": region.get("colorbase"),
                "catalog_lumabase": region.get("lumabase"),
                "placement_hits": sum(bindings.values()),
                "bindings": [
                    {
                        "colorbase": cb,
                        "lumabase": lb,
                        "cutout": co,
                        "checker": ch,
                        "poly_count": n,
                    }
                    for (cb, lb, co, ch), n in bindings.most_common()
                ],
                "uv_flags": dict(uv_flags),
            }
            if bindings:
                best = bindings.most_common(1)[0][0]
                entry["suggested_colorbase"] = best[0]
                entry["suggested_lumabase"] = best[1]
            matched.append(entry)
    return matched


def _write_conflicts_html(out_path: Path, conflicts: list[dict[str, object]]) -> None:
    cards = []
    for c in conflicts[:40]:
        bindings = c.get("bindings", [])
        bind_lines = "<br>".join(
            f"cb{b['colorbase']} lb{b['lumabase']}"
            + (" cutout" if b.get("cutout") else "")
            + (f" ({b['poly_count']} polys)" if b.get("poly_count") else "")
            for b in bindings
        )
        cards.append(
            f"<article class='card'>"
            f"<h3>sheet {c['sheet_index']} ({c['patch_x']},{c['patch_y']}) "
            f"{c['patch_w']}×{c['patch_h']}</h3>"
            f"<p>{c['binding_count']} bindings · {c['poly_count']} polys total</p>"
            f"<p class='meta'>{bind_lines}</p></article>"
        )
    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<title>Palette conflicts</title>
<style>
body {{ font: 14px system-ui; margin: 1.5rem; background: #1a1a1a; color: #eee; max-width: 900px; }}
.card {{ background: #2a2a2a; padding: 1rem; margin-bottom: 1rem; border-radius: 6px; }}
.meta {{ font-family: ui-monospace, monospace; color: #9cf; font-size: 13px; }}
</style></head><body>
<h1>Atlas rects with multiple palette bindings</h1>
<p>From full placement-stream audit. Same atlas rect can host multiple texel maps (distinct palette bindings).</p>
{''.join(cards) if cards else '<p>No conflicts found.</p>'}
</body></html>"""
    out_path.write_text(html, encoding="utf-8")


def build_polygon_palette_audit(
    rom_dir: Path,
    out_dir: Path,
    *,
    course_id: str = "desert",
    catalog_path: Path = DEFAULT_CATALOG,
    max_rows: int | None = None,
) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = collect_polygon_audit_rows(rom_dir, course_id=course_id)
    if max_rows is not None:
        rows = rows[:max_rows]

    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    load_palette_from_main_data(main_data, course_id=course_id)

    conflicts = summarize_palette_conflicts(rows)
    slot_demand = summarize_slot_demand(rows, main_data, course_id=course_id)
    catalog_matches = match_catalog_regions(rows, catalog_path)

    report: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "course_id": course_id,
        "source": "placement_stream @ 0x02867C20 + textures ROM texheaders",
        "polygon_rows": len(rows),
        "placement_stream_polys": len(rows),
        "conflict_rect_count": len(conflicts),
        "cgm_vaddrs": [f"0x{v:08x}" for v in COURSE_CGM_VADDRS_BY_ID.get(course_id, ())],
        "slot_demand": slot_demand,
        "top_conflicts": conflicts[:30],
        "catalog_regions": catalog_matches,
        "notes": [
            "Each row = one textured primitive with cb/lb from texheader + attr fallback.",
            "conflicts = same (sheet, patch rect) with multiple (cb, lb) bindings.",
            "catalog_regions.placement_hits=0 → UI art or non-placement draw path.",
            "Fix colors: CGM slot fill + correct per-poly cb/lb. Fix texels: UV path RE (0x29C10 tp templates).",
        ],
    }

    (out_dir / "polygon_palette_audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "palette_conflicts.json").write_text(
        json.dumps(conflicts, indent=2) + "\n", encoding="utf-8"
    )
    if rows:
        (out_dir / "polygon_rows.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n",
            encoding="utf-8",
        )
    _write_conflicts_html(out_dir / "palette_conflicts.html", conflicts)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Per-polygon palette + UV audit from static ROM (no MAME capture)."
    )
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "out/decomp")
    parser.add_argument("--course", default="desert")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--max-rows", type=int, default=None, help="Debug: cap output rows")
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    report = build_polygon_palette_audit(
        rom_dir,
        args.out,
        course_id=args.course,
        catalog_path=args.catalog,
        max_rows=args.max_rows,
    )
    sd = report.get("slot_demand", {})
    print(f"Polygon palette audit ({args.course})")
    print(f"  Rows: {report['polygon_rows']}")
    print(f"  Conflict rects: {report['conflict_rect_count']}")
    print(f"  Unique colorbases: {sd.get('unique_colorbases')}")
    print(f"  Missing CGM slots: {len(sd.get('missing_colorbase_slots', []))}")
    print(f"  Attr-fallback polys: {sd.get('attr_fallback_polys')}")
    print(f"  Billboard UV path: {sd.get('billboard_path_polys')}")
    manual = [
        r
        for r in report.get("catalog_regions", [])
        if r.get("label")
    ]
    manual_hits = sum(1 for r in manual if r.get("placement_hits"))
    code_maps = [
        r
        for r in report.get("catalog_regions", [])
        if str(r.get("id", "")).startswith("tex_")
    ]
    code_hits = sum(1 for r in code_maps if r.get("placement_hits"))
    print(f"  Manual tags with placement hits: {manual_hits}/{len(manual)}")
    print(f"  Code-identified texel maps with hits: {code_hits}/{len(code_maps)}")
    print(f"  Wrote {args.out / 'polygon_palette_audit.json'}")
    print(f"  Gallery: {args.out / 'palette_conflicts.html'}")


if __name__ == "__main__":
    main()
