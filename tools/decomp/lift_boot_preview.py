#!/usr/bin/env python3
"""Build a viewable preview from decomp_lift --viewer boot output.

Reads I960_PALETTE_DUMP (+ optional geo FIFO bins) and writes PNGs plus a
small HTML page you can open in a browser. Full 3D replay uses the Three.js
viewer with exported OBJs (``make lift-viewer``); this script is the fast path
to *see* lifted palette state without MAME.

Usage:

  cd decomp && make lift-boot-preview
  open ../out/lift/boot_preview/index.html
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_inspect(*, dump: Path, out: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.decomp.lift_palette_inspect",
            "--dump",
            str(dump),
            "-o",
            str(out),
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def _sys24_framebuffer_png(dump: Path, out: Path) -> Path | None:
    """Convert C lift sys24_framebuffer.ppm → PNG for HTML preview."""
    ppm = dump / "sys24_framebuffer.ppm"
    if not ppm.is_file():
        return None
    png = out / "sys24_framebuffer.png"
    try:
        from PIL import Image
    except ImportError:
        subprocess.run(
            ["sips", "-s", "format", "png", str(ppm), "--out", str(png)],
            check=False,
            capture_output=True,
        )
        return png if png.is_file() else None
    with Image.open(ppm) as img:
        img.save(png)
    return png


def _write_index_html(
    out: Path, *, dump: Path, prg: Path | None, copro: Path | None, sys24_png: Path | None
) -> None:
    report_path = out / "lift_palette.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    cb = report.get("colorbase", {})
    fifo_lines = []
    if prg and prg.is_file():
        fifo_lines.append(f"<li>prg_fifo: {prg.name} ({prg.stat().st_size} bytes)</li>")
    if copro and copro.is_file():
        fifo_lines.append(f"<li>copro_fifo: {copro.name} ({copro.stat().st_size} bytes)</li>")
    fifo_html = "\n".join(fifo_lines) if fifo_lines else "<li>(no FIFO dumps — set I960_GEO_DUMP / I960_COPRO_DUMP)</li>"

    if sys24_png:
        sys24_img_html = f'<img src="{sys24_png.name}" alt="sys24 framebuffer" />'
    else:
        sys24_img_html = (
            '<p class="meta">(no sys24_framebuffer.ppm — rebuild decomp_lift with sys24_tile)</p>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Lift boot preview</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 1.5rem; background: #1a1a1a; color: #eee; }}
    img {{ max-width: 100%; image-rendering: pixelated; border: 1px solid #444; }}
    h2 {{ margin-top: 2rem; }}
    a {{ color: #8cf; }}
    .meta {{ color: #aaa; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>Lift boot preview</h1>
  <p class="meta">Palette dump: <code>{dump}</code></p>
  <p>Nonzero palram words: {report.get("palram_nonzero_words", "?")} —
     colorbase slots: {cb.get("nonzero_slots", "?")} / {cb.get("slots_checked", "?")}</p>
  <ul>{fifo_html}</ul>
  <p>For textured 3D geometry, use the main viewer after <code>make lift-viewer</code>
     (track mesh + lift palette). Attract-screen OBJ export is not wired yet.</p>
  <p><a href="../../../viewer/">Open Three.js viewer</a> (run <code>cd viewer && npm run dev</code> first)</p>

  <h2>Upload palette (gamma strip)</h2>
  <img src="lift_palram_gamma.png" alt="palram gamma" />

  <h2>Colorbase slots</h2>
  <img src="lift_colorbase_slots.png" alt="colorbase grid" />

  <h2>System-24 framebuffer (C tile chip, lifted RAM)</h2>
  {sys24_img_html}

  <h2>Tile layer 0 (legacy Python preview)</h2>
  <img src="lift_tile_layer0.png" alt="tile layer" />
</body>
</html>
"""
    (out / "index.html").write_text(html, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dump",
        type=Path,
        default=REPO_ROOT / "decomp/build/lift/boot_palette",
        help="I960_PALETTE_DUMP directory from decomp_lift --viewer boot",
    )
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        default=REPO_ROOT / "out/lift/boot_preview",
        help="preview output (PNGs + index.html)",
    )
    ap.add_argument("--prg", type=Path, default=None, help="optional prg_fifo .bin")
    ap.add_argument("--copro", type=Path, default=None, help="optional copro_fifo .bin")
    args = ap.parse_args()

    dump = args.dump.resolve()
    out = args.out.resolve()
    if not dump.is_dir():
        raise SystemExit(f"palette dump missing: {dump} (run: cd decomp && make lift-boot-preview)")

    prg = args.prg or dump.parent / "boot_prg.bin"
    copro = args.copro or dump.parent / "boot_copro.bin"
    if not prg.is_file():
        prg = None
    if not copro.is_file():
        copro = None

    out.mkdir(parents=True, exist_ok=True)
    _run_inspect(dump=dump, out=out)
    sys24_png = _sys24_framebuffer_png(dump, out)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.decomp.lift_tile_preview",
            "--dump",
            str(dump),
            "-o",
            str(out),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    _write_index_html(out, dump=dump, prg=prg, copro=copro, sys24_png=sys24_png)
    print(f"Boot preview: file://{out / 'index.html'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
