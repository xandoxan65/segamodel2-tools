#!/usr/bin/env python3
"""Golden compare: Python GeoDisplayListRunner vs C model2_geo_dl decode.

Builds a minimal synthetic display list (matrix + object end), writes a binary
FIFO dump, runs ``decomp_lift --decode-geo-fifo``, and compares vertex counts
to the Python runner on the same words.

Usage (from repo root or decomp/):
  python3 decomp/tools/decomp/geo_fifo_compare.py
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

_DECOMP = Path(__file__).resolve().parents[2]
_REPO = _DECOMP.parent

# Prefer repo-root tools/ over decomp/tools/ (same package name).
sys.path = [p for p in sys.path if Path(p or ".").resolve() not in (_DECOMP, _DECOMP / "tools")]
sys.path.insert(0, str(_REPO))
for _k in list(sys.modules):
    if _k == "tools" or _k.startswith("tools."):
        del sys.modules[_k]

from tools.model2_float import f2u
from tools.model2_geo import GeoMode, identity_matrix, try_parse_polygon_object
from tools.model2_geo_dl import GeoDisplayContext, GeoDisplayListRunner
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir, u32_words


def _build_minimal_dl(rom_off: int) -> list[int]:
    words: list[int] = []
    words.append(0x03800000)  # set_mode
    words.append(int(GeoMode.NP_NS))
    words.append(0x05800000)  # matrix_write
    for v in identity_matrix():
        words.append(f2u(v))
    words.append(0x00800000)  # object_data
    words.append(0)
    words.append(0)
    words.append(0x00800000 | (rom_off & 0x7FFFFF))
    words.append(64)
    words.append(0x07800000)  # geo_end
    return words


def _find_seed_object(polygon_rom: list[int]) -> int | None:
    for off in range(0, min(len(polygon_rom) - 32, 0x20000), 4):
        parsed = try_parse_polygon_object(polygon_rom, off, count=64)
        if parsed and len(parsed.vertices) >= 8:
            return off
    return None


def main() -> int:
    rom_dir = resolve_rom_dir(None)
    poly = u32_words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"]))
    seed = _find_seed_object(poly)
    if seed is None:
        print("geo_fifo_compare: no seed polygon object found", file=sys.stderr)
        return 1

    dl = _build_minimal_dl(seed)
    runner = GeoDisplayListRunner(
        GeoDisplayContext(polygon_rom=poly, polygon_rom_mask=len(poly) - 1)
    )
    py = runner.run(dl, 0, source="golden")

    with tempfile.TemporaryDirectory() as td:
        fifo_path = Path(td) / "prg_fifo.bin"
        summary_path = Path(td) / "c_summary.json"
        fifo_path.write_bytes(struct.pack(f"<{len(dl)}I", *dl))
        bin_path = _DECOMP / "build" / "lift" / "decomp_lift"
        if not bin_path.is_file():
            print("geo_fifo_compare: build decomp_lift first (make lift)", file=sys.stderr)
            return 1
        cmd = [
            str(bin_path),
            "--decode-geo-fifo",
            str(fifo_path),
            "--geo-summary",
            str(summary_path),
        ]
        env = dict(**{k: v for k, v in __import__("os").environ.items()})
        env.setdefault("SEGAMOD2_ROM_DIR", str(rom_dir))
        proc = subprocess.run(cmd, cwd=str(_DECOMP), env=env, capture_output=True, text=True)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            print("geo_fifo_compare: C decode failed", file=sys.stderr)
            return 1
        csum = json.loads(summary_path.read_text())

    py_n = len(py.vertices)
    c_n = int(csum["vertex_count"])
    print(f"geo_fifo_compare: seed_rom={seed:#x} py_verts={py_n} c_verts={c_n}")
    if abs(py_n - c_n) > max(2, py_n // 20):
        print("geo_fifo_compare: FAIL vertex count mismatch", file=sys.stderr)
        return 1
    if c_n < 4:
        print("geo_fifo_compare: FAIL too few C vertices", file=sys.stderr)
        return 1
    print("geo_fifo_compare: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
