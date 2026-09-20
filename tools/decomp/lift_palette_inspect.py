#!/usr/bin/env python3
"""Visualize palette RAM captured from decomp_lift (I960_PALETTE_DUMP).

This tool only reads harness dumps produced by running lifted code. It does not
replay CGM or compare against static Python palette state.

Usage:

  cd decomp && I960_PALETTE_DUMP=build/lift/palette_state ./build/lift/decomp_lift
  cd .. && python3 -m tools.decomp.lift_palette_inspect \\
      --dump decomp/build/lift/palette_state \\
      -o out/lift/palette_inspect
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from tools.decomp.lift_palette_state import load_lift_palette_state
from tools.model2_palette import PALRAM_COLORBASE_WORD, rgb15

SLOT_PREVIEW_MAX = 256
SLOT_CELL = 8


def summarize_colorbase(state, *, max_slot: int) -> dict:
    slots: list[dict] = []
    for slot in range(max_slot + 1):
        color15 = state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
        if not color15:
            continue
        r, g, b = state.lookup_rgb15(color15)
        slots.append({"slot": slot, "color15": f"0x{color15:04x}", "rgb": [r, g, b]})
    return {
        "slots_checked": max_slot + 1,
        "nonzero_slots": len(slots),
        "samples": slots[:64],
    }


def render_colorbase_grid(state: PaletteState, *, max_slot: int) -> Image.Image:
    cols = 32
    rows = (max_slot + cols) // cols
    img = Image.new("RGB", (cols * SLOT_CELL, rows * SLOT_CELL), (32, 32, 32))
    px = img.load()
    for slot in range(max_slot + 1):
        color15 = state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
        if color15:
            r, g, b = state.lookup_rgb15(color15)
        else:
            r = g = b = 24
        x0 = (slot % cols) * SLOT_CELL
        y0 = (slot // cols) * SLOT_CELL
        for y in range(SLOT_CELL):
            for x in range(SLOT_CELL):
                px[x0 + x, y0 + y] = (r, g, b)
    return img


def render_palram_gamma_strip(state: PaletteState) -> Image.Image:
    count = PALRAM_COLORBASE_WORD
    h = 16
    img = Image.new("RGB", (count, h), (0, 0, 0))
    px = img.load()
    for i in range(count):
        word = state.palram[i] & 0x7FFF
        if word:
            r, g, b = rgb15(word)
        else:
            r = g = b = 0
        for y in range(h):
            px[i, y] = (r, g, b)
    return img


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", type=Path, required=True, help="I960_PALETTE_DUMP directory")
    ap.add_argument("-o", "--out", type=Path, required=True, help="output directory")
    ap.add_argument("--max-slot", type=int, default=189, help="colorbase slots to preview")
    args = ap.parse_args()

    dump_dir = args.dump.resolve()
    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    state, manifest = load_lift_palette_state(dump_dir)
    max_slot = min(args.max_slot, SLOT_PREVIEW_MAX - 1)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "decomp_lift",
        "dump_dir": str(dump_dir),
        "manifest": manifest,
        "palram_nonzero_words": sum(1 for w in state.palram if w),
        "colorbase": summarize_colorbase(state, max_slot=max_slot),
    }

    report_path = out_dir / "lift_palette.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    render_colorbase_grid(state, max_slot=max_slot).save(out_dir / "lift_colorbase_slots.png")
    render_palram_gamma_strip(state).save(out_dir / "lift_palram_gamma.png")

    cb = report["colorbase"]
    print(
        f"lift palette: {report['palram_nonzero_words']} nonzero palram words, "
        f"{cb['nonzero_slots']} nonzero colorbase slots (of {cb['slots_checked']})",
        file=sys.stderr,
    )
    print(f"Wrote {report_path} and PNGs under {out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
