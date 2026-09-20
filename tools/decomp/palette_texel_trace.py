"""Trace i960 texel decode: palram → lumaram → colorxlat (upload gamma baked).

Usage:
  python3 -m tools.decomp.palette_texel_trace --colorbase 477 --lumabase 128
  python3 -m tools.decomp.palette_texel_trace --colorbase 477 --compare 423,7
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tools.decomp.palette_re import colorxlat_source_for_main_data
from tools.model2_palette import (
    COLORXLAT_B_WORD,
    COLORXLAT_G_WORD,
    COLORXLAT_R_WORD,
    PALRAM_COLORBASE_WORD,
    PaletteState,
    load_palette_from_main_data,
    rgb15,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]


def trace_texel_step(
    state: PaletteState,
    texel: int,
    colorbase: int,
    lumabase: int,
    *,
    luma: int = 255,
) -> dict[str, Any]:
    """One texel through ``PaletteState.lookup_texel`` (no MAME CRT gamma pass)."""
    texel &= 0x0F
    color15 = state.pal_colorbase_entry(colorbase)
    r_nib = (color15 >> 0) & 0x1F
    g_nib = (color15 >> 5) & 0x1F
    b_nib = (color15 >> 10) & 0x1F
    r_bank = r_nib * 256
    g_bank = g_nib * 256
    b_bank = b_nib * 256

    luma_byte_idx = lumabase + ((texel << 4) >> 1)
    luma_raw = int(state.lumaram[luma_byte_idx]) if luma_byte_idx < len(state.lumaram) else 0
    luma_idx = min((luma_raw * int(luma)) // 256, 0x3F)

    r_word = COLORXLAT_R_WORD + r_bank + luma_idx
    g_word = COLORXLAT_G_WORD + g_bank + luma_idx
    b_word = COLORXLAT_B_WORD + b_bank + luma_idx
    tr = state.colorxlat[r_word] & 0xFF
    tg = state.colorxlat[g_word] & 0xFF
    tb = state.colorxlat[b_word] & 0xFF

    rgb_pre = rgb15(color15)
    rgb_out = state.lookup_texel(texel, colorbase, lumabase, luma=luma)

    return {
        "texel": texel,
        "color15": f"0x{color15:04x}",
        "color15_rgb_unpack": list(rgb_pre),
        "bank_nibbles": {"r": r_nib, "g": g_nib, "b": b_nib},
        "bank_byte_offset": {"r": r_bank, "g": g_bank, "b": b_bank},
        "lumaram_byte_index": luma_byte_idx,
        "lumaram_value": luma_raw,
        "luma_idx": luma_idx,
        "colorxlat_word_index": {"r": r_word, "g": g_word, "b": b_word},
        "colorxlat_rgb": {"r": tr, "g": tg, "b": tb},
        "texel_rgb": list(rgb_out),
    }


def trace_colorbase(
    state: PaletteState,
    colorbase: int,
    lumabase: int,
    texels: tuple[int, ...],
) -> dict[str, Any]:
    slot_idx = PALRAM_COLORBASE_WORD + (colorbase & 0x3FF)
    color15 = state.palram[slot_idx] & 0x7FFF
    return {
        "colorbase": colorbase,
        "lumabase": lumabase,
        "palram_word_index": slot_idx,
        "color15": f"0x{color15:04x}",
        "texels": [trace_texel_step(state, t, colorbase, lumabase) for t in texels],
    }


def colorxlat_bank_sample(
    state: PaletteState,
    bank_nibble: int,
    luma_indices: tuple[int, ...],
) -> dict[str, Any]:
    """Sample R/G/B lanes at selected luma indices for one 5-bit bank."""
    base = (bank_nibble & 0x1F) * 256
    rows: list[dict[str, int]] = []
    for li in luma_indices:
        rows.append(
            {
                "luma_idx": li,
                "r": state.colorxlat[COLORXLAT_R_WORD + base + li] & 0xFF,
                "g": state.colorxlat[COLORXLAT_G_WORD + base + li] & 0xFF,
                "b": state.colorxlat[COLORXLAT_B_WORD + base + li] & 0xFF,
            }
        )
    return {"bank_nibble": bank_nibble, "bank_byte_offset": base, "samples": rows}


def build_trace_report(
    main_data: bytes,
    *,
    colorbase: int,
    lumabase: int,
    texels: tuple[int, ...] = tuple(range(6, 16)),
    compare: tuple[int, ...] = (),
) -> dict[str, Any]:
    state = load_palette_from_main_data(main_data)
    primary = trace_colorbase(state, colorbase, lumabase, texels)

    color15 = int(primary["color15"], 16)
    banks = {
        "r": (color15 >> 0) & 0x1F,
        "g": (color15 >> 5) & 0x1F,
        "b": (color15 >> 10) & 0x1F,
    }
    luma_used = sorted({row["luma_idx"] for row in primary["texels"]})
    bank_samples = {
        ch: colorxlat_bank_sample(state, nib, tuple(luma_used))
        for ch, nib in banks.items()
    }

    comparisons = [trace_colorbase(state, cb, lumabase, texels) for cb in compare]

    return {
        "colorxlat_source": colorxlat_source_for_main_data(main_data),
        "primary": primary,
        "colorxlat_banks_used": bank_samples,
        "comparisons": comparisons,
    }


def _write_html(report: dict[str, Any], path: Path) -> None:
    primary = report["primary"]
    rows = []
    for row in primary["texels"]:
        pg = row["colorxlat_rgb"]
        go = row["texel_rgb"]
        rows.append(
            f"<tr><td>{row['texel']}</td>"
            f"<td><code>{row['color15']}</code></td>"
            f"<td>{row['lumaram_byte_index']}</td><td>{row['lumaram_value']}</td>"
            f"<td>{row['luma_idx']}</td>"
            f"<td>{row['bank_nibbles']['r']}/{row['bank_nibbles']['g']}/{row['bank_nibbles']['b']}</td>"
            f"<td>{pg['r']},{pg['g']},{pg['b']}</td>"
            f"<td><strong>{go[0]},{go[1]},{go[2]}</strong></td></tr>"
        )

    bank_blocks = []
    for ch, sample in report["colorxlat_banks_used"].items():
        lane_rows = "".join(
            f"<tr><td>{s['luma_idx']}</td><td>{s['r']}</td><td>{s['g']}</td><td>{s['b']}</td></tr>"
            for s in sample["samples"]
        )
        bank_blocks.append(
            f"<h3>{ch.upper()} bank nibble {sample['bank_nibble']} "
            f"(offset {sample['bank_byte_offset']})</h3>"
            f"<table><tr><th>luma_idx</th><th>R</th><th>G</th><th>B</th></tr>{lane_rows}</table>"
        )

    compare_blocks = []
    for comp in report.get("comparisons", []):
        cr = "".join(
            f"<tr><td>{t['texel']}</td><td>{','.join(str(x) for x in t['texel_rgb'])}</td></tr>"
            for t in comp["texels"]
        )
        compare_blocks.append(
            f"<h3>cb{comp['colorbase']} pal={comp['color15']}</h3>"
            f"<table><tr><th>texel</th><th>RGB</th></tr>{cr}</table>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>Palette trace cb{primary['colorbase']} lb{primary['lumabase']}</title>
<style>
body {{ font: 14px/1.45 system-ui, sans-serif; margin: 1.5rem; background: #141414; color: #eee; max-width: 960px; }}
table {{ border-collapse: collapse; font-size: 12px; margin: 0.5rem 0 1rem; }}
td, th {{ border: 1px solid #444; padding: 0.35rem 0.55rem; }}
code {{ color: #9cf; }}
.meta {{ color: #aaa; font-size: 12px; }}
</style></head><body>
<h1>Downstream trace — cb{primary['colorbase']} / lb{primary['lumabase']}</h1>
<p class="meta">colorxlat source: <code>{report['colorxlat_source']}</code> ·
palram[{primary['palram_word_index']}] = <code>{primary['color15']}</code></p>
<table>
<tr><th>texel</th><th>color15</th><th>lumaram[i]</th><th>val</th><th>luma_idx</th>
<th>R/G/B bank</th><th>pre-γ</th><th>out RGB</th></tr>
{''.join(rows)}
</table>
<h2>colorxlat banks selected by color15</h2>
{''.join(bank_blocks)}
{'<h2>Comparisons</h2>' + ''.join(compare_blocks) if compare_blocks else ''}
</body></html>"""
    path.write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace palram→lumaram→colorxlat texel decode")
    parser.add_argument("--colorbase", type=int, default=477)
    parser.add_argument("--lumabase", type=int, default=128)
    parser.add_argument("--texels", type=str, default="6-15", help="e.g. 6-15 or 6,12")
    parser.add_argument("--compare", type=str, default="", help="Other colorbases, comma-separated")
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "out/decomp")
    args = parser.parse_args()

    if "-" in args.texels and "," not in args.texels:
        lo, hi = args.texels.split("-", 1)
        texels = tuple(range(int(lo), int(hi) + 1))
    else:
        texels = tuple(int(x) for x in args.texels.split(",") if x.strip())

    compare = tuple(int(x) for x in args.compare.split(",") if x.strip())

    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    report = build_trace_report(
        main_data,
        colorbase=args.colorbase,
        lumabase=args.lumabase,
        texels=texels,
        compare=compare,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / f"palette_trace_cb{args.colorbase}_lb{args.lumabase}.json"
    html_path = args.out_dir / f"palette_trace_cb{args.colorbase}_lb{args.lumabase}.html"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _write_html(report, html_path)

    primary = report["primary"]
    print(f"colorxlat_source: {report['colorxlat_source']}")
    print(f"palram[{primary['palram_word_index']}] = {primary['color15']}")
    banks = primary["texels"][0]["bank_nibbles"]
    print(f"bank nibbles R/G/B = {banks['r']}/{banks['g']}/{banks['b']}")
    print(f"wrote {json_path}")
    print(f"wrote {html_path}")
    print("\ntexel  luma_idx  colorxlat      out RGB")
    for row in primary["texels"]:
        pg = row["colorxlat_rgb"]
        go = row["texel_rgb"]
        print(
            f"  {row['texel']:2d}     {row['luma_idx']:2d}       "
            f"{pg['r']:3d},{pg['g']:3d},{pg['b']:3d}   →  {go[0]:3d},{go[1]:3d},{go[2]:3d}"
        )


if __name__ == "__main__":
    main()
