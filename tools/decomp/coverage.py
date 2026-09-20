#!/usr/bin/env python3
"""Maincpu ASM and C translation coverage metrics."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAINCPU_ROM_BYTES = 0x100_000

# C sources: // @rom 0x023cc8 0x024750  or  // @rom 0x023cc8 +0x888
ROM_ANNOTATION_RE = re.compile(
    r"@rom\s+0x([0-9a-f]+)\s+(?:0x([0-9a-f]+)|\+0x?([0-9a-f]+))",
    re.IGNORECASE,
)


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def merged_byte_count(intervals: list[tuple[int, int]]) -> int:
    return sum(end - start for start, end in merge_intervals(intervals))


def coverage_pct(unique_bytes: int, total_bytes: int = MAINCPU_ROM_BYTES) -> float:
    if total_bytes <= 0:
        return 0.0
    return round(100 * unique_bytes / total_bytes, 2)


def resolve_paths(repo_root: Path) -> dict[str, Path]:
    root = repo_root.resolve()
    if (root / "disasm").is_dir():
        decomp = root
        analysis_out = decomp / "out"
    else:
        decomp = root / "decomp"
        analysis_out = root / "out"
    return {
        "decomp": decomp,
        "disasm_manifest": decomp / "disasm/manifest.json",
        "decode_report": analysis_out / "i960/decode_report.json",
        "layout": analysis_out / "decomp/layout.generated.yaml",
        "functions_yaml": decomp / "symbols/functions.yaml",
        "src": decomp / "src",
        "out_report": analysis_out / "decomp/coverage_report.json",
    }


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_functions(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        import yaml
    except ImportError:
        yaml = None  # type: ignore
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if yaml is not None else json.loads(text)
    return list((data or {}).get("functions") or [])


def section_regions(layout: dict | None) -> list[tuple[str, int, int]]:
    if not layout:
        return []
    sections = layout.get("images", {}).get("maincpu", {}).get("sections", [])
    rows: list[tuple[str, int, int]] = []
    for sec in sections:
        if sec.get("name") == "erase_fill":
            continue
        start = int(str(sec["start"]), 0)
        end = int(str(sec["end"]), 0)
        rows.append((str(sec["name"]), start, end))
    return rows


def section_for_address(addr: int, regions: list[tuple[str, int, int]]) -> str | None:
    for name, start, end in regions:
        if start <= addr < end:
            return name
    return None


def clip_interval(start: int, end: int, sec_start: int, sec_end: int) -> tuple[int, int] | None:
    lo = max(start, sec_start)
    hi = min(end, sec_end)
    if hi <= lo:
        return None
    return lo, hi


def by_section_coverage(
    intervals: list[tuple[int, int]],
    regions: list[tuple[str, int, int]],
) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, sec_start, sec_end in regions:
        sec_bytes = sec_end - sec_start
        covered = 0
        for start, end in merge_intervals(intervals):
            clipped = clip_interval(start, end, sec_start, sec_end)
            if clipped:
                covered += clipped[1] - clipped[0]
        out[name] = {
            "section_bytes": sec_bytes,
            "covered_bytes": covered,
            "coverage_pct": coverage_pct(covered, sec_bytes),
        }
    return out


def asm_intervals_from_manifest(manifest: dict) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    for row in manifest.get("slices", []):
        start = int(str(row["start"]), 16)
        end = int(str(row["end"]), 16)
        if end > start:
            intervals.append((start, end))
    return intervals


def build_asm_coverage(
    *,
    manifest: dict | None,
    decode: dict | None,
    layout: dict | None,
) -> dict:
    intervals = asm_intervals_from_manifest(manifest or {})
    unique_bytes = merged_byte_count(intervals)
    regions = section_regions(layout)

    pct = decode.get("coverage_pct") if decode else coverage_pct(unique_bytes)
    if decode and decode.get("unique_bytes") is not None:
        unique_bytes = int(decode["unique_bytes"])

    return {
        "coverage_pct": pct,
        "unique_bytes": unique_bytes,
        "maincpu_rom_bytes": MAINCPU_ROM_BYTES,
        "slice_count": manifest.get("slice_count") if manifest else len(intervals),
        "interval_count": len(merge_intervals(intervals)),
        "by_subsystem": manifest.get("by_subsystem", {}) if manifest else {},
        "by_section": by_section_coverage(intervals, regions),
    }


def parse_rom_annotations(text: str) -> list[tuple[int, int, str | None]]:
    """Return (start, end, name_hint) from @rom lines."""
    ranges: list[tuple[int, int, str | None]] = []
    for line in text.splitlines():
        match = ROM_ANNOTATION_RE.search(line)
        if not match:
            continue
        start = int(match.group(1), 16)
        if match.group(2):
            end = int(match.group(2), 16)
        else:
            end = start + int(match.group(3), 16)
        if end <= start:
            continue
        name_hint = None
        name_m = re.search(r"@rom\s+0x[0-9a-f]+\s+(?:0x[0-9a-f]+|\+0x?[0-9a-f]+)\s+([A-Za-z_][A-Za-z0-9_]*)", line, re.I)
        if name_m:
            name_hint = name_m.group(1)
        ranges.append((start, end, name_hint))
    return ranges


def scan_c_sources(src_root: Path) -> tuple[list[tuple[int, int]], list[dict]]:
    intervals: list[tuple[int, int]] = []
    files: list[dict] = []
    if not src_root.is_dir():
        return intervals, files

    for path in sorted(src_root.rglob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        annotations = parse_rom_annotations(text)
        file_ranges = [(s, e) for s, e, _ in annotations]
        intervals.extend(file_ranges)
        files.append(
            {
                "file": str(path.relative_to(src_root)),
                "range_count": len(file_ranges),
                "bytes": merged_byte_count(file_ranges),
                "ranges": [
                    {"start": f"0x{s:06x}", "end": f"0x{e:06x}", "bytes": e - s}
                    for s, e in merge_intervals(file_ranges)
                ],
            }
        )
    return intervals, files


def functions_with_c_translation(
    functions: list[dict],
    src_root: Path,
    c_intervals: list[tuple[int, int]],
) -> tuple[int, list[str], list[str]]:
    merged = merge_intervals(c_intervals)
    translated: list[str] = []
    pending: list[str] = []

    for fn in functions:
        name = str(fn["name"])
        addr = int(fn["address"], 16) if isinstance(fn["address"], str) else int(fn["address"])
        c_file = src_root / f"{name}.c"
        in_range = any(start <= addr < end for start, end in merged)
        if (src_root.is_dir() and c_file.is_file()) or in_range:
            translated.append(name)
        else:
            pending.append(name)

    return len(translated), sorted(translated), sorted(pending)


def build_c_coverage(
    *,
    src_root: Path,
    functions: list[dict],
    layout: dict | None,
) -> dict:
    intervals, files = scan_c_sources(src_root)
    unique_bytes = merged_byte_count(intervals)
    regions = section_regions(layout)
    translated_count, translated_names, pending_names = functions_with_c_translation(
        functions, src_root, intervals
    )

    return {
        "coverage_pct": coverage_pct(unique_bytes),
        "unique_bytes": unique_bytes,
        "maincpu_rom_bytes": MAINCPU_ROM_BYTES,
        "file_count": len(files),
        "range_count": len(merge_intervals(intervals)),
        "functions_seeded": len(functions),
        "functions_translated": translated_count,
        "functions_translated_names": translated_names,
        "functions_pending_names": pending_names,
        "files": files,
        "by_section": by_section_coverage(intervals, regions),
    }


def build_coverage_report(repo_root: Path) -> dict:
    paths = resolve_paths(repo_root)
    manifest = load_json(paths["disasm_manifest"])
    decode = load_json(paths["decode_report"])
    layout = None
    if paths["layout"].is_file():
        from tools.decomp.layout import load_yaml_file

        layout = load_yaml_file(paths["layout"])
    functions = load_functions(paths["functions_yaml"])

    asm = build_asm_coverage(manifest=manifest, decode=decode, layout=layout)
    c_cov = build_c_coverage(src_root=paths["src"], functions=functions, layout=layout)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "maincpu_rom_bytes": MAINCPU_ROM_BYTES,
        "asm": asm,
        "c": c_cov,
    }


def format_coverage_summary(report: dict) -> str:
    asm = report.get("asm", {})
    c_cov = report.get("c", {})
    asm_pct = asm.get("coverage_pct", 0)
    c_pct = c_cov.get("coverage_pct", 0)
    fn_done = c_cov.get("functions_translated", 0)
    fn_total = c_cov.get("functions_seeded", 0)
    return (
        f"Coverage: ASM {asm_pct}% ({asm.get('unique_bytes', 0)} / "
        f"{MAINCPU_ROM_BYTES} bytes) | C {c_pct}% "
        f"({fn_done}/{fn_total} seeded functions)"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute maincpu ASM and C coverage metrics")
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    paths = resolve_paths(repo_root)
    out = args.out or paths["out_report"]
    report = build_coverage_report(repo_root)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(f"Wrote {out}")
        print(format_coverage_summary(report))


if __name__ == "__main__":
    main()
