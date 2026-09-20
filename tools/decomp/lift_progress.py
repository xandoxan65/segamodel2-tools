#!/usr/bin/env python3
"""Report lifted-C coverage vs symbols/functions.yaml and maincpu ROM size."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

from tools.decomp.export_symbols import load_functions_yaml
from tools.decomp.function_slice import plan_function_slice
from tools.decomp.workspace import resolve_in_repo
from tools.i960_memory import MAINCPU_SIZE

ROM_ANNOT = re.compile(
    r"//\s*@rom\s+0x([0-9a-fA-F]+)\s+\+0x([0-9a-fA-F]+)(?:\s+(\w+))?",
    re.MULTILINE,
)


def _parse_lifted_regions(src_dirs: list[Path]) -> list[dict]:
    rows: list[dict] = []
    for src_dir in src_dirs:
        if not src_dir.is_dir():
            continue
        for path in sorted(src_dir.glob("*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            match = ROM_ANNOT.search(text)
            if not match:
                continue
            addr = int(match.group(1), 16)
            length = int(match.group(2), 16)
            name = match.group(3) or path.stem
            rows.append(
                {
                    "name": name,
                    "file": str(path.relative_to(src_dir.parent.parent)),
                    "addr": addr,
                    "length": length,
                    "rodata": "ROM constant block" in text,
                }
            )
    return rows


def _planned_regions(functions_yaml: Path) -> tuple[list[dict], int]:
    rows: list[dict] = []
    total = 0
    seen_names: set[str] = set()
    for entry in load_functions_yaml(functions_yaml):
        name = str(entry.get("name", ""))
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        addr = int(entry.get("address", 0))
        try:
            plan = plan_function_slice(name, functions_yaml=functions_yaml)
            length = plan.length
            source = plan.source
        except (KeyError, FileNotFoundError, ValueError, IsADirectoryError, OSError) as exc:
            raw_len = entry.get("length", 0) or 0
            length = int(raw_len, 0) if isinstance(raw_len, str) else int(raw_len)
            source = f"unplanned ({exc})"
        rows.append({"name": name, "addr": addr, "length": length, "source": source})
        total += length
    return rows, total


def compute_progress(*, repo_root: Path, src_dirs: list[Path], functions_yaml: Path) -> dict:
    lifted = _parse_lifted_regions(src_dirs)
    planned, planned_bytes = _planned_regions(functions_yaml)

    lifted_names = {r["name"] for r in lifted}
    curated_names = {r["name"] for r in planned}
    lifted_bytes = sum(r["length"] for r in lifted)

    # Union of lifted byte ranges (non-overlapping estimate).
    intervals = sorted((r["addr"], r["addr"] + r["length"]) for r in lifted)
    merged = 0
    if intervals:
        cur_lo, cur_hi = intervals[0]
        for lo, hi in intervals[1:]:
            if lo <= cur_hi:
                cur_hi = max(cur_hi, hi)
            else:
                merged += cur_hi - cur_lo
                cur_lo, cur_hi = lo, hi
        merged += cur_hi - cur_lo

    fn_total = len(curated_names)
    fn_done = len(lifted_names & curated_names)

    return {
        "functions": {
            "lifted": fn_done,
            "curated": fn_total,
            "percent": round(100.0 * fn_done / fn_total, 2) if fn_total else 0.0,
            "lifted_names": sorted(lifted_names),
            "missing_names": sorted(curated_names - lifted_names),
        },
        "rom_bytes": {
            "lifted_sum": lifted_bytes,
            "lifted_merged": merged,
            "maincpu_size": MAINCPU_SIZE,
            "percent_of_maincpu": round(100.0 * merged / MAINCPU_SIZE, 4) if MAINCPU_SIZE else 0.0,
            "planned_curated_sum": planned_bytes,
            "percent_of_planned": round(100.0 * merged / planned_bytes, 2) if planned_bytes else 0.0,
            "regions": lifted,
        },
        "planned": planned,
    }


def _print_human(report: dict) -> None:
    fn = report["functions"]
    rom = report["rom_bytes"]
    print("Lift progress (src/libc/ + src/boot/)")
    print(f"  Functions: {fn['lifted']} / {fn['curated']} ({fn['percent']:.1f}%)")
    print(
        f"  ROM bytes: 0x{rom['lifted_merged']:x} / 0x{rom['maincpu_size']:x}"
        f" ({rom['percent_of_maincpu']:.2f}% of maincpu)"
    )
    if rom["planned_curated_sum"]:
        print(
            f"             0x{rom['lifted_merged']:x} / 0x{rom['planned_curated_sum']:x}"
            f" ({rom['percent_of_planned']:.1f}% of curated slice plan)"
        )
    print("  Lifted regions:")
    for row in rom["regions"]:
        print(f"    {row['name']:24s} @ 0x{row['addr']:06x} +0x{row['length']:x}")
    missing = fn["missing_names"]
    if missing:
        print(f"  Missing ({len(missing)}): {', '.join(missing[:8])}" + (" …" if len(missing) > 8 else ""))


def main() -> None:
    ap = argparse.ArgumentParser(description="Lifted C progress report")
    ap.add_argument(
        "--src-dir",
        action="append",
        dest="src_dirs",
        type=Path,
        default=None,
        help="Lift output dir (repeatable; default: src/libc and src/boot)",
    )
    ap.add_argument("--functions", type=Path, default=Path("symbols/functions.yaml"))
    ap.add_argument("--json", type=Path, default=None, help="Write JSON report")
    ap.add_argument("--quiet", action="store_true", help="Only print percentage lines")
    args = ap.parse_args()

    repo_root = resolve_in_repo(Path("."))
    functions_yaml = resolve_in_repo(args.functions)
    src_dirs = args.src_dirs or [Path("src/libc"), Path("src/boot")]
    src_dirs = [resolve_in_repo(p) for p in src_dirs]

    report = compute_progress(
        repo_root=repo_root,
        src_dirs=src_dirs,
        functions_yaml=functions_yaml,
    )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.json}")

    if not args.quiet:
        _print_human(report)
    else:
        fn = report["functions"]
        rom = report["rom_bytes"]
        print(f"functions={fn['percent']:.1f}% rom={rom['percent_of_maincpu']:.2f}%")


if __name__ == "__main__":
    main()
