#!/usr/bin/env python3
"""Headless Ghidra decompile pass for selected maincpu ROM ranges."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.disasm.ghidra_paths import analyze_headless, ghidra_env, require_i960_processor

FIX_SCRIPT = Path(__file__).with_name("FixI960LeafReturns.java")
JAVA_SCRIPT = Path(__file__).with_name("ExportDecompileRanges.java")


def classify(row: dict) -> str:
    if not row["decompiled"]:
        return "failed"
    score = row["warning_score"]
    lines = row["c_lines"]
    if score <= 3 and lines >= 4:
        return "clean"
    if score <= 12:
        return "partial"
    return "stubborn"


def summarize(rows: list[dict], label: str) -> dict:
    buckets = {"clean": 0, "partial": 0, "stubborn": 0, "failed": 0}
    classified = []
    for row in rows:
        cat = classify(row)
        buckets[cat] += 1
        classified.append({**row, "class": cat, "c": None})
    total = len(rows) or 1
    return {
        "label": label,
        "function_count": len(rows),
        "buckets": buckets,
        "bucket_pct": {k: round(100 * v / total, 1) for k, v in buckets.items()},
        "functions": classified,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Ghidra decompile pass on i960 ROM ranges")
    ap.add_argument(
        "--binary",
        type=Path,
        default=Path("out/i960/maincpu_deinterleaved.bin"),
    )
    ap.add_argument("--project", type=Path, default=Path("out/i960/ghidra_decompile_project"))
    ap.add_argument("--name", default="srallyc_decompile")
    ap.add_argument("--out", type=Path, default=Path("out/i960/decompile_report.json"))
    ap.add_argument(
        "--ranges",
        default="0x05c000:0x05e000,0x020000:0x030000",
        help="Comma-separated start:end hex pairs",
    )
    args = ap.parse_args()

    try:
        require_i960_processor()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    if not args.binary.is_file():
        print(f"Missing binary: {args.binary}", file=sys.stderr)
        raise SystemExit(1)

    ranges: list[tuple[int, int]] = []
    for part in args.ranges.split(","):
        start_s, end_s = part.split(":")
        ranges.append((int(start_s, 0), int(end_s, 0)))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    raw_json = args.out.with_suffix(".raw.json")
    script_dir = args.out.parent / "ghidra_scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    for src in (FIX_SCRIPT, JAVA_SCRIPT):
        dest = script_dir / src.name
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    fix_script_path = script_dir / FIX_SCRIPT.name
    export_script_path = script_dir / JAVA_SCRIPT.name
    range_spec = ",".join(f"0x{s:x}:0x{e:x}" for s, e in ranges)

    args.project.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(analyze_headless()),
        str(args.project.resolve()),
        args.name,
        "-import",
        str(args.binary.resolve()),
        "-processor",
        "i960:LE:32:default",
        "-cspec",
        "default",
        "-loader",
        "BinaryLoader",
        "-loader-baseAddr",
        "0x0",
        "-overwrite",
        "-deleteProject",
        "-postScript",
        str(fix_script_path.resolve()),
        "-postScript",
        str(export_script_path.resolve()),
        str(raw_json.resolve()),
        range_spec,
        "-scriptPath",
        str(script_dir.resolve()),
    ]
    print("Running Ghidra headless (this may take several minutes)...", flush=True)
    subprocess.run(cmd, check=True, env=ghidra_env())

    rows: list[dict] = json.loads(raw_json.read_text(encoding="utf-8"))
    by_range: list[dict] = []
    for start, end in ranges:
        subset = [r for r in rows if start <= int(r["entry"], 16) < end]
        by_range.append(summarize(subset, f"0x{start:06X}–0x{end:06X}"))

    all_summary = summarize(rows, "combined")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary": str(args.binary),
        "ranges": [f"0x{s:06X}–0x{e:06X}" for s, e in ranges],
        "combined": {k: v for k, v in all_summary.items() if k != "functions"},
        "by_range": [{k: v for k, v in s.items() if k != "functions"} for s in by_range],
        "samples": {
            "clean": [],
            "partial": [],
            "stubborn": [],
            "failed": [],
        },
        "functions": all_summary["functions"],
    }

    for row in all_summary["functions"]:
        cat = row["class"]
        if len(report["samples"][cat]) < 3:
            report["samples"][cat].append(
                {
                    "entry": row["entry"],
                    "name": row["name"],
                    "size": row["size"],
                    "warning_score": row["warning_score"],
                    "c_preview": row["c_preview"],
                    "error": row.get("error"),
                }
            )

    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.out}")
    print(
        "Combined: "
        + ", ".join(f"{k}={report['combined']['buckets'][k]}" for k in report["combined"]["buckets"])
    )


if __name__ == "__main__":
    main()
