#!/usr/bin/env python3
"""Export merged symbol anchors for Ghidra and decomp tooling."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.layout import load_yaml_file
from tools.i960_memory import WORKRAM_SCENE_SYMBOLS
from tools.i960_section_map import ROM_ANCHORS

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_functions_yaml(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = load_yaml_file(path)
    return list(data.get("functions", []))


def memory_constants() -> list[dict]:
    rows: list[dict] = []
    import tools.i960_memory as mem

    for name, value in vars(mem).items():
        if name.startswith("_") or not isinstance(value, int):
            continue
        if value >= 0x0010_0000 and value < 0x0100_0000:
            space = "maincpu_rom"
        elif value >= 0x0020_0000 and value < 0x0080_0000:
            space = "workram_or_i960_low"
        elif value >= 0x0200_0000:
            space = "main_data_vaddr"
        else:
            space = "other"
        rows.append({"name": name, "address": f"0x{value:08x}", "space": space})
    return rows


def build_anchors(functions: list[dict]) -> dict:
    labels: dict[str, dict] = {}

    for addr, label, confidence, category in ROM_ANCHORS:
        key = f"0x{addr:06x}"
        labels[key] = {
            "address": f"0x{addr:08x}",
            "name": label,
            "confidence": confidence,
            "category": category,
            "source": "i960_section_map.ROM_ANCHORS",
        }

    for fn in functions:
        addr = int(fn["address"], 0) if isinstance(fn["address"], str) else fn["address"]
        key = f"0x{addr:06x}"
        labels[key] = {
            "address": f"0x{addr:08x}",
            "name": fn["name"],
            "section": fn.get("section"),
            "source": "decomp/symbols/functions.yaml",
        }

    for name, value in WORKRAM_SCENE_SYMBOLS.items():
        labels[f"0x{value:08x}"] = {
            "address": f"0x{value:08x}",
            "name": name,
            "space": "workram",
            "source": "i960_memory.WORKRAM_SCENE_SYMBOLS",
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "maincpu_labels": sorted(labels.values(), key=lambda r: r["address"]),
        "memory_constants": memory_constants(),
    }


def write_ghidra_syms(labels: list[dict], path: Path) -> None:
    lines = ["# srallyc maincpu — auto-generated", ""]
    for row in labels:
        addr = int(row["address"], 16)
        if addr >= MAINCPU_LIMIT:
            continue
        lines.append(f"{row['name']} 0x{addr:08x} 0x0")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


MAINCPU_LIMIT = 0x0010_0000


def main() -> None:
    ap = argparse.ArgumentParser(description="Export decomp symbol anchors")
    ap.add_argument("--functions", type=Path, default=Path("decomp/symbols/functions.yaml"))
    ap.add_argument("--out-json", type=Path, default=Path("decomp/symbols/anchors.json"))
    ap.add_argument("--out-ghidra", type=Path, default=Path("decomp/symbols/srallyc_maincpu.syms"))
    args = ap.parse_args()

    functions = load_functions_yaml(args.functions)
    report = build_anchors(functions)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_ghidra_syms(report["maincpu_labels"], args.out_ghidra)
    print(f"Wrote {args.out_json} ({len(report['maincpu_labels'])} labels)")


if __name__ == "__main__":
    main()
