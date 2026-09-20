#!/usr/bin/env python3
"""Index decomp/disasm slices for coverage tracking and subsystem RE."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.disasm_paths import (
    DECOMP_DISASM,
    LEGACY_DISASM,
    iter_asm_files,
    migrate_legacy_disasm,
    parse_slice_bounds,
)
from tools.i960_decode import build_decode_report, scan_asm_file

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

PALETTE_SUBSYSTEM_ADDRS = frozenset(
    {
        0x029A68,
        0x029C10,
        0x029D60,
        0x029EB0,
        0x029FAC,
        0x02A050,
        0x02A0F8,
        0x02A120,
        0x02A200,
        0x02A2E0,
        0x02A410,
        0x02A490,
        0x02A4E0,
        0x02A5A0,
        0x05CE18,
        0x05CEC0,
        0x05CF50,
    }
)

LIBC_ADDRS = frozenset(range(0x05C000, 0x05E000))


def load_functions_yaml(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return list((data or {}).get("functions") or [])


def load_tags_yaml(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    overrides = (data or {}).get("overrides") or {}
    return {str(k): str(v) for k, v in overrides.items()}


def load_cluster_sizes(scan_report_path: Path) -> dict[int, int]:
    if not scan_report_path.is_file():
        return {}
    report = json.loads(scan_report_path.read_text(encoding="utf-8"))
    sizes: dict[int, int] = {}
    for region in report.get("exported_regions", []):
        addr = int(region["load_address"], 16)
        sizes[addr] = int(region["size"])
    return sizes


def section_for_address(addr: int, section_map: dict) -> str | None:
    for region in section_map.get("regions", []):
        start = int(region["start"], 16)
        end = int(region["end"], 16)
        if start <= addr < end:
            return region["name"]
    return None


def symbols_in_range(start: int, end: int, functions: list[dict]) -> list[str]:
    names: list[str] = []
    for fn in functions:
        faddr = int(fn["address"], 16) if isinstance(fn["address"], str) else int(fn["address"])
        if start <= faddr < end:
            names.append(str(fn["name"]))
    return names


def classify_subsystem(
    *,
    start: int,
    end: int,
    role: str,
    symbols: list[str],
    rel_file: str,
    tag_overrides: dict[str, str],
) -> str:
    if rel_file in tag_overrides:
        return tag_overrides[rel_file]
    if symbols and any("palette" in s or "catalog_draw" in s or "draw_scene" in s for s in symbols):
        return "palette_cgm"
    if any(start <= addr < end for addr in PALETTE_SUBSYSTEM_ADDRS):
        return "palette_cgm"
    if any(start <= addr < end for addr in LIBC_ADDRS):
        return "libc"
    if role in ("vehicle_geo_feeder", "geo_feeder", "geo_helper"):
        return "geo_feeder"
    if role == "scene_setup":
        return "scene"
    if "palette" in rel_file.lower():
        return "palette_cgm"
    if "geo_cluster" in rel_file:
        return "geo_feeder"
    return "other"


def build_manifest(
    disasm_root: Path,
    *,
    repo_root: Path,
    decode_report: dict | None = None,
) -> dict:
    functions = load_functions_yaml(repo_root / "decomp/symbols/functions.yaml")
    tag_overrides = load_tags_yaml(disasm_root / "tags.yaml")
    section_map_path = repo_root / "out/i960/section_map.json"
    section_map = (
        json.loads(section_map_path.read_text(encoding="utf-8"))
        if section_map_path.is_file()
        else {}
    )
    cluster_sizes = load_cluster_sizes(repo_root / "out/i960/scan_report.json")

    role_by_file: dict[str, str] = {}
    if decode_report:
        for row in decode_report.get("files", []):
            role_by_file[row["file"]] = row.get("role", "other")

    slices: list[dict] = []
    for asm_path in iter_asm_files(disasm_root):
        rel = str(asm_path.relative_to(disasm_root))
        summary = scan_asm_file(asm_path)
        start = int(summary["rom_range"][0], 16)
        end = int(summary["rom_range"][1], 16)

        parsed = parse_slice_bounds(asm_path.name)
        if parsed and parsed[1] > parsed[0]:
            start, end = parsed
        elif asm_path.name.startswith("geo_cluster_"):
            cluster_start = int(re.search(r"0x([0-9a-f]+)", asm_path.name, re.I).group(1), 16)
            size = cluster_sizes.get(cluster_start)
            if size:
                start, end = cluster_start, cluster_start + size

        section = section_for_address(start, section_map)
        symbols = symbols_in_range(start, end, functions)
        role = role_by_file.get(rel) or role_by_file.get(asm_path.name) or summary.get("role", "other")
        subsystem = classify_subsystem(
            start=start,
            end=end,
            role=role,
            symbols=symbols,
            rel_file=rel,
            tag_overrides=tag_overrides,
        )
        slices.append(
            {
                "file": rel,
                "start": f"0x{start:06x}",
                "end": f"0x{end:06x}",
                "bytes": end - start,
                "section": section,
                "subsystem": subsystem,
                "role": role,
                "symbols": symbols,
            }
        )

    by_subsystem: dict[str, int] = {}
    for row in slices:
        by_subsystem[row["subsystem"]] = by_subsystem.get(row["subsystem"], 0) + 1

    coverage_pct = decode_report.get("coverage_pct") if decode_report else None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disasm_root": str(disasm_root.relative_to(repo_root)),
        "slice_count": len(slices),
        "coverage_pct": coverage_pct,
        "by_subsystem": dict(sorted(by_subsystem.items())),
        "slices": sorted(slices, key=lambda r: (r["start"], r["file"])),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build decomp/disasm manifest.json")
    ap.add_argument("--disasm-root", type=Path, default=DECOMP_DISASM)
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, default=DECOMP_DISASM / "manifest.json")
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    disasm_root = (repo_root / args.disasm_root).resolve()
    disasm_root.mkdir(parents=True, exist_ok=True)

    moved = migrate_legacy_disasm(
        legacy=repo_root / LEGACY_DISASM,
        dest=disasm_root,
        move=True,
    )
    if moved:
        print(f"Migrated {len(moved)} file(s) → {disasm_root.relative_to(repo_root)}")

    decode_report = build_decode_report(disasm_root) if disasm_root.is_dir() else None
    manifest = build_manifest(disasm_root, repo_root=repo_root, decode_report=decode_report)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.out} ({manifest['slice_count']} slices, "
        f"{manifest.get('coverage_pct', 0)}% coverage)"
    )


if __name__ == "__main__":
    main()
