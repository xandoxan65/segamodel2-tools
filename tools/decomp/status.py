#!/usr/bin/env python3
"""Write decomp progress status.json."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def count_section_asm(decomp_root: Path, layout_path: Path) -> tuple[int, int]:
    from tools.decomp.layout import load_yaml_file, iter_image_sections

    if not layout_path.is_file():
        return 0, 0
    layout = load_yaml_file(layout_path)
    total = 0
    with_asm = 0
    disasm_root = decomp_root / "disasm/maincpu"
    for section in iter_image_sections(layout, "maincpu"):
        total += 1
        asm = disasm_root / f"{section['name']}.asm"
        if asm.is_file():
            with_asm += 1
    return with_asm, total


def build_status(repo_root: Path) -> dict:
    from tools.decomp.coverage import build_coverage_report, format_coverage_summary

    verify = load_json(repo_root / "out/decomp/verify_report.json")
    decode = load_json(repo_root / "out/i960/decode_report.json")
    manifest = load_json(repo_root / "decomp/disasm/manifest.json")
    palette_report = load_json(repo_root / "out/decomp/palette_report.json")
    anchors = load_json(repo_root / "decomp/symbols/anchors.json")
    layout_path = repo_root / "out/decomp/layout.generated.yaml"
    coverage = build_coverage_report(repo_root)

    with_asm, section_total = count_section_asm(repo_root / "decomp", layout_path)
    fn_count = len(anchors.get("maincpu_labels", [])) if anchors else 0

    by_subsystem = manifest.get("by_subsystem", {}) if manifest else {}
    palette_geo = palette_report.get("geometry_demand", {}) if palette_report else {}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rom_roundtrip_ok": verify.get("ok") if verify else None,
        "maincpu_disasm_coverage_pct": decode.get("coverage_pct") if decode else None,
        "maincpu_c_coverage_pct": coverage["c"]["coverage_pct"],
        "coverage_summary": format_coverage_summary(coverage),
        "coverage": coverage,
        "disasm_slice_count": manifest.get("slice_count") if manifest else None,
        "disasm_by_subsystem": by_subsystem,
        "palette_subsystem_slices": by_subsystem.get("palette_cgm", 0),
        "palette_replay_ok": palette_report.get("ok_static") if palette_report else None,
        "palette_slots_filled": (palette_report.get("replay") or {}).get("colorbase_slots_filled")
        if palette_report
        else None,
        "palette_missing_high_slots": palette_geo.get("missing_high_count"),
        "palette_blocking": palette_report.get("blocking", []) if palette_report else [],
        "named_labels": fn_count,
        "maincpu_sections_with_asm": with_asm,
        "maincpu_sections_total": section_total,
        "verify_report": str(repo_root / "out/decomp/verify_report.json"),
        "decode_report": str(repo_root / "out/i960/decode_report.json"),
        "disasm_manifest": str(repo_root / "decomp/disasm/manifest.json"),
        "coverage_report": str(repo_root / "out/decomp/coverage_report.json"),
        "palette_report": str(repo_root / "out/decomp/palette_report.json"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Write decomp status.json")
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, default=Path("out/decomp/status.json"))
    args = ap.parse_args()
    status = build_status(args.repo_root.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    if status.get("coverage_summary"):
        print(status["coverage_summary"])


if __name__ == "__main__":
    main()
