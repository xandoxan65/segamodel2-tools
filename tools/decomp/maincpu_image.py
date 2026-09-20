#!/usr/bin/env python3
"""Build a full maincpu ROM image from compiled asm/C with reference ROM fill."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.asm_rom_diff import compare_bytes
from tools.decomp.coverage import parse_rom_annotations
from tools.decomp.disasm_paths import SLICE_RE
from tools.decomp.layout import load_yaml_file
from tools.decomp.rom_utils import sha256
from tools.decomp.workspace import DECOMP_ROOT, resolve_in_repo
from tools.i960_memory import MAINCPU_SIZE

DEFAULT_CONFIG = Path("maincpu.image.yaml")


@dataclass(order=True)
class ImageRegion:
    priority: int
    name: str = field(compare=False)
    kind: str = field(compare=False)  # asm | c
    path: Path = field(compare=False)
    start: int = field(compare=False)
    length: int = field(compare=False)

    @property
    def end(self) -> int:
        return self.start + self.length


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return load_yaml_file(path)


def region_from_manifest_row(row: dict, disasm_root: Path) -> ImageRegion | None:
    rel = row.get("file")
    if not rel:
        return None
    asm_path = disasm_root / rel
    if not asm_path.is_file():
        return None
    # geo_cluster_* and other non-slice names are manifest metadata only.
    if not SLICE_RE.match(asm_path.name):
        return None
    try:
        start = int(row["start"], 16)
        end = int(row["end"], 16)
    except (KeyError, ValueError):
        return None
    length = end - start
    if length <= 0 or start < 0 or start + length > MAINCPU_SIZE:
        return None
    return ImageRegion(
        priority=0,
        name=asm_path.stem,
        kind="asm",
        path=asm_path,
        start=start,
        length=length,
    )


def manifest_regions(manifest_path: Path, disasm_root: Path) -> list[ImageRegion]:
    if not manifest_path.is_file():
        return []
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[ImageRegion] = []
    for row in data.get("slices") or []:
        region = region_from_manifest_row(row, disasm_root)
        if region is not None:
            rows.append(region)
    return rows


def src_c_regions(src_root: Path) -> list[ImageRegion]:
    """Discover // @rom annotated C under src/."""
    rows: list[ImageRegion] = []
    if not src_root.is_dir():
        return rows
    for path in sorted(src_root.rglob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for start, end, name_hint in parse_rom_annotations(text):
            length = end - start
            rows.append(
                ImageRegion(
                    priority=50,
                    name=name_hint or path.stem,
                    kind="c",
                    path=path,
                    start=start,
                    length=length,
                )
            )
    return rows


def explicit_regions(config: dict, root: Path) -> list[ImageRegion]:
    rows: list[ImageRegion] = []
    for item in config.get("regions") or []:
        start = int(item["start"], 16) if isinstance(item["start"], str) else int(item["start"])
        length = int(item["length"], 16) if isinstance(item["length"], str) else int(item["length"])
        rows.append(
            ImageRegion(
                priority=int(item.get("priority", 100)),
                name=str(item.get("name") or Path(item["path"]).stem),
                kind=str(item["kind"]),
                path=root / item["path"],
                start=start,
                length=length,
            )
        )
    return rows


def merge_region_lists(lists: list[list[ImageRegion]]) -> list[ImageRegion]:
    """Later lists override earlier on exact (start,length,path) duplicates; sort by priority."""
    seen: dict[tuple[int, int, str], ImageRegion] = {}
    for group in lists:
        for region in group:
            key = (region.start, region.length, str(region.path))
            seen[key] = region
    return sorted(seen.values(), reverse=True)


def compile_region_blob(
    region: ImageRegion,
    *,
    work_dir: Path,
    rom_dir: Path | None,
    require_match: bool,
) -> tuple[bytes | None, dict]:
    """Lifted semantic C and container reasm are not ROM-stitched yet."""
    _ = (work_dir, rom_dir, require_match)
    return None, {
        "skipped": "reference_fill",
        "reason": "semantic lift / asm toolchain removed; using reference ROM bytes",
        "kind": region.kind,
    }


def build_maincpu_image(
    *,
    config_path: Path,
    rom_dir: Path | None = None,
    work_root: Path | None = None,
) -> dict:
    root = DECOMP_ROOT
    config = load_config(config_path)
    options = config.get("options") or {}

    reference_path = resolve_in_repo(Path(config.get("reference", "out/i960/maincpu_deinterleaved.bin")))
    if not reference_path.is_file():
        raise FileNotFoundError(
            f"reference ROM missing: {reference_path} — run: make reference"
        )
    reference = reference_path.read_bytes()
    if len(reference) != MAINCPU_SIZE:
        raise ValueError(f"expected 0x{MAINCPU_SIZE:x} byte reference, got 0x{len(reference):x}")

    output_path = resolve_in_repo(Path(config.get("output", "out/maincpu/maincpu_rebuilt.bin")))
    report_path = resolve_in_repo(Path(config.get("report", "out/maincpu/maincpu_image.json")))
    work_root = resolve_in_repo(work_root or Path("out/maincpu/regions"))

    region_lists: list[list[ImageRegion]] = []
    if options.get("include_disasm_manifest", False):
        region_lists.append(
            manifest_regions(root / "disasm/manifest.json", root / "disasm")
        )
    if options.get("include_src_c", options.get("include_spike_c", False)):
        region_lists.append(src_c_regions(root / "src"))
    region_lists.append(explicit_regions(config, root))
    regions = merge_region_lists(region_lists)

    require_match = bool(options.get("require_region_match", True))
    on_fail = str(options.get("on_fail", "keep_rom"))

    image = bytearray(reference)
    owned = bytearray(MAINCPU_SIZE)
    region_rows: list[dict] = []
    patched_bytes = 0
    compiled_regions = 0
    failed_regions = 0
    skipped_overlap = 0

    for region in regions:
        if region.start + region.length > MAINCPU_SIZE:
            failed_regions += 1
            region_rows.append(
                {
                    "name": region.name,
                    "kind": region.kind,
                    "path": str(region.path.relative_to(root)),
                    "start": f"0x{region.start:08x}",
                    "length": region.length,
                    "status": "fail",
                    "error": "range outside maincpu ROM",
                }
            )
            continue

        if any(owned[region.start : region.end]):
            skipped_overlap += 1
            region_rows.append(
                {
                    "name": region.name,
                    "kind": region.kind,
                    "path": str(region.path.relative_to(root)),
                    "start": f"0x{region.start:08x}",
                    "length": region.length,
                    "priority": region.priority,
                    "status": "skipped_overlap",
                }
            )
            continue

        if not region.path.is_file():
            failed_regions += 1
            region_rows.append(
                {
                    "name": region.name,
                    "kind": region.kind,
                    "path": str(region.path),
                    "start": f"0x{region.start:08x}",
                    "length": region.length,
                    "status": "fail",
                    "error": "source not found",
                }
            )
            if on_fail == "abort":
                raise FileNotFoundError(region.path)
            continue

        blob, detail = compile_region_blob(
            region,
            work_dir=work_root / region.name,
            rom_dir=rom_dir,
            require_match=require_match,
        )
        row = {
            "name": region.name,
            "kind": region.kind,
            "path": str(region.path.relative_to(root)),
            "start": f"0x{region.start:08x}",
            "length": region.length,
            "priority": region.priority,
            "detail": {k: v for k, v in detail.items() if k not in ("translation",)},
        }
        if blob is None:
            skipped = detail.get("skipped")
            if skipped == "reference_fill":
                region_rows.append(
                    {
                        **row,
                        "status": "reference_fill",
                        "note": detail.get("reason"),
                    }
                )
                continue
            failed_regions += 1
            row["status"] = "fail"
            row["error"] = detail.get("error") or detail.get("skipped") or "compile failed"
            region_rows.append(row)
            if on_fail == "abort":
                raise RuntimeError(f"region {region.name} failed: {row['error']}")
            continue

        if len(blob) != region.length:
            failed_regions += 1
            row["status"] = "fail"
            row["error"] = f"blob length 0x{len(blob):x} != 0x{region.length:x}"
            region_rows.append(row)
            if on_fail == "abort":
                raise ValueError(row["error"])
            continue

        image[region.start : region.end] = blob
        owned[region.start : region.end] = b"\x01" * region.length
        patched_bytes += region.length
        compiled_regions += 1
        row["status"] = "patched"
        row["match"] = detail.get("match", True)
        region_rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(image)

    compare = compare_bytes(reference, bytes(image), base=0)
    fill_bytes = MAINCPU_SIZE - patched_bytes

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": str(config_path.relative_to(root)),
        "reference": str(reference_path.relative_to(root)),
        "output": str(output_path.relative_to(root)),
        "report_path": str(report_path.relative_to(root)),
        "reference_sha256": sha256(reference),
        "output_sha256": sha256(bytes(image)),
        "match": compare["match"],
        "mismatch_bytes": compare["mismatch_bytes"],
        "first_diff": compare.get("first_diff"),
        "summary": {
            "regions_total": len(regions),
            "regions_patched": compiled_regions,
            "regions_failed": failed_regions,
            "regions_skipped_overlap": skipped_overlap,
            "patched_bytes": patched_bytes,
            "fill_bytes": fill_bytes,
            "fill_pct": round(100 * fill_bytes / MAINCPU_SIZE, 2),
        },
        "regions": region_rows,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Build full maincpu image (compile + ROM fill)")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--work-dir", type=Path, default=Path("out/maincpu/regions"))
    args = ap.parse_args()

    config_path = resolve_in_repo(args.config)
    report = build_maincpu_image(
        config_path=config_path,
        rom_dir=args.rom_dir,
        work_root=args.work_dir,
    )
    summary = report["summary"]
    status = "PASS" if report["match"] else "FAIL"
    print(
        f"Maincpu image {status}: patched {summary['patched_bytes']} B "
        f"({100 - summary['fill_pct']:.2f}% compiled), "
        f"fill {summary['fill_bytes']} B from reference"
    )
    print(f"  regions: {summary['regions_patched']} ok, "
          f"{summary['regions_failed']} fail, "
          f"{summary['regions_skipped_overlap']} overlap-skip")
    print(f"  output → {report['output']}")
    print(f"  report → {report['report_path']}")
    if not report["match"]:
        diff = report.get("first_diff") or {}
        print(
            f"  mismatch_bytes={report['mismatch_bytes']} "
            f"first @ {diff.get('rom_addr', '?')}"
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
