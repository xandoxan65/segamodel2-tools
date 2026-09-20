#!/usr/bin/env python3
"""Ghidra headless decompile for a single maincpu disasm slice (container-friendly)."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from tools.decomp.ghidra_export_c import export_ghidra_json

REPO_ROOT = Path(__file__).resolve().parents[2]
SLICE_NAME = re.compile(r"^maincpu_([0-9a-f]+)_([0-9a-f]+)\.asm$", re.I)
CONTAINER_GHIDRA = REPO_ROOT / "tooling/i960/container/run-decomp.sh"


def parse_slice_path(path: Path) -> tuple[int, int]:
    match = SLICE_NAME.match(path.name)
    if not match:
        raise ValueError(f"expected maincpu_<addr>_<len>.asm, got {path.name}")
    return int(match.group(1), 16), int(match.group(2), 16)


def ensure_maincpu_binary(*, rom_dir: Path | None, out_dir: Path) -> Path:
    binary = out_dir / "maincpu_deinterleaved.bin"
    if binary.is_file() and binary.stat().st_size > 0:
        return binary
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "tools.i960_scan", "--out", str(out_dir)]
    if rom_dir is not None:
        cmd.extend(["--rom-dir", str(rom_dir)])
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    if not binary.is_file():
        raise FileNotFoundError(f"scan did not produce {binary}")
    return binary


def main() -> None:
    ap = argparse.ArgumentParser(description="Ghidra decompile one maincpu disasm slice")
    ap.add_argument(
        "--slice",
        type=Path,
        required=True,
        help="decomp/disasm/maincpu/maincpu_<addr>_<len>.asm",
    )
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument(
        "--binary",
        type=Path,
        default=Path("out/i960/maincpu_deinterleaved.bin"),
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="JSON report (default: out/decomp/ghidra/<slice_stem>.json)",
    )
    ap.add_argument(
        "--project",
        type=Path,
        default=Path("out/decomp/ghidra/projects"),
    )
    ap.add_argument(
        "--in-container",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--no-export-c",
        action="store_true",
        help="Skip exporting decompiled C scaffold to decomp/src/ghidra/",
    )
    args = ap.parse_args()

    slice_asm = args.slice if args.slice.is_absolute() else REPO_ROOT / args.slice
    if not slice_asm.is_file():
        raise SystemExit(f"slice not found: {slice_asm}")

    base, length = parse_slice_path(slice_asm)
    range_spec = f"0x{base:x}:0x{base + length:x}"

    binary = args.binary if args.binary.is_absolute() else REPO_ROOT / args.binary
    if not binary.is_file():
        binary = ensure_maincpu_binary(rom_dir=args.rom_dir, out_dir=binary.parent)

    out_path = args.out
    if out_path is None:
        out_path = Path("out/decomp/ghidra") / f"{slice_asm.stem}.json"
    if not out_path.is_absolute():
        out_path = REPO_ROOT / out_path

    if not args.in_container and CONTAINER_GHIDRA.is_file():
        cmd = [
            "bash",
            str(CONTAINER_GHIDRA),
            "python3",
            "-m",
            "tools.decomp.ghidra_slice",
            "--slice",
            str(slice_asm.relative_to(REPO_ROOT)),
            "--binary",
            str(binary.relative_to(REPO_ROOT)),
            "--out",
            str(out_path.relative_to(REPO_ROOT)),
            "--project",
            str(
                (args.project if args.project.is_absolute() else REPO_ROOT / args.project).relative_to(
                    REPO_ROOT
                )
            ),
            "--in-container",
        ]
        if args.rom_dir:
            cmd.extend(["--rom-dir", str(args.rom_dir)])
        if args.no_export_c:
            cmd.append("--no-export-c")
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)
        print(f"Ghidra slice report → {out_path}")
        if not args.no_export_c:
            _export_c_scaffold(out_path, slice_asm.stem, args)
        return

    cmd = [
        "python3",
        "-m",
        "tools.disasm.ghidra_decompile_ranges",
        "--binary",
        str(binary),
        "--project",
        str(args.project if args.project.is_absolute() else REPO_ROOT / args.project),
        "--out",
        str(out_path),
        "--ranges",
        range_spec,
        "--name",
        slice_asm.stem,
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    print(f"Ghidra slice report → {out_path}")
    if not args.no_export_c:
        _export_c_scaffold(out_path, slice_asm.stem, args)


def _export_c_scaffold(out_path: Path, slice_label: str, args: argparse.Namespace) -> None:
    raw_path = out_path.with_suffix(".raw.json")
    source = raw_path if raw_path.is_file() else out_path
    manifest = export_ghidra_json(source, repo_root=REPO_ROOT, slice_label=slice_label)
    print(
        f"C scaffold → {manifest['dest_dir']}/ ({len(manifest['exported'])} files, "
        f"{len(manifest['skipped'])} skipped)"
    )


if __name__ == "__main__":
    main()
