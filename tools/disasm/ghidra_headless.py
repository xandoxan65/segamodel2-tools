#!/usr/bin/env python3
"""Run Ghidra headless on exported maincpu / region binaries (requires i960 module)."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from tools.disasm.ghidra_paths import analyze_headless, ghidra_env, require_i960_processor


def run_import(binary: Path, project_dir: Path, project_name: str, base: int) -> None:
    require_i960_processor()
    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(analyze_headless()),
        str(project_dir),
        project_name,
        "-import",
        str(binary.resolve()),
        "-processor",
        "i960:LE:32:default",
        "-cspec",
        "default",
        "-loader",
        "BinaryLoader",
        "-loader-baseAddr",
        hex(base),
        "-overwrite",
        "-deleteProject",
    ]
    subprocess.run(cmd, check=True, env=ghidra_env())


def main() -> None:
    ap = argparse.ArgumentParser(description="Ghidra headless import for i960 binaries")
    ap.add_argument("binary", type=Path, help="Raw binary (e.g. out/i960/maincpu_deinterleaved.bin)")
    ap.add_argument("--project", type=Path, default=Path("out/i960/ghidra_project"))
    ap.add_argument("--name", default="srallyc_maincpu")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    try:
        require_i960_processor()
    except FileNotFoundError as exc:
        print(str(exc), file=__import__("sys").stderr)
        raise SystemExit(1) from exc

    run_import(args.binary, args.project, args.name, args.base)
    print(f"Ghidra project: {args.project / args.name}")


if __name__ == "__main__":
    main()
