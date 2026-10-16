#!/usr/bin/env python3
"""Decomp build orchestrator (standalone decomp repo)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from tools.decomp_paths import (
    decomp_root,
    disasm_dir,
    monorepo_root,
    out_dir,
    section_map_path,
)


def run_module(module: str, *args: str) -> None:
    cmd = [sys.executable, "-m", module, *args]
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=decomp_root(), check=True, env=os.environ.copy())


def rom_args(args: argparse.Namespace) -> list[str]:
    if args.rom_dir:
        return ["--rom-dir", str(args.rom_dir)]
    return []


def cmd_analyze(args: argparse.Namespace) -> None:
    root = decomp_root()
    out_i960 = out_dir("i960")
    out_decomp = out_dir("decomp")
    out_i960.mkdir(parents=True, exist_ok=True)
    out_decomp.mkdir(parents=True, exist_ok=True)

    extra = rom_args(args)
    run_module("tools.i960_scan", "--out", "out/i960", *extra)

    maincpu_map = out_i960 / "section_map.json"
    if not maincpu_map.is_file():
        run_module("tools.i960_section_map", "--out", "out/i960/section_map.json", *extra)
    else:
        print(f"Using {maincpu_map}", flush=True)

    main_data_map = out_i960 / "section_map_main_data.json"
    baseline = section_map_path("section_map_main_data.json")
    if not main_data_map.is_file():
        if baseline.is_file() and not extra:
            main_data_map.write_text(baseline.read_text(encoding="utf-8"), encoding="utf-8")
            print(f"Seeded {main_data_map} from {baseline}", flush=True)
        else:
            try:
                if os.environ.get("SEGAMOD2_MONOREPO_ROOT"):
                    env = os.environ.copy()
                    mono = os.environ["SEGAMOD2_MONOREPO_ROOT"]
                    env["PYTHONPATH"] = f"{mono}{os.pathsep}{decomp_root()}{os.pathsep}{env.get('PYTHONPATH', '')}"
                    cmd = [sys.executable, "-m", "tools.decomp.section_map_main_data", "--out", "out/i960/section_map_main_data.json", *extra]
                    print(f"+ {' '.join(cmd)}", flush=True)
                    subprocess.run(cmd, cwd=decomp_root(), check=True, env=env)
                else:
                    raise FileNotFoundError(
                        f"Missing {main_data_map} and no segamod2 parent for regeneration"
                    )
            except subprocess.CalledProcessError:
                if baseline.is_file():
                    main_data_map.write_text(baseline.read_text(encoding="utf-8"), encoding="utf-8")
                    print(f"Fell back to baseline {baseline}", flush=True)
                else:
                    raise

    from tools.decomp.layout import generate_layout, load_yaml_file, merge_layout, write_layout_outputs

    maincpu_map_data = json.loads(maincpu_map.read_text(encoding="utf-8"))
    main_data_map_data = json.loads(main_data_map.read_text(encoding="utf-8"))
    fill_start = int(maincpu_map_data.get("fill_start", "0x0bd568"), 16)
    layout = generate_layout(maincpu_map_data, main_data_map_data, fill_start=fill_start)
    overlay_path = root / "layout.overlay.yaml"
    if overlay_path.is_file():
        layout = merge_layout(layout, load_yaml_file(overlay_path))
    write_layout_outputs(layout, root, out_decomp)

    from tools.decomp.disasm_paths import LEGACY_DISASM, migrate_legacy_disasm

    disasm_root = disasm_dir()
    disasm_root.mkdir(parents=True, exist_ok=True)
    legacy = decomp_root() / LEGACY_DISASM
    moved = migrate_legacy_disasm(legacy=legacy, dest=disasm_root)
    if moved:
        print(f"Migrated {len(moved)} disasm slice(s) → {disasm_root}", flush=True)

    run_module(
        "tools.i960_decode",
        "--disasm-dir",
        "disasm",
        "--out",
        "out/i960/decode_report.json",
    )
    run_module(
        "tools.decomp.disasm_manifest",
        "--repo-root",
        str(root),
    )
    run_module("tools.decomp.export_symbols", "--repo-root", str(root))
    run_module("tools.decomp.memory_header", "--repo-root", str(root))
    run_module("tools.decomp.coverage", "--repo-root", str(root))
    run_module("tools.decomp.status", "--repo-root", str(root))


def cmd_split(args: argparse.Namespace) -> None:
    run_module(
        "tools.decomp.split_rom",
        "--decomp-root",
        ".",
        "--repo-root",
        ".",
        *rom_args(args),
    )


def cmd_verify(args: argparse.Namespace) -> None:
    run_module(
        "tools.decomp.link_rom",
        "--decomp-root",
        ".",
        "--repo-root",
        ".",
        *rom_args(args),
    )
    run_module("tools.decomp.status", "--repo-root", str(decomp_root()))


def cmd_disasm(args: argparse.Namespace) -> None:
    extra = rom_args(args)
    run_module("tools.decomp.disasm_sections", *extra)
    run_module(
        "tools.i960_decode",
        "--disasm-dir",
        "disasm",
        "--out",
        "out/i960/decode_report.json",
    )
    run_module("tools.decomp.status", "--repo-root", str(decomp_root()))


def cmd_coverage(args: argparse.Namespace) -> None:
    root = decomp_root()
    run_module("tools.decomp.coverage", "--repo-root", str(root))
    run_module("tools.decomp.status", "--repo-root", str(root))


def cmd_lift(args: argparse.Namespace) -> None:
    cmd_extra: list[str] = []
    if args.pilot:
        cmd_extra.append("--pilot")
    elif args.slice is not None:
        cmd_extra.extend(["--slice", str(args.slice)])
    else:
        raise SystemExit("./build lift requires --slice or --pilot")
    if args.name:
        cmd_extra.extend(["--name", args.name])
    if args.wasm:
        cmd_extra.append("--wasm")
    if args.out_dir:
        cmd_extra.extend(["--out-dir", str(args.out_dir)])
    if args.src_dir:
        cmd_extra.extend(["--src-dir", str(args.src_dir)])
    run_module("tools.decomp.lift_slice", *cmd_extra)


def cmd_all(args: argparse.Namespace) -> None:
    cmd_analyze(args)
    cmd_split(args)
    cmd_verify(args)


def main() -> None:
    os.environ.setdefault("DECOMP_ROOT", str(decomp_root()))
    ap = argparse.ArgumentParser(description="Sega Rally decomp build (standalone repo)")
    ap.add_argument("--rom-dir", type=Path, default=None, help="MAME ROM directory")
    sub = ap.add_subparsers(dest="command")

    for name, handler in (
        ("analyze", cmd_analyze),
        ("split", cmd_split),
        ("verify", cmd_verify),
        ("coverage", cmd_coverage),
        ("disasm", cmd_disasm),
        ("all", cmd_all),
    ):
        sub.add_parser(name, help=handler.__doc__ or name)

    lift_p = sub.add_parser(
        "lift",
        help="Lift MAME disasm to i960-ML IR, pseudocode, and semantic C",
    )
    lift_p.add_argument(
        "--slice",
        type=Path,
        default=None,
        help="disasm/maincpu/maincpu_<addr>_<len>.asm",
    )
    lift_p.add_argument("--pilot", action="store_true", help="Lift libc_memcpy + libc_strcpy")
    lift_p.add_argument("--name", default=None, help="Function name override")
    lift_p.add_argument("--wasm", action="store_true", help="Also emit .wat")
    lift_p.add_argument("--out-dir", type=Path, default=None)
    lift_p.add_argument("--src-dir", type=Path, default=None)

    if len(sys.argv) == 1:
        sys.argv.append("all")
    args = ap.parse_args()
    if args.command is None:
        args.command = "all"

    handlers = {
        "analyze": cmd_analyze,
        "split": cmd_split,
        "verify": cmd_verify,
        "coverage": cmd_coverage,
        "disasm": cmd_disasm,
        "lift": cmd_lift,
        "all": cmd_all,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
