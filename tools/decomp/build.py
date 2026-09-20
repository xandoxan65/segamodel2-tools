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


def cmd_decomp_image(args: argparse.Namespace) -> None:
    script = decomp_root() / "container" / "build-image.sh"
    subprocess.run(["bash", str(script)], cwd=decomp_root(), check=True)


def cmd_decomp_shell(args: argparse.Namespace) -> None:
    script = decomp_root() / "container" / "shell.sh"
    os.environ.setdefault("DECOMP_ROOT", str(decomp_root()))
    os.execvp("bash", ["bash", str(script)])


def cmd_decomp_run(args: argparse.Namespace) -> None:
    if not args.cmd:
        raise SystemExit("./build decomp-run requires a command")
    script = decomp_root() / "container" / "run-decomp.sh"
    env = os.environ.copy()
    env.setdefault("DECOMP_ROOT", str(decomp_root()))
    cmd = ["bash", str(script), *args.cmd]
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=decomp_root(), env=env, check=True)


def cmd_ghidra(args: argparse.Namespace) -> None:
    extra: list[str] = []
    if args.no_export_c:
        extra.append("--no-export-c")
    if args.function is not None:
        extra.extend(["--function", args.function])
    elif args.slice is not None:
        extra.extend(["--slice", str(args.slice)])
    else:
        run_module(
            "tools.disasm.ghidra_decompile_ranges",
            "--out",
            "out/ghidra/decompile_report.json",
        )
        if not args.no_export_c:
            run_module(
                "tools.decomp.ghidra_export_c",
                "out/ghidra/decompile_report.json",
                "--repo-root",
                str(decomp_root()),
                "--slice",
                "decompile_report",
            )
        run_module("tools.decomp.status", "--repo-root", str(decomp_root()))
        return
    run_module("tools.decomp.ghidra_slice", *extra)
    run_module("tools.decomp.status", "--repo-root", str(decomp_root()))


def cmd_reasm(args: argparse.Namespace) -> None:
    cmd_extra: list[str] = []
    if args.all:
        cmd_extra.append("--all")
    elif args.slice is not None:
        cmd_extra.extend(["--slice", str(args.slice)])
    else:
        raise SystemExit("./build reasm requires --slice or --all")
    if args.keep:
        cmd_extra.append("--keep")
    if args.rom_dir:
        cmd_extra.extend(["--rom-dir", str(args.rom_dir)])
    if args.report:
        cmd_extra.extend(["--report", str(args.report)])
    if getattr(args, "mode", "gas") != "gas":
        cmd_extra.extend(["--mode", args.mode])
    run_module("tools.decomp.reasm_slice", *cmd_extra)
    run_module("tools.decomp.status", "--repo-root", str(decomp_root()))


def cmd_c_reasm(args: argparse.Namespace) -> None:
    if args.c_source is None or args.rom is None:
        raise SystemExit("./build c-reasm requires --c and --rom 0x<base>:0x<len>")
    cmd_extra = ["--c", str(args.c_source), "--rom", args.rom]
    if args.keep:
        cmd_extra.append("--keep")
    if args.no_peephole:
        cmd_extra.append("--no-peephole")
    if args.rom_dir:
        cmd_extra.extend(["--rom-dir", str(args.rom_dir)])
    if args.report:
        cmd_extra.extend(["--report", str(args.report)])
    for flag in getattr(args, "gcc_extra", []) or []:
        cmd_extra.extend(["--gcc-extra", flag])
    run_module("tools.decomp.c_reasm_slice", *cmd_extra)


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


def cmd_gcc_reasm(args: argparse.Namespace) -> None:
    cmd_extra: list[str] = []
    if args.all:
        cmd_extra.append("--all")
    elif args.slice is not None:
        cmd_extra.extend(["--slice", str(args.slice)])
    else:
        raise SystemExit("./build gcc-reasm requires --slice or --all")
    if args.keep:
        cmd_extra.append("--keep")
    if args.rom_dir:
        cmd_extra.extend(["--rom-dir", str(args.rom_dir)])
    if args.report:
        cmd_extra.extend(["--report", str(args.report)])
    if getattr(args, "compare_gas", False):
        cmd_extra.append("--compare-gas")
    if getattr(args, "mode", "bytes") != "bytes":
        cmd_extra.extend(["--mode", args.mode])
    run_module("tools.decomp.gcc_reasm_slice", *cmd_extra)


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

    reasm_p = sub.add_parser(
        "reasm",
        help="Assemble MAME disasm slice via i960 container; compare bytes to ROM",
    )
    reasm_p.add_argument(
        "--slice",
        type=Path,
        default=None,
        help="disasm/maincpu/maincpu_<addr>_<len>.asm",
    )
    reasm_p.add_argument(
        "--all",
        action="store_true",
        help="Reassemble every maincpu slice under disasm/maincpu",
    )
    reasm_p.add_argument("--keep", action="store_true", help="Keep translated .s/.o/.elf")
    reasm_p.add_argument(
        "--mode",
        choices=("gas", "bytes"),
        default="gas",
        help="Translator mode: gas (mnemonics) or bytes (MAME hex only)",
    )
    reasm_p.add_argument("--report", type=Path, default=None)

    c_reasm_p = sub.add_parser(
        "c-reasm",
        help="Hand C → gcc -S → peephole → i960-elf-as; compare bytes to ROM (tier 3)",
    )
    c_reasm_p.add_argument("--c", type=Path, default=None, dest="c_source")
    c_reasm_p.add_argument(
        "--rom",
        default=None,
        help="ROM slice 0x<base>:0x<len> hex or 0x<base>:<decimal>",
    )
    c_reasm_p.add_argument("--keep", action="store_true")
    c_reasm_p.add_argument(
        "--no-peephole",
        action="store_true",
        help="Skip tools/decomp/gcc_peephole.py transforms",
    )
    c_reasm_p.add_argument(
        "--gcc-extra",
        action="append",
        default=[],
        metavar="FLAG",
        help="Extra i960-elf-gcc flag (repeatable)",
    )
    c_reasm_p.add_argument("--report", type=Path, default=None)

    gcc_reasm_p = sub.add_parser(
        "gcc-reasm",
        help="Assemble MAME slice via i960-elf-gcc; compare bytes to ROM",
    )
    gcc_reasm_p.add_argument("--slice", type=Path, default=None)
    gcc_reasm_p.add_argument("--all", action="store_true")
    gcc_reasm_p.add_argument("--keep", action="store_true")
    gcc_reasm_p.add_argument(
        "--mode",
        choices=("gas", "bytes"),
        default="bytes",
        help="Translator mode (bytes recommended)",
    )
    gcc_reasm_p.add_argument(
        "--compare-gas",
        action="store_true",
        help="Cross-check with i960-elf-as on single-slice runs",
    )
    gcc_reasm_p.add_argument("--report", type=Path, default=None)

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

    ghidra_p = sub.add_parser(
        "ghidra",
        help="Headless Ghidra decompile (runs in container when image is built)",
    )
    ghidra_p.add_argument(
        "--slice",
        type=Path,
        default=None,
        help="Decompile one maincpu disasm slice",
    )
    ghidra_p.add_argument(
        "--function",
        metavar="NAME",
        default=None,
        help="Decompile by symbols/functions.yaml name (auto slice length)",
    )
    ghidra_p.add_argument(
        "--no-export-c",
        action="store_true",
        help="Do not write src/ghidra/ C scaffold files",
    )

    sub.add_parser(
        "decomp-image",
        help="Build Debian decomp container (GCC 2.95.3 + Ghidra + i960)",
    )
    sub.add_parser(
        "decomp-shell",
        help="Interactive shell in decomp container (/src = decomp root)",
    )
    decomp_run_p = sub.add_parser(
        "decomp-run",
        help="Run a command in the decomp container",
    )
    decomp_run_p.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command passed to container (e.g. ./build reasm --all)",
    )

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
        "ghidra": cmd_ghidra,
        "lift": cmd_lift,
        "reasm": cmd_reasm,
        "c-reasm": cmd_c_reasm,
        "gcc-reasm": cmd_gcc_reasm,
        "decomp-image": cmd_decomp_image,
        "decomp-shell": cmd_decomp_shell,
        "decomp-run": cmd_decomp_run,
        "all": cmd_all,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
