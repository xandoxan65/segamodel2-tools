"""liftkit command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from liftkit import __version__
from liftkit.api import available_arches, lift_address, lift_function, lift_slice, rewrite_function
from liftkit.project.workspace import set_project_root


def _add_project(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--project",
        type=Path,
        default=None,
        help="Project root (symbols/, disasm/, src/). Default: LIFTKIT_PROJECT or cwd",
    )


def cmd_arches(_args: argparse.Namespace) -> int:
    for name in available_arches():
        print(name)
    return 0


def cmd_lift(args: argparse.Namespace) -> int:
    if args.project:
        set_project_root(args.project)

    if args.mame:
        if args.address is None or args.length is None:
            print("--mame requires --address and --length", file=sys.stderr)
            return 2
        from liftkit.disasm.mame_i960 import disasm_maincpu_slice
        from liftkit.project.workspace import project_root

        slice_path = disasm_maincpu_slice(
            int(args.address, 0),
            int(args.length, 0),
            project=project_root(),
            rom_dir=args.rom_dir,
        )
        print(f"Wrote {slice_path}", flush=True)
        result = lift_slice(
            slice_path,
            arch=args.arch,
            name=args.name,
            out_dir=args.out_dir,
            src_dir=args.src_dir,
            emit_wasm=args.wasm,
        )
    elif args.function:
        result = lift_function(
            args.function,
            arch=args.arch,
            out_dir=args.out_dir,
            src_dir=args.src_dir,
            emit_wasm=args.wasm,
            length=int(args.length, 0) if args.length else None,
        )
    elif args.address is not None:
        if args.length is None:
            print("--address requires --length", file=sys.stderr)
            return 2
        result = lift_address(
            args.address,
            args.length,
            arch=args.arch,
            name=args.name,
            out_dir=args.out_dir,
            src_dir=args.src_dir,
            emit_wasm=args.wasm,
        )
    elif args.slice:
        result = lift_slice(
            args.slice,
            arch=args.arch,
            name=args.name,
            out_dir=args.out_dir,
            src_dir=args.src_dir,
            emit_wasm=args.wasm,
        )
    else:
        print("lift requires --slice, --function, or --address/--length", file=sys.stderr)
        return 2

    print(json.dumps(result.report, indent=2))
    return 0


def cmd_disasm(args: argparse.Namespace) -> int:
    if args.project:
        set_project_root(args.project)
    from liftkit.disasm.mame_i960 import disasm_maincpu_slice
    from liftkit.project.workspace import project_root

    if args.arch != "i960":
        print(f"disasm for arch {args.arch!r} is not implemented yet (i960 only)", file=sys.stderr)
        return 2
    addr = int(args.address, 0)
    length = int(args.length, 0)
    path = disasm_maincpu_slice(
        addr,
        length,
        project=project_root(),
        rom_dir=args.rom_dir,
        out_dir=args.out,
    )
    print(json.dumps({"arch": "i960", "address": f"0x{addr:x}", "length": length, "slice": str(path)}, indent=2))
    return 0


def cmd_rewrite(args: argparse.Namespace) -> int:
    if args.project:
        set_project_root(args.project)
    result = rewrite_function(
        args.function,
        arch=args.arch,
        provider=args.provider,
        apply=args.apply,
    )
    print(
        json.dumps(
            {
                "name": args.function,
                "provider": result.provider,
                "model": result.model,
                "prompt_hash": result.prompt_hash,
                "draft": result.draft_path,
                "applied": result.applied_path,
            },
            indent=2,
        )
    )
    return 0


def cmd_project(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from liftkit.project import catalog

    if args.project_cmd == "status":
        if args.project:
            set_project_root(args.project)
        print(json.dumps(asdict(catalog.project_summary()), indent=2))
        return 0
    if args.project_cmd == "open":
        summary = catalog.open_project(Path(args.path))
        print(json.dumps(summary, indent=2))
        return 0
    if args.project_cmd == "init":
        summary = catalog.init_project(Path(args.path), name=args.name)
        print(json.dumps(summary, indent=2))
        return 0
    if args.project_cmd == "functions":
        if args.project:
            set_project_root(args.project)
        rows = catalog.inventory_functions()
        if args.status:
            rows = [r for r in rows if r.status == args.status]
        print(json.dumps([asdict(r) for r in rows], indent=2))
        return 0
    if args.project_cmd == "recent":
        print(json.dumps(catalog.recent_projects(), indent=2))
        return 0
    print("unknown project subcommand", file=sys.stderr)
    return 2


def cmd_gui(args: argparse.Namespace) -> int:
    if args.project:
        set_project_root(args.project)
    try:
        import uvicorn
    except ImportError:
        print("GUI requires: pip install 'liftkit[gui]'", file=sys.stderr)
        return 1
    from liftkit.gui.app import create_app

    app = create_app(project=args.project)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="liftkit", description="Multi-ISA uplift toolkit")
    ap.add_argument("--version", action="version", version=f"liftkit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_arches = sub.add_parser("arches", help="List registered architectures")
    p_arches.set_defaults(func=cmd_arches)

    p_lift = sub.add_parser("lift", help="Deterministic disasm → IR → C scaffold")
    _add_project(p_lift)
    p_lift.add_argument("--arch", default="i960", help="Architecture plugin (default: i960)")
    p_lift.add_argument("--slice", type=Path, help="MAME/disasm .asm slice path")
    p_lift.add_argument("--function", help="Lift by symbols/functions.yaml name")
    p_lift.add_argument("--address", help="Function address (hex/dec)")
    p_lift.add_argument("--length", help="Slice length (hex/dec)")
    p_lift.add_argument(
        "--mame",
        action="store_true",
        help="Run MAME i960dasm for --address/--length before lift",
    )
    p_lift.add_argument("--rom-dir", type=Path, default=None, help="ROM directory for --mame")
    p_lift.add_argument("--name", default=None, help="Output function name")
    p_lift.add_argument("--out-dir", type=Path, default=Path("out/lift"))
    p_lift.add_argument("--src-dir", type=Path, default=None)
    p_lift.add_argument("--wasm", action="store_true", help="Also emit .wat")
    p_lift.set_defaults(func=cmd_lift)

    p_disasm = sub.add_parser("disasm", help="Disassemble a ROM slice (i960 via MAME)")
    _add_project(p_disasm)
    p_disasm.add_argument("--arch", default="i960")
    p_disasm.add_argument("--address", required=True, help="Start address (hex/dec)")
    p_disasm.add_argument("--length", required=True, help="Byte length (hex/dec)")
    p_disasm.add_argument("--rom-dir", type=Path, default=None)
    p_disasm.add_argument("--out", type=Path, default=None, help="Output directory (default: disasm/maincpu)")
    p_disasm.set_defaults(func=cmd_disasm)

    p_rw = sub.add_parser("rewrite", help="Optional AI semantic rewrite (post-lift)")
    _add_project(p_rw)
    p_rw.add_argument("--function", required=True, help="Function name previously lifted")
    p_rw.add_argument("--arch", default="i960")
    p_rw.add_argument(
        "--provider",
        default=None,
        help="echo (default) | openai — live needs LIFTKIT_API_KEY",
    )
    p_rw.add_argument(
        "--apply",
        action="store_true",
        help="Write curated src/<section>/<name>.c (default: only *.semantic.c draft)",
    )
    p_rw.set_defaults(func=cmd_rewrite)

    p_proj = sub.add_parser("project", help="Manage lift projects (open/init/status/functions)")
    p_proj_sub = p_proj.add_subparsers(dest="project_cmd", required=True)
    p_st = p_proj_sub.add_parser("status", help="Summarize active or --project root")
    _add_project(p_st)
    p_st.set_defaults(func=cmd_project)
    p_open = p_proj_sub.add_parser("open", help="Remember and activate a project root")
    p_open.add_argument("path", type=Path)
    p_open.set_defaults(func=cmd_project)
    p_init = p_proj_sub.add_parser("init", help="Create a new project skeleton")
    p_init.add_argument("path", type=Path)
    p_init.add_argument("--name", default=None)
    p_init.set_defaults(func=cmd_project)
    p_fns = p_proj_sub.add_parser("functions", help="List catalog functions + lift status")
    _add_project(p_fns)
    p_fns.add_argument("--status", default=None, help="Filter: curated|scaffold|not_lifted|…")
    p_fns.set_defaults(func=cmd_project)
    p_recent = p_proj_sub.add_parser("recent", help="List recent project paths")
    p_recent.set_defaults(func=cmd_project)

    p_gui = sub.add_parser("gui", help="Local web UI")
    _add_project(p_gui)
    p_gui.add_argument("--host", default="127.0.0.1")
    p_gui.add_argument("--port", type=int, default=8765)
    p_gui.set_defaults(func=cmd_gui)

    args = ap.parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
