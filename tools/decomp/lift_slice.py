#!/usr/bin/env python3
"""Lift MAME disasm slices to i960-ML IR, annotated pseudocode, C, and WAT."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from tools.decomp.disasm_parse import parse_slice_file, write_slice_json
from tools.decomp.i960_cfg import find_structured_regions
from tools.decomp.i960_emit_c import emit_c
from tools.decomp.i960_emit_rodata import emit_rodata_c
from tools.decomp.i960_emit_wasm import emit_wat
from tools.decomp.i960_idioms import apply_idioms
from tools.decomp.i960_abi import clear_abi_catalog_cache, merge_abi_catalog, write_abi_json
from tools.decomp.i960_ptr_pass import apply_pointer_pass
from tools.decomp.i960_reg_alias import build_typed_param_aliases, refine_param_types
from tools.decomp.i960_ir import lift_slice, write_ir_json
from tools.decomp.i960_macros import (
    apply_macros,
    detect_function_profile,
    emit_lifted_text,
)
from tools.decomp.symbol_kind import default_src_dir, lookup_symbol_kind
from tools.decomp.workspace import resolve_in_repo


def _lookup_function_name(addr: int, repo_root: Path) -> str | None:
    fn_yaml = repo_root / "symbols" / "functions.yaml"
    if not fn_yaml.is_file():
        return None
    data = yaml.safe_load(fn_yaml.read_text(encoding="utf-8"))
    for entry in data.get("functions", []):
        if int(entry.get("address", -1)) == addr:
            return entry.get("name")
    return None


def _default_name(doc_path: Path, repo_root: Path) -> str:
    from tools.decomp.disasm_parse import parse_slice_name

    parsed = parse_slice_name(doc_path)
    if parsed:
        name = _lookup_function_name(parsed[0], repo_root)
        if name:
            return name
        return f"fn_{parsed[0]:06x}"
    return doc_path.stem


def lift_one(
    slice_path: Path,
    *,
    name: str | None = None,
    out_dir: Path,
    src_dir: Path | None = None,
    emit_wasm: bool = False,
    symbol_kind: str | None = None,
) -> dict:
    repo_root = resolve_in_repo(Path("."))
    slice_path = resolve_in_repo(slice_path)
    doc = parse_slice_file(slice_path)
    fn_name = name or _default_name(slice_path, repo_root)
    kind = symbol_kind or lookup_symbol_kind(fn_name, doc.base)
    if src_dir is None:
        src_dir = default_src_dir(fn_name)

    out_dir = resolve_in_repo(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = fn_name
    json_path = out_dir / f"{stem}.json"
    lifted_path = out_dir / f"{stem}.lifted"
    ir_path = out_dir / f"{stem}.ir.json"
    c_path = resolve_in_repo(src_dir) / f"{stem}.c"
    wat_path = out_dir / f"{stem}.wat"

    write_slice_json(doc, json_path)

    if kind == "rodata":
        c_path.parent.mkdir(parents=True, exist_ok=True)
        c_path.write_text(emit_rodata_c(doc, name=fn_name), encoding="utf-8")
        lifted_path.write_text(
            f"/* rodata @ 0x{doc.base:x} +0x{doc.length:x} — {fn_name} */\n",
            encoding="utf-8",
        )
        report = {
            "name": fn_name,
            "slice": str(slice_path),
            "kind": "rodata",
            "addr": f"0x{doc.base:x}",
            "length": doc.length,
            "outputs": {
                "json": str(json_path),
                "lifted": str(lifted_path),
                "ir": None,
                "abi": None,
                "c": str(c_path),
            },
        }
        return report

    profile = detect_function_profile(doc.insns)
    macro_stmts = apply_idioms(apply_macros(doc, profile))
    ir_fn = lift_slice(doc, name=fn_name, profile=profile, macro_stmts=macro_stmts)
    apply_pointer_pass(ir_fn)
    if ir_fn.abi and ir_fn.abi.has_c_abi:
        ir_fn.param_aliases = build_typed_param_aliases(
            ir_fn.abi,
            refine_param_types(ir_fn),
        )
    ir_fn.regions = find_structured_regions(ir_fn)

    lifted_path.write_text(
        emit_lifted_text(macro_stmts, name=fn_name, profile=profile, doc=doc),
        encoding="utf-8",
    )
    write_ir_json(ir_fn, ir_path)
    abi_path: Path | None = None
    if ir_fn.abi:
        abi_path = out_dir / f"{stem}.abi.json"
        abi_doc = ir_fn.abi.to_abi_document(
            name=fn_name,
            addr=doc.base,
            kind=profile.kind.value,
        )
        write_abi_json(abi_path, abi_doc)
        merge_abi_catalog(repo_root / "symbols" / "function_abi.json", abi_doc)
        clear_abi_catalog_cache()
    c_path.parent.mkdir(parents=True, exist_ok=True)
    c_path.write_text(emit_c(ir_fn), encoding="utf-8")
    if emit_wasm:
        wat_path.write_text(emit_wat(ir_fn), encoding="utf-8")

    report = {
        "name": fn_name,
        "slice": str(slice_path),
        "kind": profile.kind.value,
        "addr": f"0x{doc.base:x}",
        "length": doc.length,
        "outputs": {
            "json": str(json_path),
            "lifted": str(lifted_path),
            "ir": str(ir_path),
            "abi": str(abi_path) if ir_fn.abi else None,
            "c": str(c_path),
        },
    }
    if emit_wasm:
        report["outputs"]["wat"] = str(wat_path)
    return report


def cmd_pilot(repo_root: Path) -> int:
    pilots = [
        ("disasm/maincpu/maincpu_05daa0_140.asm", "libc_memcpy"),
        ("asm/libc/maincpu_05cdc8_03c.asm", "libc_strcpy"),
    ]
    reports = []
    for rel, name in pilots:
        path = repo_root / rel
        if not path.is_file():
            print(f"skip missing pilot slice: {path}", file=sys.stderr)
            continue
        reports.append(
            lift_one(
                path,
                name=name,
                out_dir=Path("out/lift"),
                src_dir=Path("src/libc"),
                emit_wasm=True,
            )
        )
    report_path = repo_root / "out/lift/pilot_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {report_path} ({len(reports)} functions)")
    for r in reports:
        print(f"  {r['name']} @ {r['addr']} kind={r['kind']} → {r['outputs']['c']}")
    return 0 if reports else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Lift MAME disasm to i960-ML IR + C + WAT")
    ap.add_argument("--function", metavar="NAME", help="Lift by symbols/functions.yaml name")
    ap.add_argument("--slice", type=Path, help="MAME .asm slice path")
    ap.add_argument("--name", default=None, help="Function name (default: symbols/functions.yaml)")
    ap.add_argument("--out-dir", type=Path, default=Path("out/lift"))
    ap.add_argument("--src-dir", type=Path, default=None, help="Semantic C output dir (default: from section)")
    ap.add_argument("--wasm", action="store_true", help="Also emit .wat")
    ap.add_argument("--pilot", action="store_true", help="Run memcpy + strcpy pilot slices")
    args = ap.parse_args()

    repo_root = resolve_in_repo(Path("."))

    if args.pilot:
        raise SystemExit(cmd_pilot(repo_root))

    slice_path = args.slice
    fn_name = args.name
    if args.function:
        from tools.decomp.function_slice import plan_function_slice

        plan = plan_function_slice(args.function)
        slice_path = plan.slice_path
        fn_name = fn_name or plan.name
        print(f"/* {plan.note} */", flush=True)

    if slice_path is None:
        ap.error("requires --slice, --function, or --pilot")

    report = lift_one(
        slice_path,
        name=fn_name,
        out_dir=args.out_dir,
        src_dir=args.src_dir,
        emit_wasm=args.wasm,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
