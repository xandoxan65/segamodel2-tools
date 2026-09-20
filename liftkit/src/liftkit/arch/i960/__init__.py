"""i960 ArchPlugin — MAME listing → IR → C scaffold."""

from __future__ import annotations

from pathlib import Path

from liftkit.arch.base import LiftArtifacts, ParsedSlice, register_arch
from liftkit.arch.i960.disasm_parse import SliceDocument, parse_slice_file, write_slice_json
from liftkit.arch.i960.i960_abi import clear_abi_catalog_cache, merge_abi_catalog, write_abi_json
from liftkit.arch.i960.i960_cfg import find_structured_regions
from liftkit.arch.i960.i960_emit_c import emit_c
from liftkit.arch.i960.i960_emit_rodata import emit_rodata_c
from liftkit.arch.i960.i960_emit_wasm import emit_wat
from liftkit.arch.i960.i960_idioms import apply_idioms
from liftkit.arch.i960.i960_ir import lift_slice as ir_lift_slice, write_ir_json
from liftkit.arch.i960.i960_macros import apply_macros, detect_function_profile, emit_lifted_text
from liftkit.arch.i960.i960_ptr_pass import apply_pointer_pass
from liftkit.arch.i960.i960_reg_alias import build_typed_param_aliases, refine_param_types
from liftkit.arch.i960.symbol_kind import lookup_symbol_kind
from liftkit.project.workspace import resolve_in_repo


class I960Plugin:
    name = "i960"

    def parse_slice(self, path: Path) -> ParsedSlice:
        doc = parse_slice_file(path)
        return ParsedSlice(
            arch=self.name,
            base=doc.base,
            length=doc.length,
            source=str(path),
            raw=doc,
        )

    def lift(self, parsed: ParsedSlice, *, name: str) -> LiftArtifacts:
        doc: SliceDocument = parsed.raw
        kind = lookup_symbol_kind(name, doc.base)

        if kind == "rodata":
            return LiftArtifacts(
                name=name,
                arch=self.name,
                addr=doc.base,
                length=doc.length,
                kind="rodata",
                ir=None,
                scaffold_c=emit_rodata_c(doc, name=name),
                lifted_text=f"/* rodata @ 0x{doc.base:x} +0x{doc.length:x} — {name} */\n",
            )

        profile = detect_function_profile(doc.insns)
        macro_stmts = apply_idioms(apply_macros(doc, profile))
        ir_fn = ir_lift_slice(doc, name=name, profile=profile, macro_stmts=macro_stmts)
        apply_pointer_pass(ir_fn)
        if ir_fn.abi and ir_fn.abi.has_c_abi:
            ir_fn.param_aliases = build_typed_param_aliases(
                ir_fn.abi,
                refine_param_types(ir_fn),
            )
        ir_fn.regions = find_structured_regions(ir_fn)

        abi_doc = None
        if ir_fn.abi:
            abi_doc = ir_fn.abi.to_abi_document(
                name=name,
                addr=doc.base,
                kind=profile.kind.value,
            )

        return LiftArtifacts(
            name=name,
            arch=self.name,
            addr=doc.base,
            length=doc.length,
            kind=profile.kind.value,
            ir=ir_fn,
            scaffold_c=emit_c(ir_fn),
            lifted_text=emit_lifted_text(macro_stmts, name=name, profile=profile, doc=doc),
            abi=abi_doc,
            extras={"emit_wat": emit_wat},
        )

    def runtime_header(self) -> Path | None:
        here = Path(__file__).resolve().parents[4]  # liftkit/
        cand = here / "runtime" / "i960.h"
        return cand if cand.is_file() else None


PLUGIN = I960Plugin()
register_arch(PLUGIN)


def write_lift_outputs(
    artifacts: LiftArtifacts,
    *,
    out_dir: Path,
    src_dir: Path,
    slice_path: Path,
    emit_wasm: bool = False,
    merge_abi: bool = True,
) -> dict:
    """Write IR/C/ABI artifacts to disk (decomp-compatible layout)."""
    out_dir = resolve_in_repo(out_dir)
    src_dir = resolve_in_repo(src_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    src_dir.mkdir(parents=True, exist_ok=True)

    stem = artifacts.name
    json_path = out_dir / f"{stem}.json"
    lifted_path = out_dir / f"{stem}.lifted"
    ir_path = out_dir / f"{stem}.ir.json"
    c_path = src_dir / f"{stem}.c"
    wat_path = out_dir / f"{stem}.wat"

    doc = parse_slice_file(slice_path)
    write_slice_json(doc, json_path)
    lifted_path.write_text(artifacts.lifted_text, encoding="utf-8")
    # Scaffold always written as .lifted.c; curated .c only if missing
    scaffold_path = src_dir / f"{stem}.lifted.c"
    scaffold_path.write_text(artifacts.scaffold_c, encoding="utf-8")
    if not c_path.is_file():
        c_path.write_text(artifacts.scaffold_c, encoding="utf-8")

    abi_path = None
    if artifacts.ir is not None:
        write_ir_json(artifacts.ir, ir_path)
    if artifacts.abi:
        abi_path = out_dir / f"{stem}.abi.json"
        write_abi_json(abi_path, artifacts.abi)
        if merge_abi:
            merge_abi_catalog(resolve_in_repo(Path("symbols/function_abi.json")), artifacts.abi)
            clear_abi_catalog_cache()

    if emit_wasm and artifacts.ir is not None and artifacts.extras and "emit_wat" in artifacts.extras:
        wat_path.write_text(artifacts.extras["emit_wat"](artifacts.ir), encoding="utf-8")

    return {
        "name": artifacts.name,
        "arch": artifacts.arch,
        "slice": str(slice_path),
        "kind": artifacts.kind,
        "addr": f"0x{artifacts.addr:x}",
        "length": artifacts.length,
        "outputs": {
            "json": str(json_path),
            "lifted": str(lifted_path),
            "ir": str(ir_path) if artifacts.ir is not None else None,
            "abi": str(abi_path) if abi_path else None,
            "c": str(c_path),
            "scaffold_c": str(scaffold_path),
            "wat": str(wat_path) if emit_wasm and wat_path.is_file() else None,
        },
    }
