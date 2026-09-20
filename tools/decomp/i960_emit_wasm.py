"""Lower i960-ML IR to WebAssembly text (WAT) for simulation."""

from __future__ import annotations

from tools.decomp.i960_ir import IrFunction, IrStmt, StmtKind

# i960 g0-g15 as WASM globals; host provides memory/MMIO.
G_REGS = [f"$g{i}" for i in range(16)]


def emit_wat(fn: IrFunction) -> str:
    lines = [
        "(module",
        '  (import "host" "workram_load" (func $workram_load (param i32) (result i32)))',
        '  (import "host" "workram_store" (func $workram_store (param i32 i32)))',
        '  (import "host" "geo_fifo_write" (func $geo_fifo_write (param i32)))',
        "",
    ]
    for i in range(16):
        lines.append(f"  (global ${i} (mut i32) (i32.const 0))")
    lines.append("")

    params = [(a.name, i) for i, a in enumerate(fn.args)]
    param_types = " ".join("(param i32)" for _ in params)
    lines.append(f"  (func (export \"{fn.name}\") {param_types} (result i32)")

    for i, (name, _) in enumerate(params):
        reg = fn.args[i].reg
        g_idx = int(reg[1:]) if reg.startswith("g") else i
        lines.append(f"    global.set ${g_idx} (local.get {i})  ;; {name}")

    for block in fn.blocks:
        for stmt in block.stmts:
            wat = _stmt_to_wat(stmt)
            if wat:
                lines.extend(f"    {w}" for w in wat)

    lines.append("    i32.const 0")
    lines.append("  )")
    lines.append(")")
    return "\n".join(lines) + "\n"


def _stmt_to_wat(stmt: IrStmt) -> list[str]:
    if stmt.kind == StmtKind.LABEL:
        return [f"(block $L_{stmt.addr:08x} (if (i32.const 1) (then"]
    if stmt.kind == StmtKind.RETURN:
        return ["return"]
    if stmt.kind == StmtKind.RAW:
        return [f";; {stmt.text}"]
    if stmt.kind == StmtKind.ASSIGN:
        return [f";; {stmt.text}"]
    if stmt.kind == StmtKind.BRANCH:
        return [f";; {stmt.text}"]
    if stmt.kind == StmtKind.MACRO:
        return [f";; {stmt.text}"]
    return []


def emit_wat_stub(fn: IrFunction) -> str:
    """Minimal WAT module exporting fn name; body is host-call placeholder."""
    n_args = len(fn.args)
    params = " ".join("(param i32)" for _ in range(n_args))
    return (
        f"(module\n"
        f'  (import "host" "run_lifted" (func $run (param i32 i32 i32) (result i32)))\n'
        f'  (func (export "{fn.name}") {params} (result i32)\n'
        f"    (call $run (local.get 0) (local.get 1) (local.get 2))\n"
        f"  )\n"
        f")\n"
    )
