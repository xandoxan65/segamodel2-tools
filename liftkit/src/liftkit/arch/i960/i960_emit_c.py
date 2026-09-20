"""Emit semantic C from i960-ML IR."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from liftkit.arch.i960.i960_cfg import IfElseRegion, IfThenRegion, WhileRegion
from liftkit.arch.i960.i960_ir import IrBlock, IrFunction, IrStmt, StmtKind
from liftkit.arch.i960.i960_ptr_pass import function_needs_mem_header, function_needs_rom_header
from liftkit.arch.i960.i960_reg_alias import (
    AliasContext,
    RegAliasState,
    build_typed_param_aliases,
    compute_block_alias_states,
    emit_param_alias_lines,
    emit_param_reg_loads,
    refine_param_types,
    substitute_reg_aliases,
)
from liftkit.arch.i960.i960_symbols import format_call, format_extern_decl, lookup_symbol_name

# g*/r* are shared extern state in i960_lift.h.

_LABEL_IN_BRANCH = re.compile(r"goto\s+(L_[0-9a-fA-F]+)")
_REG_TOKEN = re.compile(r"\b([gr]\d+|r\d+)\b")
_BYTE_ZERO = re.compile(r"\(unsigned char\)0\b")
_SIGNED_BYTE_ZERO = re.compile(r"\(signed char\)0\b")
_CALL_ADDR = re.compile(r"^call\s+(0x[0-9a-fA-F]+)\s*;?\s*$", re.I)
_CALL_INDIRECT = re.compile(r"^call\s+\(([^)]+)\)\s*;?\s*$", re.I)


@dataclass
class EmitContext:
    fn: IrFunction
    alias_state: RegAliasState = field(default_factory=RegAliasState)
    block_alias_states: dict[int, dict[str, str]] = field(default_factory=dict)


def _build_emit_context(fn: IrFunction) -> EmitContext:
    ctx = EmitContext(fn=fn)
    if fn.abi and fn.abi.has_c_abi and fn.param_aliases:
        alias_ctx = AliasContext.from_param_aliases(fn.param_aliases)
        ctx.alias_state = RegAliasState(
            alias_ctx.reg_to_var,
            pointer_vars=alias_ctx.pointer_vars,
        )
        ctx.block_alias_states = compute_block_alias_states(fn)
    return ctx


def _restore_block_aliases(ctx: EmitContext, block_addr: int | None) -> None:
    if block_addr is None or not ctx.block_alias_states:
        return
    entry = ctx.block_alias_states.get(block_addr)
    if entry is not None:
        ctx.alias_state.aliases = dict(entry)


def _collect_call_addrs(fn: IrFunction) -> set[int]:
    addrs: set[int] = set()
    for block in fn.blocks:
        for stmt in block.stmts:
            if stmt.target is not None:
                addrs.add(stmt.target)
            if stmt.kind != StmtKind.CALL:
                continue
            m = _CALL_ADDR.match(stmt.text.strip().rstrip(";") + ";")
            if m:
                addrs.add(int(m.group(1), 16))
    return addrs


def _emit_extern_decls(fn: IrFunction) -> list[str]:
    lines: list[str] = []
    for addr in sorted(_collect_call_addrs(fn)):
        decl = format_extern_decl(addr)
        if decl:
            lines.append(decl)
    return lines


def emit_c(fn: IrFunction) -> str:
    lines = [
        "/* Auto-lifted semantic C — edit by hand; not tier-3 byte-matched. */",
        f"/* source: {fn.source} */",
        f"// @rom 0x{fn.addr:x} +0x{fn.length:x} {fn.name}",
        "",
        '#include "../i960_lift.h"',
        '#include "../i960_fp.h"',
    ]
    if function_needs_rom_header(fn):
        lines.append('#include "model2_rom.h"')
    if function_needs_mem_header(fn):
        lines.append('#include "../i960_mem.h"')
    lines.append("")

    if fn.kind == "frame":
        lines.append("/* frame function */")
        lines.append("")

    if fn.abi:
        lines.extend(fn.abi.emit_comment_lines())
        lines.append("")
    elif fn.args:
        abi = ", ".join(a.reg for a in fn.args)
        lines.append(f"/* abi args: {abi} */")
        lines.append("")

    if fn.pointer_regs:
        parts = [f"{reg}={ctype}" for reg, ctype in sorted(fn.pointer_regs.items())]
        lines.append(f"/* pointers: {', '.join(parts)} */")
        lines.append("")

    externs = _emit_extern_decls(fn)
    if externs:
        lines.extend(externs)
        lines.append("")

    sig = _format_signature(fn)
    lines.append(f"{sig}")
    lines.append("{")
    ctx = _build_emit_context(fn)
    lines.extend(_emit_prologue(fn))
    lines.extend(_emit_body(fn, ctx))
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _emit_prologue(fn: IrFunction) -> list[str]:
    if not fn.abi or not fn.abi.has_c_abi:
        return []
    lines: list[str] = []
    if fn.param_aliases:
        decls = emit_param_alias_lines(fn.param_aliases, indent=4)
        if decls:
            lines.extend(decls)
        lines.extend(emit_param_reg_loads(fn.param_aliases, indent=4))
    else:
        lines.extend(fn.abi.param_prologue_lines(indent=4))
    if lines and lines[-1].strip():
        lines.append("")
    return lines


def _emit_stmt_with_aliases(stmt: IrStmt, indent: int, ctx: EmitContext) -> str | None:
    original = stmt.text
    emit_stmt = stmt
    alias_ctx = ctx.alias_state.context
    if alias_ctx.reg_to_var:
        if stmt.kind == StmtKind.ASSIGN:
            display = substitute_reg_aliases(original.strip().rstrip(";"), alias_ctx)
            emit_stmt = IrStmt(
                kind=stmt.kind,
                text=display,
                addr=stmt.addr,
                words=stmt.words,
                target=stmt.target,
                meta=stmt.meta,
            )
        elif stmt.kind == StmtKind.BRANCH:
            emit_stmt = IrStmt(
                kind=stmt.kind,
                text=substitute_reg_aliases(original, alias_ctx),
                addr=stmt.addr,
                words=stmt.words,
                target=stmt.target,
                meta=stmt.meta,
            )

    line = _format_stmt(emit_stmt, indent, ctx)
    if line and alias_ctx.reg_to_var and stmt.kind == StmtKind.RETURN:
        fixed: list[str] = []
        for part in line.split("\n"):
            stripped = part.strip()
            if not stripped:
                continue
            if stripped.startswith("return"):
                pad = part[: len(part) - len(part.lstrip())]
                sub = substitute_reg_aliases(stripped.rstrip(";"), alias_ctx)
                fixed.append(f"{pad}{sub};")
            else:
                fixed.append(part)
        line = "\n".join(fixed)

    if stmt.kind == StmtKind.ASSIGN:
        ctx.alias_state.update_from_assign(original)
    return line


def _referenced_labels(fn: IrFunction) -> set[int]:
    refs: set[int] = set()
    for block in fn.blocks:
        for stmt in block.stmts:
            if stmt.target is not None:
                refs.add(stmt.target)
            if stmt.kind != StmtKind.BRANCH:
                continue
            for match in _LABEL_IN_BRANCH.finditer(stmt.text):
                refs.add(int(match.group(1).split("_", 1)[1], 16))
    return refs


def _branch_targets_of(fn: IrFunction, branch_addr: int) -> set[int]:
    targets: set[int] = set()
    for block in fn.blocks:
        for stmt in block.stmts:
            if stmt.addr != branch_addr or stmt.kind != StmtKind.BRANCH:
                continue
            if stmt.target is not None:
                targets.add(stmt.target)
            for match in _LABEL_IN_BRANCH.finditer(stmt.text):
                targets.add(int(match.group(1).split("_", 1)[1], 16))
    return targets


def _label_refs_outside(fn: IrFunction, addr: int, region_branch_addrs: set[int]) -> bool:
    """True if some branch outside the structured region still jumps to addr."""
    for block in fn.blocks:
        for stmt in block.stmts:
            if stmt.kind != StmtKind.BRANCH:
                continue
            stmt_addr = stmt.addr if stmt.addr is not None else block.addr
            if stmt_addr in region_branch_addrs:
                continue
            if stmt.target == addr:
                return True
            for match in _LABEL_IN_BRANCH.finditer(stmt.text):
                if int(match.group(1).split("_", 1)[1], 16) == addr:
                    return True
    return False


def _referenced_labels_for_emit(fn: IrFunction) -> set[int]:
    refs = _referenced_labels(fn)
    if not fn.regions:
        return refs
    region_branches = {
        r.branch_addr
        for r in fn.regions
        if isinstance(r, (IfThenRegion, IfElseRegion))
    }
    region_branches.update(
        r.tail_addr for r in fn.regions if isinstance(r, WhileRegion)
    )
    for region in fn.regions:
        if isinstance(region, IfThenRegion):
            if not _label_refs_outside(fn, region.join_addr, region_branches):
                refs.discard(region.join_addr)
            # Skip-target of the if is absorbed; keep it if something else jumps there.
            for tgt in _branch_targets_of(fn, region.branch_addr):
                if not _label_refs_outside(fn, tgt, region_branches):
                    refs.discard(tgt)
        elif isinstance(region, IfElseRegion):
            if region.join_addr is not None and not _label_refs_outside(
                fn, region.join_addr, region_branches
            ):
                refs.discard(region.join_addr)
            for tgt in _branch_targets_of(fn, region.branch_addr):
                if not _label_refs_outside(fn, tgt, region_branches):
                    refs.discard(tgt)
        elif isinstance(region, WhileRegion):
            if not _label_refs_outside(fn, region.head_addr, region_branches):
                refs.discard(region.head_addr)
            for tgt in _branch_targets_of(fn, region.tail_addr):
                if not _label_refs_outside(fn, tgt, region_branches):
                    refs.discard(tgt)
    return refs


def _linearize(fn: IrFunction) -> list[tuple[int | None, IrStmt]]:
    ordered = sorted(fn.blocks, key=lambda b: b.addr)
    out: list[tuple[int | None, IrStmt]] = []
    for block in ordered:
        for stmt in block.stmts:
            if stmt.kind == StmtKind.LABEL:
                continue
            out.append((block.addr, stmt))
    return out


def _emit_body(fn: IrFunction, ctx: EmitContext) -> list[str]:
    if fn.regions:
        return _emit_structured_body(fn, ctx)
    return _emit_linear_body(fn, ctx)


def _block_map(fn: IrFunction) -> dict[int, IrBlock]:
    return {b.addr: b for b in fn.blocks}


def _region_entry_map(fn: IrFunction) -> dict[int, object]:
    """Map linear-scan entry address → structured region."""
    entries: dict[int, object] = {}
    for region in fn.regions:
        if isinstance(region, WhileRegion):
            entries[region.head_addr] = region
        else:
            entries[region.branch_addr] = region
    return entries


def _covered_by_region(region: object) -> set[int]:
    if isinstance(region, WhileRegion):
        covered = set(region.body_addrs)
        covered.add(region.tail_addr)
        covered.add(region.head_addr)
        return covered
    if isinstance(region, IfThenRegion):
        covered = set(region.then_addrs)
        covered.add(region.branch_addr)
        return covered
    if isinstance(region, IfElseRegion):
        covered = set(region.then_addrs)
        covered.update(region.else_addrs)
        covered.add(region.branch_addr)
        return covered
    return set()


def _emit_label(
    lines: list[str],
    addr: int,
    *,
    referenced: set[int],
    emitted: set[int],
) -> None:
    if addr not in referenced or addr in emitted:
        return
    if lines and lines[-1].strip():
        lines.append("")
    lines.append(f"    L_{addr:08x}:")
    emitted.add(addr)


def _emit_structured_body(fn: IrFunction, ctx: EmitContext) -> list[str]:
    blocks = _block_map(fn)
    region_at = _region_entry_map(fn)
    referenced = _referenced_labels_for_emit(fn)
    covered: set[int] = set()
    emitted_labels: set[int] = set()
    linear = _linearize(fn)
    lines: list[str] = []
    i = 0
    in_label_block = False
    fallthrough_indent: int | None = None

    while i < len(linear):
        block_addr, stmt = linear[i]
        if block_addr is not None and block_addr in covered:
            i += 1
            continue

        if block_addr is not None and block_addr in region_at:
            region = region_at[block_addr]
            _restore_block_aliases(ctx, block_addr)
            before = len(lines)
            _emit_label(
                lines,
                block_addr,
                referenced=referenced,
                emitted=emitted_labels,
            )
            if len(lines) > before:
                in_label_block = True
                fallthrough_indent = None
            base = _stmt_indent(stmt, fallthrough_indent, in_label_block)
            if isinstance(region, WhileRegion):
                lines.extend(_emit_while(region, blocks, covered, ctx, base_indent=base))
            elif isinstance(region, IfThenRegion):
                lines.extend(_emit_if_then(region, blocks, covered, ctx, base_indent=base))
            elif isinstance(region, IfElseRegion):
                lines.extend(_emit_if_else(region, blocks, covered, ctx, base_indent=base))
            i += 1
            while i < len(linear) and linear[i][0] in covered:
                i += 1
            in_label_block = False
            fallthrough_indent = None
            continue

        if block_addr is not None:
            _restore_block_aliases(ctx, block_addr)
            before = len(lines)
            _emit_label(
                lines,
                block_addr,
                referenced=referenced,
                emitted=emitted_labels,
            )
            if len(lines) > before:
                in_label_block = True
                fallthrough_indent = None

        indent = _stmt_indent(stmt, fallthrough_indent, in_label_block)
        line = _emit_stmt_with_aliases(stmt, indent, ctx)
        _append_stmt(lines, line)

        if stmt.kind == StmtKind.BRANCH and "goto" in stmt.text:
            fallthrough_indent = None
        elif stmt.kind in (StmtKind.RETURN, StmtKind.CALL):
            in_label_block = False
            fallthrough_indent = None

        i += 1

    return lines


def _balanced_parens(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def clean_condition(cond: str) -> str:
    """Drop redundant grouping parens and literal casts before emit."""
    out = cond.strip()
    while out.startswith("(") and out.endswith(")"):
        inner = out[1:-1].strip()
        if not _balanced_parens(inner):
            break
        out = inner
    m = re.fullmatch(r"\(signed char\)0 >= \(signed char\)(\w+)", out)
    if m:
        return f"{m.group(1)} <= 0"
    m = re.fullmatch(r"0 >= \(signed char\)(\w+)", out)
    if m:
        return f"{m.group(1)} <= 0"
    m = re.fullmatch(r"(\d+) >= \(unsigned char\)(\w+)", out)
    if m:
        return f"{m.group(2)} <= {m.group(1)}"
    out = _BYTE_ZERO.sub("0", out)
    out = _SIGNED_BYTE_ZERO.sub("0", out)
    out = re.sub(r"\(unsigned char\)(\d+)\b", r"\1", out)
    out = re.sub(r"\(signed char\)(\d+)\b", r"\1", out)
    out = re.sub(r"\(g4 >> 0\)", "g4", out)
    return out


def _invert_condition(cond: str) -> str:
    """Negate a simple compare for inverted if-then regions."""
    out = cond.strip()
    m = re.fullmatch(r"(.+?) != (.+)", out)
    if m:
        return f"{m.group(1)} == {m.group(2)}"
    m = re.fullmatch(r"(.+?) == (.+)", out)
    if m:
        return f"{m.group(1)} != {m.group(2)}"
    m = re.fullmatch(r"(.+?) > (.+)", out)
    if m:
        return f"{m.group(1)} <= {m.group(2)}"
    m = re.fullmatch(r"(.+?) >= (.+)", out)
    if m:
        return f"{m.group(1)} < {m.group(2)}"
    m = re.fullmatch(r"(.+?) < (.+)", out)
    if m:
        return f"{m.group(1)} >= {m.group(2)}"
    m = re.fullmatch(r"(.+?) <= (.+)", out)
    if m:
        return f"{m.group(1)} > {m.group(2)}"
    return f"!({out})"


def _append_stmt(lines: list[str], line: str | None) -> None:
    if line is None:
        return
    for part in line.split("\n"):
        if not part.strip():
            continue
        if part.strip() == "return;" and lines:
            prev = lines[-1].strip()
            if prev.startswith("return "):
                continue
        lines.append(part)


def _emit_while(
    region: WhileRegion,
    blocks: dict[int, IrBlock],
    covered: set[int],
    ctx: EmitContext,
    *,
    base_indent: int = 4,
) -> list[str]:
    covered.update(_covered_by_region(region))
    body_indent = base_indent + 4
    if region.post_test:
        lines = [f"{' ' * base_indent}do {{"]
        for addr in region.body_addrs:
            lines.extend(_emit_block_body(blocks.get(addr), indent=body_indent, ctx=ctx))
        cond = clean_condition(region.condition)
        lines.append(f"{' ' * base_indent}}} while ({cond});")
        return lines
    cond = clean_condition(region.condition)
    lines = [f"{' ' * base_indent}while ({cond}) {{"]
    for addr in region.body_addrs:
        lines.extend(_emit_block_body(blocks.get(addr), indent=body_indent, ctx=ctx))
    lines.append(f"{' ' * base_indent}}}")
    return lines


def _emit_if_then(
    region: IfThenRegion,
    blocks: dict[int, IrBlock],
    covered: set[int],
    ctx: EmitContext,
    *,
    base_indent: int = 4,
) -> list[str]:
    covered.update(_covered_by_region(region))
    body_indent = base_indent + 4
    cond = clean_condition(region.condition)
    if region.invert:
        cond = _invert_condition(cond)
    lines = [f"{' ' * base_indent}if ({cond}) {{"]
    for addr in region.then_addrs:
        lines.extend(_emit_block_body(blocks.get(addr), indent=body_indent, ctx=ctx))
    lines.append(f"{' ' * base_indent}}}")
    return lines


def _emit_if_else(
    region: IfElseRegion,
    blocks: dict[int, IrBlock],
    covered: set[int],
    ctx: EmitContext,
    *,
    base_indent: int = 4,
) -> list[str]:
    covered.update(_covered_by_region(region))
    body_indent = base_indent + 4
    cond = clean_condition(region.condition)
    # i960: branch-taken skips fallthrough — else_addrs is the fallthrough (if body).
    lines = [f"{' ' * base_indent}if ({cond}) {{"]
    for addr in region.else_addrs:
        lines.extend(_emit_block_body(blocks.get(addr), indent=body_indent, ctx=ctx))
    lines.append(f"{' ' * base_indent}}} else {{")
    for addr in region.then_addrs:
        lines.extend(_emit_block_body(blocks.get(addr), indent=body_indent, ctx=ctx))
    lines.append(f"{' ' * base_indent}}}")
    return lines


def _emit_block_body(block: IrBlock | None, *, indent: int, ctx: EmitContext) -> list[str]:
    if block is None:
        return []
    _restore_block_aliases(ctx, block.addr)
    out: list[str] = []
    for stmt in block.stmts:
        if stmt.kind in (StmtKind.LABEL, StmtKind.BRANCH):
            continue
        line = _emit_stmt_with_aliases(stmt, indent, ctx)
        if line is not None:
            out.append(line)
    return out


def _emit_linear_body(fn: IrFunction, ctx: EmitContext) -> list[str]:
    referenced = _referenced_labels_for_emit(fn)
    emitted_labels: set[int] = set()
    linear = _linearize(fn)
    lines: list[str] = []
    i = 0
    fallthrough_indent: int | None = None
    in_label_block = False

    while i < len(linear):
        block_addr, stmt = linear[i]

        if block_addr is not None:
            _restore_block_aliases(ctx, block_addr)
            before = len(lines)
            _emit_label(
                lines,
                block_addr,
                referenced=referenced,
                emitted=emitted_labels,
            )
            if len(lines) > before:
                fallthrough_indent = None
                in_label_block = True

        indent = _stmt_indent(stmt, fallthrough_indent, in_label_block)
        line = _emit_stmt_with_aliases(stmt, indent, ctx)
        _append_stmt(lines, line)

        if stmt.kind == StmtKind.BRANCH and "goto" in stmt.text:
            fallthrough_indent = None
        elif stmt.kind in (StmtKind.RETURN, StmtKind.CALL):
            in_label_block = False
            fallthrough_indent = None

        i += 1

    return lines


def _stmt_indent(stmt: IrStmt, fallthrough_indent: int | None, in_label_block: bool) -> int:
    if fallthrough_indent is not None and stmt.kind != StmtKind.BRANCH:
        return fallthrough_indent
    if in_label_block:
        return 8
    return 4


def _format_call_line(text: str) -> str:
    stripped = text.strip().rstrip(";")
    m = _CALL_ADDR.match(stripped + ";")
    if m:
        return format_call(int(m.group(1), 16))
    m = _CALL_INDIRECT.match(stripped + ";")
    if m:
        reg = m.group(1).strip()
        return f"i960_call_indirect({reg});"
    if stripped.endswith("()"):
        return f"{stripped};"
    return text if text.endswith(";") else f"{text};"


def _format_stmt(stmt: IrStmt, indent: int, ctx: EmitContext) -> str | None:
    pad = " " * indent
    if stmt.kind == StmtKind.MACRO:
        text = stmt.text.strip()
        if text.startswith("/*") and not text.endswith(";"):
            return f"{pad}{text}"
        if "\n" in stmt.text:
            body_pad = " " * (indent + 4)
            out: list[str] = []
            for line in stmt.text.splitlines():
                if not line.strip():
                    continue
                stripped = line.strip()
                if stripped.endswith("();") or _CALL_ADDR.match(stripped + ";"):
                    out.append(f"{body_pad}{_format_call_line(stripped)}")
                else:
                    out.append(f"{body_pad}{stripped if stripped.endswith(';') else stripped + ';'}")
            return "\n".join(out)
        return f"{pad}{stmt.text}"
    if stmt.kind == StmtKind.ASSIGN:
        text = stmt.text.strip().rstrip(";")
        if text.startswith("/*"):
            return f"{pad}{text}"
        rom_note = stmt.meta.get("rom_comment")
        if rom_note:
            return f"{pad}{text}; {rom_note}"
        return f"{pad}{text};"
    if stmt.kind == StmtKind.BRANCH:
        text = stmt.text.strip()
        if text.startswith("if ") and " goto " in text:
            rest, _, target = text.partition(" goto ")
            target = target.rstrip(";")
            cond = clean_condition(rest.removeprefix("if ").strip())
            body_pad = " " * (indent + 4)
            return f"{pad}if ({cond})\n{body_pad}goto {target};"
        if text.startswith("goto "):
            target = text.removeprefix("goto ").strip().rstrip(";")
            return f"{pad}goto {target};"
        return f"{pad}{text}"
    if stmt.kind == StmtKind.CALL:
        return f"{pad}{_format_call_line(stmt.text)}"
    if stmt.kind == StmtKind.RETURN:
        abi = ctx.fn.abi
        if stmt.meta.get("style") == "ret":
            if abi and abi.returns:
                return abi.format_c_return_stmt(indent=indent)
            return f"{pad}return;"
        if stmt.meta.get("style") == "leaf_bx":
            link_reg = stmt.meta.get("link_reg") or ctx.fn.link_reg or "g14"
            if abi and abi.returns:
                return abi.format_c_return_stmt(indent=indent, link_reg=link_reg)
            return _format_leaf_return(pad, link_reg)
        if abi and abi.returns:
            return abi.format_c_return_stmt(indent=indent)
        return f"{pad}return;"
    if stmt.kind == StmtKind.RAW:
        return f"{pad}{stmt.text}"
    if stmt.kind == StmtKind.DATA:
        raw = stmt.text.strip()
        if raw.startswith("/* data */"):
            payload = raw.removeprefix("/* data */").strip()
            return f"{pad}/* data {payload} */"
        if raw.startswith("/*"):
            return f"{pad}{raw}"
        return f"{pad}/* {raw} */"
    return None


def _format_leaf_return(pad: str, link_reg: str) -> str:
    return (
        f"{pad}i960_call_indirect({link_reg});\n"
        f"{pad}return;"
    )


def _format_signature(fn: IrFunction) -> str:
    if fn.abi and fn.abi.has_c_abi:
        return fn.abi.c_signature(fn.name)
    return f"void {fn.name}(void)"
