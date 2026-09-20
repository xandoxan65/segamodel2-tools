"""Typed parameter aliases and register-name substitution for C emit."""

from __future__ import annotations

import re
from dataclasses import dataclass

from tools.decomp.i960_abi import AbiParam, FunctionAbi
from tools.decomp.i960_ir import IrFunction, IrStmt, StmtKind

_REG = re.compile(r"^[gr]\d+$", re.I)
_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(.+?)\s*;?\s*$")
_SIMPLE_REG = re.compile(r"^(?:[gr]\d+|fp|sp)$", re.I)
_PTR_BUMP = re.compile(
    r"^(?:\(u32\)\s*)?(?:\(uintptr_t\)\s*)?(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)$",
    re.I,
)
_DEREF = re.compile(
    r"\*\(\s*([^)]+?\*)\s*\)(?:\(uintptr_t\))?([a-z]\w*|\w+)\b",
    re.I,
)
_CAST_PTR = re.compile(
    r"\(\s*([^)]+?\*)\s*\)(?:\(uintptr_t\))?([a-z]\w*|\w+)\b",
    re.I,
)
_UINTPTR = re.compile(r"\(uintptr_t\)([a-z]\w*|\w+)\b", re.I)

_SHORT_NAMES = {
    "dst": "d",
    "src": "s",
    "len": "n",
    "fmt": "fmt",
    "arg1": "a1",
    "arg2": "a2",
}


@dataclass(frozen=True)
class TypedParamAlias:
    reg: str
    param_name: str
    var_name: str
    ctype: str
    needs_decl: bool


def _normalize_type(ctype: str) -> str:
    return " ".join(ctype.replace("*", " *").split())


def _merge_ptr_type(existing: str, new: str) -> str:
    if _normalize_type(existing) == _normalize_type(new):
        return existing
    if existing in ("void *", "const void *") and new.endswith("*"):
        if "const" in existing and "const" not in new:
            return f"const {new}"
        return new
    if new in ("void *", "const void *"):
        return existing
    if "const" in existing and new.endswith("*") and "const" not in new:
        return f"const {new}"
    return existing


def _linearize_stmts(fn: IrFunction) -> list[IrStmt]:
    ordered = sorted(fn.blocks, key=lambda b: b.addr)
    out: list[IrStmt] = []
    for block in ordered:
        for stmt in block.stmts:
            if stmt.kind == StmtKind.LABEL:
                continue
            out.append(stmt)
    return out


def refine_param_types(fn: IrFunction) -> dict[str, str]:
    """Narrow ABI param register types using inferred working-register roles."""
    if not fn.abi:
        return {}
    types: dict[str, str] = {}
    for param in fn.abi.params:
        reg = param.reg.lower()
        refined = fn.pointer_regs.get(reg)
        types[reg] = refined if refined else param.type

    param_regs = {p.reg.lower() for p in fn.abi.params}
    for stmt in _linearize_stmts(fn):
        m = _ASSIGN.match(stmt.text.strip())
        if not m:
            continue
        dst, src = m.group(1).lower(), m.group(2).strip().rstrip(";")
        if _SIMPLE_REG.fullmatch(src):
            src = src.lower()
            if src in param_regs and dst in fn.pointer_regs:
                types[src] = _merge_ptr_type(types[src], fn.pointer_regs[dst])
            if dst in param_regs and src in fn.pointer_regs:
                types[dst] = _merge_ptr_type(types[dst], fn.pointer_regs[src])
            continue
        sub_one = re.match(r"^(\w+)\s*-\s*(?:0x)?(\d+)$", src, re.I)
        if sub_one:
            base = sub_one.group(1).lower()
            if base in param_regs and dst in fn.pointer_regs:
                types[base] = _merge_ptr_type(types[base], fn.pointer_regs[dst])

    return types


def build_typed_param_aliases(
    abi: FunctionAbi,
    param_types: dict[str, str],
) -> list[TypedParamAlias]:
    aliases: list[TypedParamAlias] = []
    for param in abi.params:
        reg = param.reg.lower()
        ctype = param_types.get(reg, param.type)
        is_ptr = param.pointer or ctype.endswith("*")
        if is_ptr:
            needs_decl = _normalize_type(ctype) != _normalize_type(param.type)
            var_name = _var_name(param.name, needs_short=needs_decl)
            aliases.append(
                TypedParamAlias(
                    reg=reg,
                    param_name=param.name,
                    var_name=var_name,
                    ctype=ctype,
                    needs_decl=needs_decl,
                )
            )
        else:
            aliases.append(
                TypedParamAlias(
                    reg=reg,
                    param_name=param.name,
                    var_name=param.name,
                    ctype=ctype,
                    needs_decl=False,
                )
            )
    return aliases


def _var_name(param_name: str, *, needs_short: bool) -> str:
    if not needs_short:
        return param_name
    return _SHORT_NAMES.get(param_name, f"{param_name}_p")


def emit_param_alias_lines(
    aliases: list[TypedParamAlias],
    *,
    indent: int = 4,
) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    for alias in aliases:
        if not alias.needs_decl:
            continue
        if alias.ctype.endswith("*"):
            lines.append(
                f"{pad}{alias.ctype} {alias.var_name} = ({alias.ctype}){alias.param_name};"
            )
        else:
            lines.append(f"{pad}{alias.ctype} {alias.var_name} = ({alias.ctype}){alias.param_name};")
    return lines


def emit_param_reg_loads(
    aliases: list[TypedParamAlias],
    *,
    indent: int = 4,
) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    for alias in aliases:
        if alias.needs_decl:
            continue
        src = alias.var_name
        if alias.ctype.endswith("*"):
            lines.append(f"{pad}{alias.reg} = (uintptr_t){src};")
        else:
            lines.append(f"{pad}{alias.reg} = (uintptr_t){src};")
    return lines


@dataclass(frozen=True)
class AliasContext:
    """Active register → typed local name mapping for emit substitution."""

    reg_to_var: dict[str, str]
    pointer_vars: frozenset[str] = frozenset()

    @classmethod
    def from_param_aliases(cls, aliases: list[TypedParamAlias]) -> AliasContext:
        reg_to_var = {a.reg: a.var_name for a in aliases}
        pointer_vars = frozenset(a.var_name for a in aliases if a.ctype.endswith("*"))
        return cls(reg_to_var=reg_to_var, pointer_vars=pointer_vars)


def initial_reg_aliases(aliases: list[TypedParamAlias]) -> dict[str, str]:
    return {a.reg: a.var_name for a in aliases}


def _apply_assign_aliases(aliases: dict[str, str], text: str) -> dict[str, str]:
    state = RegAliasState(aliases)
    state.update_from_assign(text)
    return dict(state.aliases)


def _merge_alias_states(states: list[dict[str, str]]) -> dict[str, str]:
    if not states:
        return {}
    if len(states) == 1:
        return dict(states[0])
    merged = dict(states[0])
    for other in states[1:]:
        for reg in list(merged):
            if merged.get(reg) != other.get(reg):
                del merged[reg]
    return merged


def compute_block_alias_states(fn: IrFunction) -> dict[int, dict[str, str]]:
    """CFG dataflow: register alias map at the entry of each basic block."""
    if not fn.param_aliases:
        return {}

    from tools.decomp.i960_cfg import build_cfg

    cfg = build_cfg(fn)
    initial = initial_reg_aliases(fn.param_aliases)
    preds: dict[int, list[int]] = {addr: [] for addr in cfg.blocks}
    for edge in cfg.edges:
        preds[edge.dst].append(edge.src)

    in_states: dict[int, dict[str, str]] = {fn.entry: dict(initial)}
    out_states: dict[int, dict[str, str]] = {}
    changed = True
    while changed:
        changed = False
        for addr in cfg.blocks:
            block = cfg.block_map[addr]
            pred_addrs = preds[addr]
            if pred_addrs:
                pred_out = [out_states[p] for p in pred_addrs if p in out_states]
                if len(pred_out) < len(pred_addrs):
                    continue
                new_in = _merge_alias_states(pred_out)
            elif addr == fn.entry:
                new_in = dict(initial)
            else:
                continue

            if in_states.get(addr) != new_in:
                in_states[addr] = dict(new_in)
                changed = True

            cur = dict(in_states[addr])
            for stmt in block.stmts:
                if stmt.kind == StmtKind.ASSIGN:
                    cur = _apply_assign_aliases(cur, stmt.text)
            if out_states.get(addr) != cur:
                out_states[addr] = cur
                changed = True

    return in_states


class RegAliasState:
    """Track which g/r registers currently mirror a typed param/local name."""

    def __init__(
        self,
        seed: dict[str, str] | None = None,
        *,
        pointer_vars: frozenset[str] | None = None,
    ) -> None:
        self.aliases: dict[str, str] = dict(seed or {})
        self.pointer_vars: frozenset[str] = pointer_vars or frozenset()

    @property
    def context(self) -> AliasContext:
        return AliasContext(reg_to_var=self.aliases, pointer_vars=self.pointer_vars)

    def update_from_assign(self, text: str) -> None:
        m = _ASSIGN.match(text.strip())
        if not m:
            return
        dst = m.group(1).lower()
        src = m.group(2).strip()

        if _SIMPLE_REG.fullmatch(src):
            src = src.lower()
            if src in self.aliases:
                self.aliases[dst] = self.aliases[src]
            else:
                self.aliases.pop(dst, None)
            return

        bump = _PTR_BUMP.match(src)
        if bump and bump.group(1).lower() == dst.lower():
            self.aliases.pop(dst, None)
            return

        if dst in self.aliases:
            self.aliases.pop(dst, None)


def _reg_value(name: str, *, pointer: bool) -> str:
    if pointer:
        return f"(uintptr_t){name}"
    return name


def _substitute_expr(text: str, ctx: AliasContext) -> str:
    if not ctx.reg_to_var:
        return text

    out = text
    for reg, name in sorted(ctx.reg_to_var.items(), key=lambda item: len(item[0]), reverse=True):
        if not _REG.match(reg):
            continue
        pointer = name in ctx.pointer_vars

        def deref_repl(match: re.Match[str]) -> str:
            cast = match.group(1).strip()
            hit = match.group(2).lower()
            if hit != reg:
                return match.group(0)
            if cast.endswith("*") and pointer:
                return f"*({cast}){name}"
            return f"*({cast}){name}"

        def cast_ptr_repl(match: re.Match[str]) -> str:
            cast = match.group(1).strip()
            hit = match.group(2).lower()
            if hit != reg:
                return match.group(0)
            return f"({cast}){name}"

        def uintptr_repl(match: re.Match[str]) -> str:
            hit = match.group(1).lower()
            if hit != reg:
                return match.group(0)
            return f"(uintptr_t){name}"

        out = _DEREF.sub(deref_repl, out)
        out = _CAST_PTR.sub(cast_ptr_repl, out)
        out = _UINTPTR.sub(uintptr_repl, out)

        out = re.sub(rf"\(unsigned char\){re.escape(reg)}\b", f"(unsigned char)(u8){reg}", out)
        out = re.sub(rf"\(signed char\){re.escape(reg)}\b", f"(signed char)(u8){reg}", out)
        out = re.sub(rf"\b{re.escape(reg)}\s*==\s*0\b", f"{_reg_value(name, pointer=pointer)} == 0", out)

        val = _reg_value(name, pointer=pointer)
        out = re.sub(rf"\b{re.escape(reg)}\b", val, out)

    return out


def substitute_reg_aliases(text: str, ctx: AliasContext) -> str:
    if not ctx.reg_to_var:
        return text

    stripped = text.strip().rstrip(";")
    m = _ASSIGN.match(stripped)
    if m:
        dst, rhs = m.group(1), m.group(2).strip()
        if _SIMPLE_REG.fullmatch(rhs):
            src = rhs.lower()
            if src in ctx.reg_to_var:
                name = ctx.reg_to_var[src]
                pointer = name in ctx.pointer_vars
                if pointer:
                    return f"{dst} = (uintptr_t){name}"
                return f"{dst} = (uintptr_t){name}"
        return f"{dst} = {_substitute_expr(rhs, ctx)}"

    return _substitute_expr(stripped, ctx)
