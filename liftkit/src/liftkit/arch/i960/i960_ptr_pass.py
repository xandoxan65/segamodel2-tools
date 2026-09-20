"""IR pass: infer register pointers and rewrite reg-relative mem to C derefs."""

from __future__ import annotations

import re
from typing import Any

from liftkit.arch.i960.i960_ir import IrFunction, IrStmt, StmtKind
from liftkit.arch.i960.i960_regs import I960_SHARED_REGS, is_i960_reg

_WIDTH_CTYPE = {
    "u8": "unsigned char",
    "u16": "unsigned short",
    "u32": "u32",
    "u64": "u64",
}

_WIDTH_PTR = {
    "u8": "unsigned char *",
    "u16": "unsigned short *",
    "u32": "u32 *",
    "u64": "u64 *",
}

_REG = re.compile(r"^[gr]\d+$", re.I)
_MOV = re.compile(
    r"^\s*(\w+)\s*=\s*(?:\(u32\)\s*)?(?:\(uintptr_t\)\s*)?(\w+)\s*;?\s*$"
)
_MEM_LD = re.compile(
    r"^\s*(\w+)\s*=\s*(?:\(u32\)\s*)?"
    r"i960_ld_u(8|16|32|64)\(I960_(REG|FP),\s*(\w+),\s*(0x[0-9a-fA-F]+)\)\s*;?\s*$",
    re.I,
)
_MEM_ST = re.compile(
    r"^\s*i960_st_u(8|16|32|64)\(I960_(REG|FP),\s*(\w+),\s*(0x[0-9a-fA-F]+),\s*"
    r"\((u\d+)\)(\w+)\)\s*;?\s*$",
    re.I,
)
_FP_SLOT = re.compile(
    r"^\s*(\w+)\s*=\s*(?:\(u32\)\s*)?i960_fp_slot\((0x[0-9a-fA-F]+)\)\s*;?\s*$",
    re.I,
)
_PTR_BUMP = re.compile(
    r"^\s*(\w+)\s*=\s*(?:\(u32\)\s*)?(?:\(uintptr_t\)\s*)?(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*;?\s*$"
)


def _is_reg_base(base: str) -> bool:
    token = base.lower()
    return token in I960_SHARED_REGS or bool(_REG.match(token))


def _widen_ptr(existing: str | None, width: str) -> str:
    candidate = _WIDTH_PTR.get(width, "void *")
    if existing is None:
        return candidate
    if existing in ("void *", "const void *"):
        return candidate
    return existing


def _merge_ptr(existing: str | None, new: str) -> str:
    if existing is None:
        return new
    if existing == new:
        return existing
    if existing in ("void *", "const void *"):
        return new
    if new in ("void *", "const void *"):
        return existing
    return existing


def _seed_from_abi(fn: IrFunction) -> dict[str, str]:
    ptr: dict[str, str] = {}
    if not fn.abi:
        return ptr
    for param in fn.abi.params:
        if param.pointer or param.type.endswith("*"):
            ptr[param.reg.lower()] = param.type
    for ret in fn.abi.returns:
        if ret.pointer or ret.type.endswith("*"):
            ptr[ret.reg.lower()] = ret.type
    return ptr


def _mem_from_stmt(stmt: IrStmt) -> dict[str, Any] | None:
    mem = stmt.meta.get("mem")
    if isinstance(mem, dict):
        return mem
    text = stmt.text.strip().rstrip(";")
    m = _MEM_LD.match(text)
    if m:
        return {
            "op": "load",
            "width": f"u{m.group(2)}",
            "base": m.group(4).lower(),
            "offset": int(m.group(5), 16),
            "dst": m.group(1).lower(),
        }
    m = _MEM_ST.match(text)
    if m:
        return {
            "op": "store",
            "width": f"u{m.group(1)}",
            "base": m.group(3).lower(),
            "offset": int(m.group(4), 16),
            "value": m.group(6).lower(),
        }
    return None


def _propagate_from_stmt(stmt: IrStmt, ptr: dict[str, str]) -> bool:
    changed = False
    mem = _mem_from_stmt(stmt)
    if mem and _is_reg_base(mem["base"]):
        base = mem["base"].lower()
        width = mem.get("width", "u8")
        new_type = _widen_ptr(ptr.get(base), width)
        if ptr.get(base) != new_type:
            ptr[base] = new_type
            changed = True
        if mem["op"] == "load":
            dst = mem.get("dst")
            if dst is None:
                m = re.match(r"^\s*(\w+)\s*=", stmt.text)
                dst = m.group(1).lower() if m else None
            if dst and dst not in ptr:
                ptr[dst] = "u32"
                changed = True

    if stmt.kind in (StmtKind.ASSIGN, StmtKind.MACRO):
        text = stmt.text.strip().rstrip(";")
        m = _MOV.match(text)
        if m:
            dst, src = m.group(1).lower(), m.group(2).lower()
            if src in ptr:
                merged = _merge_ptr(ptr.get(dst), ptr[src])
                if ptr.get(dst) != merged:
                    ptr[dst] = merged
                    changed = True
        bump = _PTR_BUMP.match(text)
        if bump:
            dst, src = bump.group(1).lower(), bump.group(2).lower()
            if src in ptr:
                merged = _merge_ptr(ptr.get(dst), ptr[src])
                if ptr.get(dst) != merged:
                    ptr[dst] = merged
                    changed = True

    if stmt.meta.get("lda") or stmt.meta.get("frame"):
        m = re.match(r"^\s*(\w+)\s*=", stmt.text.strip())
        if m:
            dst = m.group(1).lower()
            if dst not in ptr:
                ptr[dst] = "void *"
                changed = True

    return changed


def analyze_pointer_regs(fn: IrFunction) -> dict[str, str]:
    ptr = _seed_from_abi(fn)
    changed = True
    while changed:
        changed = False
        for block in fn.blocks:
            for stmt in block.stmts:
                if _propagate_from_stmt(stmt, ptr):
                    changed = True
    return ptr


def _ptr_cell(base: str, offset: int, width: str) -> str:
    ctype = _WIDTH_CTYPE[width]
    if offset == 0:
        return f"({ctype} *){base}"
    if offset < 0:
        return f"({ctype} *)({base} - 0x{-offset:x})"
    if offset >= 0x80000000:
        return f"({ctype} *)({base} - 0x{(0x100000000 - offset):x})"
    return f"({ctype} *)({base} + 0x{offset:x})"


def _rewrite_reg_mem(text: str, mem: dict[str, Any]) -> str | None:
    if not _is_reg_base(mem["base"]):
        return None
    width = mem.get("width", "u32")
    if width not in _WIDTH_CTYPE:
        return None
    base = mem["base"]
    raw_off = mem.get("offset", 0)
    # Scaled-index offsets stay as i960_ld/st intrinsics (not *ptr rewrite).
    if isinstance(raw_off, str):
        return None
    offset = int(raw_off)
    cell = _ptr_cell(base, offset, width)

    if mem["op"] == "load":
        dst = mem.get("dst")
        if dst is None:
            m = _MEM_LD.match(text.strip().rstrip(";"))
            if not m:
                m2 = re.match(r"^\s*(\w+)\s*=", text)
                dst = m2.group(1) if m2 else None
            else:
                dst = m.group(1)
        if not dst:
            return None
        if width == "u64":
            return f"{dst} = (u32)*({cell});"
        return f"{dst} = *{cell};"

    if mem["op"] == "store":
        value = mem.get("value")
        if value is None:
            m = _MEM_ST.match(text.strip().rstrip(";"))
            value = m.group(6) if m else "?"
        cast = _WIDTH_CTYPE[width]
        return f"*{cell} = ({cast}){value};"

    return None


def rewrite_stmt(stmt: IrStmt) -> IrStmt:
    text = stmt.text.strip().rstrip(";")
    slot = _FP_SLOT.match(text)
    if slot:
        dst, off = slot.group(1), slot.group(2)
        meta = dict(stmt.meta)
        meta["ptr_deref"] = True
        meta["frame"] = {"base": "fp", "offset": int(off, 16)}
        return IrStmt(
            kind=stmt.kind,
            text=f"{dst} = fp + {off};",
            addr=stmt.addr,
            words=list(stmt.words),
            target=stmt.target,
            meta=meta,
        )

    mem = _mem_from_stmt(stmt)
    if not mem:
        return stmt
    new_text = _rewrite_reg_mem(stmt.text, mem)
    if new_text is None:
        return stmt
    meta = dict(stmt.meta)
    meta["ptr_deref"] = True
    meta.pop("mem", None)
    return IrStmt(
        kind=stmt.kind,
        text=new_text,
        addr=stmt.addr,
        words=list(stmt.words),
        target=stmt.target,
        meta=meta,
    )


def apply_pointer_pass(fn: IrFunction) -> dict[str, str]:
    """Analyze pointer registers and rewrite reg-relative memory intrinsics."""
    ptr_regs = analyze_pointer_regs(fn)
    fn.pointer_regs = dict(ptr_regs)
    for block in fn.blocks:
        block.stmts = [rewrite_stmt(stmt) for stmt in block.stmts]
    return ptr_regs


def function_needs_mem_header(fn: IrFunction) -> bool:
    for block in fn.blocks:
        for stmt in block.stmts:
            text = stmt.text
            if (
                "i960_ld_" in text
                or "i960_st_" in text
                or "i960_mmio_" in text
                or "i960_fp_slot" in text
            ):
                return True
    return False


def function_needs_rom_header(fn: IrFunction) -> bool:
    markers = (
        "model2_maincpu_rom",
        "model2_workram",
        "model2_crx_ram",
        "model2_cpu_wait",
        "i960_vaddr_ptr",
    )
    for block in fn.blocks:
        for stmt in block.stmts:
            if any(m in stmt.text for m in markers):
                return True
    return False
