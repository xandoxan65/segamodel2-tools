"""i960 compare/branch semantics and instruction lowering to lifted C."""

from __future__ import annotations

import re
from typing import Any

from tools.decomp.i960_mem_emit import (
    MemAccess,
    emit_abs_load,
    emit_abs_store,
    emit_load,
    emit_mmio_store,
    emit_store,
    emit_synmov,
    emit_synmovq,
    space_for_operand,
)
from tools.decomp.i960_operand import MemSpace, Operand, parse_operands, space_for_abs_addr
from tools.decomp.i960_regs import (
    is_abi_arg,
    lda_to_reg,
    reg_assign,
    signed_byte,
    u32_val,
    unsigned_byte,
)
from tools.decomp.i960_rom_ref import maincpu_rom_ptr_expr, vaddr_ptr_expr
from tools.i960_memory import MAINCPU_SIZE


def cmpibge_cond(imm: str, reg: str) -> str:
    return f"(signed char){_imm(imm)} >= {signed_byte(reg)}"


def cmpibne_cond(imm: str, reg: str) -> str:
    imm_v = _imm(imm)
    if imm_v == "0":
        return f"{unsigned_byte(reg)} != 0"
    return f"{unsigned_byte(reg)} != {imm_v}"


def cmpobge_cond(imm: str, reg: str) -> str:
    return f"(unsigned char){_imm(imm)} >= {unsigned_byte(reg)}"


def cmpobne_cond(imm: str, reg: str) -> str:
    imm_v = _imm(imm)
    if imm_v == "0":
        return f"{unsigned_byte(reg)} != 0"
    return f"{unsigned_byte(reg)} != {imm_v}"


def bbs_cond(bit: str, reg: str) -> str:
    return f"({reg} >> {_imm(bit)}) & 1"


def ac_branch_cond(mnemonic: str, prior_mnemonic: str | None, prior_ops: list[str]) -> str | None:
    if not prior_mnemonic or not prior_ops:
        return None
    lhs = prior_ops[0]
    if is_abi_arg(lhs):
        lhs = f"(uintptr_t){lhs}"
    if prior_mnemonic in ("cmpi", "cmpo") and len(prior_ops) >= 2:
        rhs = prior_ops[1]
        if mnemonic == "be":
            return f"{lhs} == {_imm(rhs)}"
        if mnemonic == "bne":
            return f"{lhs} != {_imm(rhs)}"
        if mnemonic == "bg":
            return f"{lhs} > {_imm(rhs)}"
        if mnemonic == "bl":
            return f"{lhs} < {_imm(rhs)}"
        if mnemonic == "bge":
            return f"{lhs} >= {_imm(rhs)}"
        if mnemonic == "ble":
            return f"{lhs} <= {_imm(rhs)}"
    return None


def format_lda_expr(src: Operand, dst: str) -> tuple[str, dict[str, Any]]:
    """i960 lda — load effective address (not a memory load)."""
    meta: dict[str, Any] = {"lda": True}
    if src.kind in ("imm", "label") and src.imm is not None:
        if src.imm >= 0x100000:
            expr, note = vaddr_ptr_expr(src.imm)
            meta["rom_ref"] = f"0x{src.imm:x}"
            if note:
                meta["rom_comment"] = note
            return f"{dst} = {expr}", meta
        if src.imm < MAINCPU_SIZE:
            # Word-aligned low addresses are ROM pointers; others (0x101, 0xffff) are scalars.
            if src.imm % 4 == 0 and src.imm != 0:
                expr, note = maincpu_rom_ptr_expr(src.imm)
                meta["rom_ref"] = f"0x{src.imm:x}"
                if note:
                    meta["rom_comment"] = note
                return f"{dst} = {expr}", meta
            meta["abs_addr"] = f"0x{src.imm:x}"
            return f"{dst} = 0x{src.imm:x}", meta
        meta["abs_addr"] = f"0x{src.imm:x}"
        return f"{dst} = 0x{src.imm:x}", meta
    if src.kind == "mem":
        base = src.mem_base
        off = src.mem_offset or 0
        if base is None:
            return f"{dst} = 0x{off:x}", meta
        if base.lower() == "fp":
            meta["frame"] = {"base": "fp", "offset": off}
        return lda_to_reg(base, off, dst), meta
    return reg_assign(dst, u32_val(src.raw)), meta


def _mem_access_from(op: Operand, *, op_kind: str, width: str, value: str | None = None) -> MemAccess:
    base = op.mem_base or "?"
    off = op.mem_offset or 0
    return MemAccess(
        op=op_kind,
        space=space_for_operand(op),
        width=width,
        base=base.lower(),
        offset=off,
        value=value,
    )


def _imm(token: str) -> str:
    if token.startswith("0x") or token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
        return token
    return token


def _alu_operand(op: Operand) -> str:
    if op.kind == "imm" or op.raw.isdigit() or op.raw.startswith("0x"):
        return _imm(op.raw)
    return u32_val(op.raw)


def _abs_addr(op: Operand) -> int | None:
    if op.kind in ("imm", "label") and op.imm is not None:
        return op.imm
    return None


_PAIR_REG = re.compile(r"^([gr])(\d+)$", re.I)


def _reg_pair(reg: str) -> tuple[str, str] | None:
    m = _PAIR_REG.match(reg.strip())
    if not m:
        return None
    idx = int(m.group(2))
    if idx % 2 != 0:
        return None
    prefix = m.group(1).lower()
    lo = f"{prefix}{idx}"
    hi = f"{prefix}{idx + 1}"
    return lo, hi


def _is_zero_imm(op: Operand) -> bool:
    if op.raw in ("0", "0x0"):
        return True
    return op.kind in ("imm", "label") and op.imm == 0


def lower_movq_stmts(operands: list[str]) -> list[tuple[str, dict[str, Any]]]:
    """Expand movq to two 32-bit register assignments (even/odd pair)."""
    ops = parse_operands(operands)
    if len(ops) != 2:
        return []
    src, dst = ops[0], ops[1].raw
    dst_pair = _reg_pair(dst)
    if dst_pair is None:
        return []

    dst_lo, dst_hi = dst_pair
    meta: dict[str, Any] = {"mnemonic": "movq", "operands": operands, "movq_pair": True}

    if _is_zero_imm(src):
        return [
            (f"{dst_lo} = 0", meta),
            (f"{dst_hi} = 0", meta),
        ]

    if src.kind in ("imm", "label") and src.imm is not None:
        return [
            (f"{dst_lo} = 0x{src.imm & 0xFFFFFFFF:x}", meta),
            (f"{dst_hi} = 0x{(src.imm >> 32) & 0xFFFFFFFF:x}", meta),
        ]

    src_pair = _reg_pair(src.raw)
    if src_pair is None:
        return []
    src_lo, src_hi = src_pair
    return [
        (f"{dst_lo} = {u32_val(src_lo)}", meta),
        (f"{dst_hi} = {u32_val(src_hi)}", meta),
    ]


def insn_c_expr(mnemonic: str, operands: list[str]) -> str | None:
    expr, _ = insn_lower(mnemonic, operands)
    return expr


def insn_lower(mnemonic: str, operands: list[str]) -> tuple[str | None, dict[str, Any]]:
    if not operands:
        return None, {}
    ops = parse_operands(operands)
    mn = mnemonic.lower()
    meta: dict[str, Any] = {"mnemonic": mn, "operands": operands}

    if mn == "movl" and len(ops) == 2:
        return f"{ops[1].raw} = {u32_val(ops[0].raw)}", meta
    if mn == "mov" and len(ops) == 2:
        return f"{ops[1].raw} = {u32_val(ops[0].raw)}", meta
    if mn in ("synmov", "synmovq") and len(ops) == 2:
        src, dst = ops[0].raw, ops[1].raw
        meta["sync_move"] = mn
        if mn == "synmovq":
            return emit_synmovq(src, dst), meta
        return emit_synmov(src, dst), meta
    if mn in ("addo", "add") and len(ops) == 3:
        lhs, rhs, dst = ops[1].raw, _alu_operand(ops[0]), ops[2].raw
        if lhs == dst:
            return reg_assign(dst, f"{lhs} + {rhs}"), meta
        return reg_assign(dst, f"{rhs} + {lhs}"), meta
    if mn in ("subo", "sub") and len(ops) == 3:
        lhs = ops[1].raw
        return reg_assign(ops[2].raw, f"{lhs} - {_imm(ops[0].raw)}"), meta
    if mn == "and" and len(ops) == 3:
        return f"{ops[2].raw} = {_alu_operand(ops[1])} & {_alu_operand(ops[0])}", meta
    if mn == "or" and len(ops) == 3:
        return f"{ops[2].raw} = {_alu_operand(ops[1])} | {_alu_operand(ops[0])}", meta
    if mn == "shro" and len(ops) == 3:
        return f"{ops[2].raw} = {ops[1].raw} >> {_imm(ops[0].raw)}", meta
    if mn == "shlo" and len(ops) == 3:
        return f"{ops[2].raw} = {ops[1].raw} << {_imm(ops[0].raw)}", meta

    if mn == "ldl" and len(ops) == 2 and ops[0].mem_base:
        access = _mem_access_from(ops[0], op_kind="load", width="u64")
        meta.update(access.to_meta())
        return emit_load(ops[1].raw, access), meta
    if mn == "stl" and len(ops) == 2 and ops[1].mem_base:
        access = _mem_access_from(ops[1], op_kind="store", width="u64", value=ops[0].raw)
        meta.update(access.to_meta())
        return emit_store(access), meta

    if mn == "lda" and len(ops) == 2:
        if ops[0].kind == "mem" and ops[1].raw == "sp" and ops[0].mem_base == "sp":
            off = ops[0].mem_offset or 0
            meta["stack"] = {"op": "alloc", "bytes": off}
            return f"sp = (u32)((uintptr_t)sp + 0x{off:x})", meta
        expr, lda_meta = format_lda_expr(ops[0], ops[1].raw)
        meta.update(lda_meta)
        return expr, meta

    load_map = {
        "ld": "u32",
        "ldq": "u64",
        "ldob": "u8",
        "ldos": "u16",
    }
    if mn in load_map and len(ops) == 2:
        abs_addr = _abs_addr(ops[0])
        if abs_addr is not None:
            meta["abs_addr"] = f"0x{abs_addr:x}"
            meta["mem"] = {
                "op": "load",
                "space": space_for_abs_addr(abs_addr).value,
                "width": load_map[mn],
                "base": f"0x{abs_addr:x}",
                "offset": 0,
            }
            return emit_abs_load(ops[1].raw, load_map[mn], abs_addr), meta
        if ops[0].mem_base:
            access = _mem_access_from(ops[0], op_kind="load", width=load_map[mn])
            meta.update(access.to_meta())
            return emit_load(ops[1].raw, access), meta

    store_map = {
        "st": "u32",
        "stq": "u64",
        "stob": "u8",
        "stos": "u16",
    }
    if mn in store_map and len(ops) == 2:
        abs_addr = _abs_addr(ops[1])
        if abs_addr is not None:
            meta["abs_addr"] = f"0x{abs_addr:x}"
            meta["mem"] = {
                "op": "store",
                "space": space_for_abs_addr(abs_addr).value,
                "width": store_map[mn],
                "base": f"0x{abs_addr:x}",
                "offset": 0,
                "value": ops[0].raw,
            }
            return emit_abs_store(store_map[mn], abs_addr, ops[0].raw), meta
        if ops[1].mem_base:
            if ops[1].space == MemSpace.MMIO_GEO:
                off = ops[1].mem_offset or 0
                meta["mmio"] = {"offset": off}
                return emit_mmio_store(off, ops[0].raw), meta
            access = _mem_access_from(ops[1], op_kind="store", width=store_map[mn], value=ops[0].raw)
            meta.update(access.to_meta())
            return emit_store(access), meta

    return None, meta
