"""i960 compare/branch semantics and instruction lowering to lifted C."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from liftkit.arch.i960.i960_mem_emit import (
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
from liftkit.arch.i960.i960_operand import MemSpace, Operand, parse_operands, space_for_abs_addr
from liftkit.arch.i960.i960_fp_emit import lower_fp_insn
from liftkit.arch.i960.i960_regs import (
    addr_uintptr,
    is_abi_arg,
    lda_to_reg,
    reg_assign,
    u32_val,
)
from liftkit.arch.i960.i960_rom_ref import maincpu_rom_ptr_expr, vaddr_ptr_expr
from liftkit.arch.i960.memory_map import MAINCPU_SIZE


_COBR_REL = {"e": "==", "ne": "!=", "l": "<", "le": "<=", "g": ">", "ge": ">="}


def cmp_branch_cond(mnemonic: str, src1: str, src2: str) -> str | None:
    """cmpib*/cmpob* src1, src2: branch if src1 <cc> src2.

    The ``b`` is *branch*, not *byte*: both compare all 32 bits, signed (cmpib)
    or unsigned (cmpob). src1 may be a literal 0..31.
    """
    mn = mnemonic.lower()
    if mn.startswith("cmpib"):
        cast = "(i32)(u32)"
    elif mn.startswith("cmpob"):
        cast = "(u32)"
    else:
        return None
    rel = _COBR_REL.get(mn[5:])
    if rel is None:
        return None
    return f"{cast}{_imm(src1)} {rel} {cast}{src2}"


def cmpr_branch_cond(mnemonic: str, lhs: str, rhs: str) -> str | None:
    """Real compare (cmpr) fused with ordered branch (MAME cmp_d + bxx_s)."""
    a = f"i960_u32_to_f64({lhs})"
    b = f"i960_u32_to_f64({rhs})"
    if mnemonic == "be":
        return f"{a} == {b}"
    if mnemonic == "bne":
        return f"{a} != {b}"
    if mnemonic == "bg":
        return f"{a} > {b}"
    if mnemonic == "bl":
        return f"{a} < {b}"
    if mnemonic == "bge":
        return f"{a} >= {b}"
    if mnemonic == "ble":
        return f"{a} <= {b}"
    return None


def is_movrl_double_high_word(imm: int) -> bool:
    """i960 lda + movrl (even=0): high 32 bits of an IEEE double, not a virtual address."""
    return 0x40400000 <= imm <= 0x407FFFFF


def is_palette_aperture_base(imm: int) -> bool:
    """lda 0x1800000 — virtual palette index base; downstream lda adds aperture offsets."""
    return imm == 0x1800000


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
    if prior_mnemonic == "cmpr" and len(prior_ops) >= 2:
        return cmpr_branch_cond(mnemonic, prior_ops[0], prior_ops[1])
    if prior_mnemonic == "cmprl" and len(prior_ops) >= 2:
        return cmprl_branch_cond(mnemonic, prior_ops[0], prior_ops[1])
    return None


def cmprl_branch_cond(mnemonic: str, lhs: str, rhs: str) -> str | None:
    """Long-real compare (cmprl) fused with ordered branch."""
    from liftkit.arch.i960.i960_fp_emit import rifl_src_expr

    a = rifl_src_expr(lhs)
    b = rifl_src_expr(rhs)
    if mnemonic == "be":
        return f"{a} == {b}"
    if mnemonic == "bne":
        return f"{a} != {b}"
    if mnemonic == "bg":
        return f"{a} > {b}"
    if mnemonic == "bl":
        return f"{a} < {b}"
    if mnemonic == "bge":
        return f"{a} >= {b}"
    if mnemonic == "ble":
        return f"{a} <= {b}"
    return None


def _index_scale_expr(index: str, scale: int) -> str:
    """C expression for index * scale (power-of-two scales use shifts)."""
    if scale == 1:
        return f"(u32){index}"
    if scale in (2, 4, 8, 16, 32):
        shift = {2: 1, 4: 2, 8: 3, 16: 4, 32: 5}[scale]
        return f"(u32)({index} << {shift})"
    return f"(u32)({index} * {scale})"


def _mem_offset_expr(op: Operand) -> int | str:
    """Displacement (+ optional scaled index) for load/store offset argument."""
    off = op.mem_offset or 0
    if not op.mem_index:
        return off
    idx = _index_scale_expr(op.mem_index, op.mem_scale or 1)
    if off == 0:
        return idx
    if off < 0:
        return f"({idx}) - 0x{-off:x}"
    return f"0x{off:x} + ({idx})"


def _ea_expr(op: Operand) -> str:
    """C expression for an lda effective address."""
    off = op.mem_offset or 0
    idx = (
        _index_scale_expr(op.mem_index, op.mem_scale or 1)
        if op.mem_index
        else None
    )
    base = op.mem_base
    if base is None:
        terms: list[str] = []
        if off != 0:
            terms.append(f"0x{off:x}" if off >= 0 else f"-0x{-off:x}")
        if idx is not None:
            terms.append(idx)
        if not terms:
            return "0"
        if len(terms) == 1:
            return terms[0]
        return " + ".join(terms)
    if base.lower() == "fp" and idx is None and off >= 0:
        return f"i960_fp_slot(0x{off:x})"
    expr = addr_uintptr(base)
    if off != 0:
        if off < 0:
            expr = f"{expr} - 0x{-off:x}"
        else:
            expr = f"{expr} + 0x{off:x}"
    if idx is not None:
        expr = f"{expr} + {idx}"
    return expr


def format_lda_expr(src: Operand, dst: str) -> tuple[str, dict[str, Any]]:
    """i960 lda — load effective address (not a memory load)."""
    meta: dict[str, Any] = {"lda": True}
    if src.kind in ("imm", "label") and src.imm is not None:
        if src.imm >= 0x100000:
            if is_movrl_double_high_word(src.imm):
                meta["fpu_literal"] = f"0x{src.imm:x}"
                return f"{dst} = 0x{src.imm:x}", meta
            if is_palette_aperture_base(src.imm):
                meta["palette_base"] = f"0x{src.imm:x}"
                return f"{dst} = 0x{src.imm:x}", meta
            expr, note = vaddr_ptr_expr(src.imm)
            meta["rom_ref"] = f"0x{src.imm:x}"
            if note:
                meta["rom_comment"] = note
            return f"{dst} = {expr}", meta
        if src.imm < MAINCPU_SIZE:
            # Word-aligned low ROM offsets are host pointers; larger immediates in the
            # maincpu image file (e.g. 0x186a0 timer token) stay scalar lda values.
            if src.imm % 4 == 0 and src.imm != 0 and src.imm < 0x10000:
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
        if base is not None and base.lower() == "fp" and not src.mem_index and off >= 0:
            meta["frame"] = {"base": "fp", "offset": off}
            return lda_to_reg(base, off, dst), meta
        if base is not None and not src.mem_index:
            return lda_to_reg(base, off, dst), meta
        meta["ea"] = {"base": base, "offset": off, "index": src.mem_index, "scale": src.mem_scale}
        return reg_assign(dst, _ea_expr(src)), meta
    return reg_assign(dst, u32_val(src.raw)), meta


def _mem_access_from(op: Operand, *, op_kind: str, width: str, value: str | None = None) -> MemAccess:
    base = op.mem_base or "?"
    return MemAccess(
        op=op_kind,
        space=space_for_operand(op),
        width=width,
        base=base.lower() if op.mem_base else base,
        offset=_mem_offset_expr(op),
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


def _scaled_index_expr(index: str) -> str:
    """Turn MAME 'g4*4' into a C offset expression (legacy token form)."""
    if "*" not in index:
        return f"(u32){index}"
    reg, scale_s = index.split("*", 1)
    return _index_scale_expr(reg.strip(), int(scale_s.strip(), 0))


def _space_c_for_addr(addr: int) -> str:
    from liftkit.arch.i960.i960_mem_emit import _SPACE_C, space_for_abs_addr

    return _SPACE_C.get(space_for_abs_addr(addr), "I960_ABS")


_PAIR_REG = re.compile(r"^([gr])(\d+)$", re.I)

# Registers each multi-word suffix moves: l = long, t = triple, q = quad.
_WORD_COUNT = {"l": 2, "t": 3, "q": 4}


def _reg_group(reg: str, count: int) -> list[str] | None:
    """The ``count`` consecutive registers a multi-word op names by its first.

    A long starts on an even register; a triple or quad on a multiple of four.
    """
    m = _PAIR_REG.match(reg.strip())
    if not m:
        return None
    idx = int(m.group(2))
    if idx % (2 if count == 2 else 4) != 0:
        return None
    prefix = m.group(1).lower()
    return [f"{prefix}{idx + k}" for k in range(count)]


def _is_zero_imm(op: Operand) -> bool:
    if op.raw in ("0", "0x0"):
        return True
    return op.kind in ("imm", "label") and op.imm == 0


def lower_multi_mov_stmts(mnemonic: str, operands: list[str]) -> list[tuple[str, dict[str, Any]]]:
    """Expand movl/movt/movq to one 32-bit assignment per register."""
    mn = mnemonic.lower()
    count = _WORD_COUNT.get(mn[3:]) if mn.startswith("mov") else None
    ops = parse_operands(operands)
    if count is None or len(ops) != 2:
        return []
    dst = _reg_group(ops[1].raw, count)
    if dst is None:
        return []
    meta: dict[str, Any] = {"mnemonic": mn, "operands": operands, "multi_reg": dst}

    imm = ops[0].imm if ops[0].kind in ("imm", "label") else None
    if imm is None and ops[0].raw.isdigit():
        imm = int(ops[0].raw)
    if imm is not None:
        # A literal lands in the first register; the rest are cleared.
        return [
            (f"{reg} = 0x{(imm >> (32 * k)) & 0xFFFFFFFF:x}", meta)
            for k, reg in enumerate(dst)
        ]

    src = _reg_group(ops[0].raw, count)
    if src is None:
        return []
    return [(f"{d} = {u32_val(r)}", meta) for r, d in zip(src, dst)]


def _word_offset(offset: int | str, k: int) -> int | str:
    if k == 0:
        return offset
    if isinstance(offset, int):
        return offset + 4 * k
    return f"({offset}) + 0x{4 * k:x}"


def lower_multi_mem(mn: str, ops: list[Operand]) -> tuple[str | None, dict[str, Any]]:
    """ldl/ldt/ldq and stl/stt/stq as one 32-bit access per register.

    Word k of the access is register k of the group, at the lowest address
    first — so the even register of an ldl gets the word at the address.
    """
    load = mn.startswith("ld")
    count = _WORD_COUNT[mn[2:]]
    reg_op, mem = (ops[1], ops[0]) if load else (ops[0], ops[1])
    regs = _reg_group(reg_op.raw, count)
    if regs is None:
        return None, {}
    kind = "load" if load else "store"
    meta: dict[str, Any] = {"multi_reg": regs}

    abs_addr = _abs_addr(mem)
    if abs_addr is not None or (mem.kind == "mem" and mem.mem_index and mem.mem_base is None):
        if abs_addr is not None:
            base, offset = abs_addr, 0
        else:
            off = mem.mem_offset or 0
            base = off if off >= 0 else off + 0x1_0000_0000
            offset = _index_scale_expr(mem.mem_index, mem.mem_scale or 1)
        space_c = _space_c_for_addr(base)
        meta["mem"] = {
            "op": kind,
            "space": space_for_abs_addr(base).value,
            "width": "u32",
            "base": f"0x{base:x}",
            "offset": offset,
        }
        stmts = []
        for k, reg in enumerate(regs):
            off_c = _word_offset(offset, k)
            if isinstance(off_c, int):
                off_c = f"0x{off_c:x}"
            if load:
                stmts.append(f"{reg} = i960_ld_u32({space_c}, 0x{base:x}, {off_c})")
            else:
                stmts.append(f"i960_st_u32({space_c}, 0x{base:x}, {off_c}, (u32){reg})")
        return "; ".join(stmts), meta

    if mem.kind != "mem" or not (mem.mem_base or mem.mem_index):
        return None, {}
    access = _mem_access_from(mem, op_kind=kind, width="u32", value=regs[0] if not load else None)
    meta.update(access.to_meta())
    stmts = []
    for k, reg in enumerate(regs):
        word = replace(access, offset=_word_offset(access.offset, k), value=None if load else reg)
        text = emit_load(reg, word) if load else emit_store(word)
        stmts.append(text.rstrip(";"))
    return "; ".join(stmts), meta


def insn_c_expr(mnemonic: str, operands: list[str]) -> str | None:
    expr, _ = insn_lower(mnemonic, operands)
    return expr


def insn_lower(mnemonic: str, operands: list[str]) -> tuple[str | None, dict[str, Any]]:
    mn = mnemonic.lower()
    meta: dict[str, Any] = {"mnemonic": mn, "operands": operands}
    if not operands:
        if mn == "flushreg":
            return "/* flushreg */", meta
        return None, {}
    ops = parse_operands(operands)

    fp_expr, fp_meta = lower_fp_insn(mn, operands)
    if fp_expr is not None:
        meta.update(fp_meta)
        return fp_expr, meta

    if mn == "mov" and len(ops) == 2:
        return f"{ops[1].raw} = {u32_val(ops[0].raw)}", meta
    if mn in ("synmov", "synmovq") and len(ops) == 2:
        src, dst = ops[0].raw, ops[1].raw
        meta["sync_move"] = mn
        if mn == "synmovq":
            return emit_synmovq(src, dst), meta
        return emit_synmov(src, dst), meta
    if mn == "xor" and len(ops) == 3:
        return f"{ops[2].raw} = {_alu_operand(ops[1])} ^ {_alu_operand(ops[0])}", meta
    if mn == "mulo" and len(ops) == 3:
        return f"{ops[2].raw} = (u32){ops[1].raw} * (u32){_alu_operand(ops[0])}", meta
    if mn == "shrdi" and len(ops) == 3:
        return f"{ops[2].raw} = (u32){ops[1].raw} >> {_imm(ops[0].raw)}", meta
    if mn == "setbit" and len(ops) == 3:
        bit = _imm(ops[0].raw)
        src = ops[1].raw
        dst = ops[2].raw
        # setbit bitpos, src, dst → dst = src | (1 << bitpos)
        return f"{dst} = {_alu_operand(ops[1])} | (1u << {bit})", meta
    if mn == "notbit" and len(ops) == 3:
        bit = _imm(ops[0].raw)
        src = _alu_operand(ops[1])
        dst = ops[2].raw
        return f"{dst} = {src} ^ (1u << {bit})", meta
    if mn == "andnot" and len(ops) == 3:
        # dst = src2 & ~src1
        return f"{ops[2].raw} = {_alu_operand(ops[1])} & ~{_alu_operand(ops[0])}", meta
    if mn == "clrbit" and len(ops) == 3:
        bit = _imm(ops[0].raw)
        src = _alu_operand(ops[1])
        dst = ops[2].raw
        return f"{dst} = {src} & ~(1u << {bit})", meta

    if mn == "ldis" and len(ops) == 2 and ops[0].mem_base:
        access = _mem_access_from(ops[0], op_kind="load", width="u16")
        meta.update(access.to_meta())
        return emit_load(ops[1].raw, access), meta

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
    if mn == "shri" and len(ops) == 3:
        return (
            f"{ops[2].raw} = (uintptr_t)((i32){ops[1].raw} >> {_imm(ops[0].raw)})",
            meta,
        )
    if mn == "divi" and len(ops) == 3:
        return (
            f"{ops[2].raw} = (uintptr_t)((i32){ops[1].raw} / (i32){_alu_operand(ops[0])})",
            meta,
        )

    if mn in ("ldl", "ldt", "ldq", "stl", "stt", "stq"):
        if len(ops) != 2:
            return None, meta
        expr, mem_meta = lower_multi_mem(mn, ops)
        meta.update(mem_meta)
        return expr, meta

    if mn == "lda" and len(ops) == 2:
        if ops[0].kind == "mem" and ops[1].raw == "sp" and ops[0].mem_base == "sp":
            off = ops[0].mem_offset or 0
            meta["stack"] = {"op": "alloc", "bytes": off}
            return f"sp = sp + 0x{off:x}", meta
        expr, lda_meta = format_lda_expr(ops[0], ops[1].raw)
        meta.update(lda_meta)
        return expr, meta

    load_map = {
        "ld": "u32",
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
        if ops[0].kind == "mem" and ops[0].mem_index and ops[0].mem_base is None:
            base = ops[0].mem_offset or 0
            abs_base = base if base >= 0 else base + 0x1_0000_0000
            idx = _index_scale_expr(ops[0].mem_index, ops[0].mem_scale or 1)
            space_c = _space_c_for_addr(abs_base)
            fn = {
                "u32": "i960_ld_u32",
                "u64": "i960_ld_u64",
                "u8": "i960_ld_u8",
                "u16": "i960_ld_u16",
            }[load_map[mn]]
            meta["mem"] = {
                "op": "load",
                "space": space_for_abs_addr(abs_base).value,
                "width": load_map[mn],
                "base": f"0x{abs_base:x}",
                "offset": idx,
            }
            return f"{ops[1].raw} = {fn}({space_c}, 0x{abs_base:x}, {idx});", meta
        if ops[0].kind == "mem" and (ops[0].mem_base or ops[0].mem_index):
            access = _mem_access_from(ops[0], op_kind="load", width=load_map[mn])
            meta.update(access.to_meta())
            return emit_load(ops[1].raw, access), meta

    store_map = {
        "st": "u32",
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
        if ops[1].kind == "mem" and ops[1].mem_index and ops[1].mem_base is None:
            base = ops[1].mem_offset or 0
            abs_base = base if base >= 0 else base + 0x1_0000_0000
            idx = _index_scale_expr(ops[1].mem_index, ops[1].mem_scale or 1)
            space_c = _space_c_for_addr(abs_base)
            fn = {
                "u32": "i960_st_u32",
                "u64": "i960_st_u64",
                "u8": "i960_st_u8",
                "u16": "i960_st_u16",
            }[store_map[mn]]
            cast = store_map[mn]
            meta["mem"] = {
                "op": "store",
                "space": space_for_abs_addr(abs_base).value,
                "width": store_map[mn],
                "base": f"0x{abs_base:x}",
                "offset": idx,
                "value": ops[0].raw,
            }
            return f"{fn}({space_c}, 0x{abs_base:x}, {idx}, ({cast}){ops[0].raw});", meta
        if ops[1].kind == "mem" and (ops[1].mem_base or ops[1].mem_index):
            if ops[1].space == MemSpace.MMIO_GEO and not ops[1].mem_index:
                off = ops[1].mem_offset or 0
                meta["mmio"] = {"offset": off}
                return emit_mmio_store(off if off >= 0 else off + 0x1_0000_0000, ops[0].raw), meta
            access = _mem_access_from(ops[1], op_kind="store", width=store_map[mn], value=ops[0].raw)
            meta.update(access.to_meta())
            return emit_store(access), meta

    return None, meta
