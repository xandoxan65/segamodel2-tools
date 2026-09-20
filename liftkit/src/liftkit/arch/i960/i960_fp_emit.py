"""Lower i960 real (rif/rifl) instructions to lifted C."""

from __future__ import annotations

import re
from typing import Any

from liftkit.arch.i960.i960_operand import Operand, parse_operands
from liftkit.arch.i960.i960_regs import is_i960_reg

FP_REGS = frozenset({"fp0", "fp1", "fp2", "fp3"})
FLOAT_LIT = re.compile(r"^\+?-?\d+\.\d+$")
_PAIR_REG = re.compile(r"^([gr])(\d+)$", re.I)


def is_fp_reg(name: str) -> bool:
    return name.strip().lower() in FP_REGS


def _reg_pair(reg: str) -> tuple[str, str] | None:
    m = _PAIR_REG.match(reg.strip())
    if not m:
        return None
    idx = int(m.group(2))
    if idx % 2 != 0:
        return None
    prefix = m.group(1).lower()
    return f"{prefix}{idx}", f"{prefix}{idx + 1}"


def _float_literal(token: str) -> float | None:
    if not FLOAT_LIT.match(token.strip()):
        return None
    try:
        return float(token)
    except ValueError:
        return None


def _rif_src(op: Operand) -> str:
    if is_fp_reg(op.raw):
        return op.raw.lower()
    lit = _float_literal(op.raw)
    if lit is not None:
        return repr(lit)
    if op.kind == "reg" and is_i960_reg(op.raw):
        return f"i960_u32_to_f64({op.raw})"
    return op.raw


def _rifl_src(op: Operand) -> str:
    if is_fp_reg(op.raw):
        return op.raw.lower()
    lit = _float_literal(op.raw)
    if lit is not None:
        return repr(lit)
    pair = _reg_pair(op.raw)
    if pair is not None:
        lo, hi = pair
        return f"i960_rifl_read({lo}, {hi})"
    if op.kind == "reg" and is_i960_reg(op.raw):
        lo = op.raw
        hi = f"{op.raw[:-1]}{int(op.raw[1:]) + 1}" if _PAIR_REG.match(op.raw) else None
        if hi:
            return f"i960_rifl_read({lo}, {hi})"
    return op.raw


def rifl_src_expr(token: str) -> str:
    """Public helper for cmprl branch fusion."""
    return _rifl_src(parse_operands([token])[0])


def _rif_dst(reg: str, expr: str) -> str:
    if is_fp_reg(reg):
        return f"{reg.lower()} = {expr}"
    return f"{reg} = i960_f64_to_u32({expr})"


def _rifl_dst(reg: str, expr: str) -> str:
    if is_fp_reg(reg):
        return f"{reg.lower()} = {expr}"
    pair = _reg_pair(reg)
    if pair is not None:
        lo, hi = pair
        return f"i960_rifl_write(&{lo}, &{hi}, {expr})"
    return f"{reg} = (uintptr_t)(u64)(int64_t)({expr})"


def _rifl_dst_pair(reg: str, expr: str) -> str:
    """Store long real; cvtzril uses set_ri64 (even/odd pair)."""
    pair = _reg_pair(reg)
    if pair is not None:
        lo, hi = pair
        return (
            f"{{ i64 _cvt = (i64)({expr}); "
            f"{lo} = (uintptr_t)(u32)_cvt; {hi} = (uintptr_t)(u32)((u64)_cvt >> 32); }}"
        )
    return _rif_dst(reg, expr)


def lower_fp_insn(mnemonic: str, operands: list[str]) -> tuple[str | None, dict[str, Any]]:
    if not operands:
        return None, {}
    ops = parse_operands(operands)
    mn = mnemonic.lower()
    meta: dict[str, Any] = {"mnemonic": mn, "operands": operands, "fp": True}

    if mn == "movr" and len(ops) == 2:
        return _rif_dst(ops[1].raw, _rif_src(ops[0])), meta

    if mn == "movrl" and len(ops) == 2:
        return _rifl_dst(ops[1].raw, _rifl_src(ops[0])), meta

    if mn == "cvtir" and len(ops) == 2:
        src = ops[0].raw
        dst = ops[1].raw
        return _rif_dst(dst, f"(double)(i32)(u32)({src})"), meta

    if mn == "cvtzri" and len(ops) == 2:
        src = _rif_src(ops[0])
        dst = ops[1].raw
        return f"{dst} = (uintptr_t)(i32)({src})", meta

    if mn == "cvtzril" and len(ops) == 2:
        return _rifl_dst_pair(ops[1].raw, _rifl_src(ops[0])), meta

    if mn == "sqrtr" and len(ops) == 2:
        return _rif_dst(ops[1].raw, f"sqrt({_rif_src(ops[0])})"), meta

    # cpysre src1, src2, dst — magnitude of src2, sign of src1 (IEEE copysign).
    if mn == "cpysre" and len(ops) == 3:
        return _rif_dst(ops[2].raw, f"copysign({_rif_src(ops[1])}, {_rif_src(ops[0])})"), meta
    if mn == "cpyrsre" and len(ops) == 3:
        return _rif_dst(
            ops[2].raw,
            f"copysign({_rif_src(ops[1])}, -{_rif_src(ops[0])})",
        ), meta

    three_op_rif = {
        "mulr": "*",
        "divr": "/",
        "subr": "-",
        "addr": "+",
    }
    if mn in three_op_rif and len(ops) == 3:
        op_sym = three_op_rif[mn]
        src1 = _rif_src(ops[0])
        src2 = _rif_src(ops[1])
        dst = ops[2].raw
        return _rif_dst(dst, f"({src2}) {op_sym} ({src1})"), meta

    three_op_rifl = {
        "mulrl": "*",
        "divrl": "/",
        "subrl": "-",
        "addrl": "+",
    }
    if mn in three_op_rifl and len(ops) == 3:
        op_sym = three_op_rifl[mn]
        src1 = _rifl_src(ops[0])
        src2 = _rifl_src(ops[1])
        dst = ops[2].raw
        return _rifl_dst(dst, f"({src2}) {op_sym} ({src1})"), meta

    return None, meta
