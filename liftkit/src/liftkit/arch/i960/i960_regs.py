"""i960 register model and value casts for lifted semantic C.

All g* and r* registers are 32-bit (i960 word). Memory widths and compare
semantics come from the instruction mnemonic, not from per-function maps.
"""

from __future__ import annotations

import re

REG_GR = re.compile(r"^[gr]\d+$", re.IGNORECASE)
ABI_ARG = re.compile(r"^arg\d+$", re.IGNORECASE)

I960_REG_TYPE = "uintptr_t"
I960_G_REGS = tuple(f"g{i}" for i in range(16))
I960_R_REGS = tuple(f"r{i}" for i in range(16))
I960_SHARED_REGS = frozenset((*I960_G_REGS, *I960_R_REGS, "fp", "sp"))
I960_IMPLICIT_REGS = I960_SHARED_REGS


def is_shared_reg(name: str) -> bool:
    return name.strip().lower() in I960_SHARED_REGS


def is_i960_reg(name: str) -> bool:
    token = name.strip().lower()
    return bool(REG_GR.match(token) or token in ("fp", "sp", "pfp", "rip"))


def is_abi_arg(name: str) -> bool:
    return bool(ABI_ARG.match(name.strip()))


def is_reg_operand(name: str) -> bool:
    return is_i960_reg(name) or is_abi_arg(name)


def reg_decl(name: str) -> str:
    """Per-function local register decl (unused — all g*/r* are shared)."""
    return f"register {I960_REG_TYPE} {name};"


def signed_byte(reg: str) -> str:
    """Low signed byte of a general register (cmpibge semantics)."""
    return f"(signed char){reg}"


def unsigned_byte(reg: str) -> str:
    """Low unsigned byte of a general register (cmpibne/cmpobne semantics)."""
    return f"(unsigned char){reg}"


def reg_assign(dst: str, expr: str) -> str:
    """Assign into a register or ABI argument."""
    return f"{dst} = {expr}"


def u32_val(expr: str) -> str:
    """Coerce an expression into a register value."""
    if is_abi_arg(expr):
        return f"(uintptr_t){expr}"
    return expr


def addr_uintptr(base: str) -> str:
    """Expression usable as uintptr_t for address arithmetic."""
    if base in ("sp", "fp") or is_reg_operand(base):
        return base
    return f"(uintptr_t){base}"


def addr_ptr(base: str) -> str:
    """Register or arg holding an address -> typed pointer."""
    return f"(void *){base}"


def mem_load(base: str, *, ctype: str) -> str:
    return f"*({ctype} *){addr_ptr(base)}"


def mem_store_value(value: str, base: str, *, ctype: str) -> str:
    if ctype == "unsigned char":
        val = f"(unsigned char){value}"
    elif ctype == "unsigned short":
        val = f"(unsigned short){value}"
    elif ctype == "u32":
        val = f"(u32){value}"
    elif ctype == "u64":
        val = f"(u64){value}"
    else:
        val = value
    return f"*({ctype} *){addr_ptr(base)} = {val}"


def _offset_term(offset: int) -> str:
    if offset < 0:
        return f"- 0x{-offset:x}"
    return f"+ 0x{offset:x}"


def lda_to_reg(base: str, offset: int, dst: str) -> str:
    if base.lower() == "fp" and offset >= 0:
        return reg_assign(dst, f"i960_fp_slot(0x{offset:x})")
    if offset == 0:
        return reg_assign(dst, addr_uintptr(base))
    if offset >= 0x1000000:
        return reg_assign(dst, f"{addr_uintptr(base)} {_offset_term(offset)}")
    if offset >= 0x10000:
        return reg_assign(
            dst,
            f"(uintptr_t)i960_vaddr_ptr((u32)({addr_uintptr(base)} {_offset_term(offset)}))",
        )
    return reg_assign(dst, f"{addr_uintptr(base)} {_offset_term(offset)}")
