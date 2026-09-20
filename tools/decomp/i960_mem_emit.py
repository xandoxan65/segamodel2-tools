"""Emit space-tagged i960 memory intrinsics for lifted C."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.decomp.i960_operand import MemSpace, Operand, parse_operand, parse_operands, space_for_abs_addr

try:
    from tools.i960_memory import region_name
except ImportError:
    def region_name(addr: int) -> str | None:  # type: ignore[misc]
        return None


@dataclass(frozen=True)
class MemAccess:
    op: str  # load | store
    space: MemSpace
    width: str  # u8, u16, u32, u64
    base: str
    offset: int | str  # constant or C expr (scaled index / combined)
    value: str | None = None  # store source reg

    def to_meta(self) -> dict[str, Any]:
        return {
            "mem": {
                "op": self.op,
                "space": self.space.value,
                "width": self.width,
                "base": self.base,
                "offset": self.offset,
                "value": self.value,
            }
        }


_SPACE_C = {
    MemSpace.REG_INDIRECT: "I960_REG",
    MemSpace.WORKRAM: "I960_WORKRAM",
    MemSpace.MAIN_DATA: "I960_ROM",
    MemSpace.MMIO_GEO: "I960_MMIO",
    MemSpace.ABSOLUTE: "I960_ROM",
    MemSpace.UNKNOWN: "I960_ABS",
}


def space_for_operand(op: Operand) -> MemSpace:
    if op.kind != "mem":
        return MemSpace.UNKNOWN
    base = (op.mem_base or "").lower()
    if base == "fp":
        return MemSpace.REG_INDIRECT  # emit uses I960_FP when base is fp
    return op.space


def _space_c(space: MemSpace, base: str) -> str:
    if base.lower() == "fp":
        return "I960_FP"
    if base.lower() == "sp":
        return "I960_REG"
    return _SPACE_C.get(space, "I960_ABS")


def _off_c(offset: int | str) -> str:
    if isinstance(offset, str):
        return offset
    if offset < 0:
        return f"-0x{-offset:x}"
    return f"0x{offset:x}"


def _off_hex(offset: int) -> str:
    """Absolute address / MMIO offset as hex (unsigned view)."""
    if offset < 0:
        return f"0x{(offset + 0x1_0000_0000) & 0xFFFFFFFF:x}"
    return f"0x{offset:x}"


def emit_load(dst: str, access: MemAccess) -> str:
    fn = {
        "u8": "i960_ld_u8",
        "u16": "i960_ld_u16",
        "u32": "i960_ld_u32",
        "u64": "i960_ld_u64",
    }[access.width]
    space = _space_c(access.space, access.base)
    off = _off_c(access.offset)
    if access.width == "u64":
        return f"{dst} = (u32){fn}({space}, {access.base}, {off});"
    return f"{dst} = {fn}({space}, {access.base}, {off});"


def emit_store(access: MemAccess) -> str:
    assert access.value is not None
    fn = {
        "u8": "i960_st_u8",
        "u16": "i960_st_u16",
        "u32": "i960_st_u32",
        "u64": "i960_st_u64",
    }[access.width]
    space = _space_c(access.space, access.base)
    cast = {"u8": "u8", "u16": "u16", "u32": "u32", "u64": "u64"}[access.width]
    return f"{fn}({space}, {access.base}, {_off_c(access.offset)}, ({cast}){access.value});"


def emit_mmio_store(offset: int, value: str) -> str:
    return f"i960_mmio_write_u32({_off_hex(offset)}, (u32){value});"


def emit_mmio_store_u8(offset: int, value: str) -> str:
    return f"i960_mmio_write_u8({_off_hex(offset)}, (u8){value});"


def _mmio_comment(addr: int) -> str:
    name = region_name(addr)
    return f" /* {name} */" if name else ""


def emit_abs_load(dst: str, width: str, addr: int) -> str:
    space = space_for_abs_addr(addr)
    cmt = _mmio_comment(addr) if space == MemSpace.MMIO_GEO else ""
    if space == MemSpace.MMIO_GEO and width == "u8":
        return f"{dst} = i960_mmio_read_u8({_off_hex(addr)});{cmt}"
    fn = {
        "u8": "i960_ld_u8",
        "u16": "i960_ld_u16",
        "u32": "i960_ld_u32",
        "u64": "i960_ld_u64",
    }[width]
    space_c = _SPACE_C.get(space, "I960_ABS")
    if width == "u64":
        return f"{dst} = (u32){fn}({space_c}, {_off_hex(addr)}, 0);{cmt}"
    return f"{dst} = {fn}({space_c}, {_off_hex(addr)}, 0);{cmt}"


def emit_abs_store(width: str, addr: int, value: str) -> str:
    space = space_for_abs_addr(addr)
    cmt = _mmio_comment(addr) if space == MemSpace.MMIO_GEO else ""
    if space == MemSpace.MMIO_GEO and width == "u8":
        return f"{emit_mmio_store_u8(addr, value)}{cmt}"
    if space == MemSpace.MMIO_GEO and width == "u32":
        return f"{emit_mmio_store(addr, value)}{cmt}"
    fn = {
        "u8": "i960_st_u8",
        "u16": "i960_st_u16",
        "u32": "i960_st_u32",
        "u64": "i960_st_u64",
    }[width]
    space_c = _SPACE_C.get(space, "I960_ABS")
    cast = {"u8": "u8", "u16": "u16", "u32": "u32", "u64": "u64"}[width]
    return f"{fn}({space_c}, {_off_hex(addr)}, 0, ({cast}){value});"


def emit_synmov(src: str, dst: str) -> str:
    return f"i960_synmov({src}, {dst});"


def emit_synmovq(src: str, dst: str) -> str:
    return f"i960_synmovq({src}, {dst});"
