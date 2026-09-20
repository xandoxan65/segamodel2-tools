"""i960 operand parsing and memory-space classification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

REG_G = re.compile(r"^g(\d+)$", re.IGNORECASE)
REG_R = re.compile(r"^r(\d+)$", re.IGNORECASE)
REG_SF = re.compile(r"^sf(\d+)$", re.IGNORECASE)
# MEMA/MEMB with optional displacement, base, and scaled index:
#   (r8)[r8*8]  0xffffffff(g9)[g6]  0x18(g5)[g4*4]
MEM_BASE_INDEX = re.compile(
    r"^(?:0x([0-9a-fA-F]+))?\(([^)]+)\)\[([^\]]+)\]$"
)
MEM_DISP = re.compile(r"^0x([0-9a-fA-F]+)\(([^)]+)\)$")
# Absolute + scaled index: 0x1000[g4*4]
MEM_ABS_INDEX = re.compile(r"^0x([0-9a-fA-F]+)\[([^\]]+)\]$")
MEM_IND = re.compile(r"^\(([^)]+)\)$")
HEX_LIT = re.compile(r"^0x[0-9a-fA-F]+$")
FLOAT_LIT = re.compile(r"^\+?-?\d+\.\d+$")
INDEX_SCALE = re.compile(r"^([gr]\d+)(?:\*(\d+))?$", re.IGNORECASE)

try:
    from tools.i960_memory import (
        GEO_WRITE_START,
        MAIN_DATA_A,
        MAIN_DATA_SIZE,
        WORKRAM_BASE,
        WORKRAM_SIZE,
        is_mmio_addr,
        lookup_region,
    )
except ImportError:
    GEO_WRITE_START = 0x0080_1008
    WORKRAM_BASE = 0x0050_0000
    WORKRAM_SIZE = 0x0010_0000
    MAIN_DATA_A = 0x0200_0000
    MAIN_DATA_SIZE = 0x0200_0000

    def lookup_region(addr: int):  # type: ignore[misc]
        return None

    def is_mmio_addr(addr: int) -> bool:
        return addr == GEO_WRITE_START or (0x0080_0000 <= addr < 0x0080_4000)


class MemSpace(str, Enum):
    UNKNOWN = "unknown"
    REG_INDIRECT = "reg_indirect"
    WORKRAM = "workram"
    MAIN_DATA = "main_data"
    MMIO_GEO = "mmio_geo"
    ABSOLUTE = "absolute"


@dataclass(frozen=True)
class Operand:
    raw: str
    kind: str  # reg, imm, mem, label
    reg: str | None = None
    imm: int | None = None
    mem_base: str | None = None
    mem_offset: int | None = None  # signed displacement
    mem_index: str | None = None
    mem_scale: int = 1
    space: MemSpace = MemSpace.UNKNOWN

    @property
    def is_reg(self) -> bool:
        return self.kind == "reg"


def space_for_abs_addr(addr: int) -> MemSpace:
    if is_mmio_addr(addr):
        return MemSpace.MMIO_GEO
    entry = lookup_region(addr)
    if entry is not None:
        if entry.kind == "ram":
            if WORKRAM_BASE <= addr < WORKRAM_BASE + WORKRAM_SIZE:
                return MemSpace.WORKRAM
            if 0x0020_0000 <= addr < 0x0024_0000:
                return MemSpace.WORKRAM
        if entry.kind == "rom":
            if addr < 0x0020_0000:
                return MemSpace.ABSOLUTE
            return MemSpace.MAIN_DATA
    if WORKRAM_BASE <= addr < WORKRAM_BASE + WORKRAM_SIZE:
        return MemSpace.WORKRAM
    if 0x0020_0000 <= addr < 0x0060_0000:
        return MemSpace.WORKRAM
    if MAIN_DATA_A <= addr < MAIN_DATA_A + MAIN_DATA_SIZE:
        return MemSpace.MAIN_DATA
    if addr >= 0x1000:
        return MemSpace.ABSOLUTE
    return MemSpace.UNKNOWN


def _space_for_addr(addr: int) -> MemSpace:
    return space_for_abs_addr(addr)


def signed_disp(off: int) -> int:
    """Interpret a 32-bit hex displacement as signed i32."""
    if off >= 0x8000_0000:
        return off - 0x1_0000_0000
    return off


def parse_index_scale(token: str) -> tuple[str, int] | None:
    """Parse 'g4' or 'g4*4' into (reg, scale)."""
    m = INDEX_SCALE.match(token.strip())
    if not m:
        return None
    reg = m.group(1).lower()
    scale = int(m.group(2)) if m.group(2) else 1
    if scale not in (1, 2, 4, 8, 16):
        return None
    return reg, scale


def parse_operand(raw: str) -> Operand:
    token = raw.strip()
    m = MEM_BASE_INDEX.match(token)
    if m:
        off_s, base, index_s = m.group(1), m.group(2).strip(), m.group(3).strip()
        off = signed_disp(int(off_s, 16)) if off_s else 0
        parsed = parse_index_scale(index_s)
        if parsed is None:
            return Operand(raw=token, kind="reg", reg=token)
        index, scale = parsed
        return Operand(
            raw=token,
            kind="mem",
            mem_base=base,
            mem_offset=off,
            mem_index=index,
            mem_scale=scale,
            space=MemSpace.REG_INDIRECT,
        )
    m = MEM_DISP.match(token)
    if m:
        off = signed_disp(int(m.group(1), 16))
        base = m.group(2).strip()
        return Operand(
            raw=token,
            kind="mem",
            mem_base=base,
            mem_offset=off,
            space=MemSpace.REG_INDIRECT,
        )
    m = MEM_ABS_INDEX.match(token)
    if m:
        off = signed_disp(int(m.group(1), 16))
        parsed = parse_index_scale(m.group(2).strip())
        if parsed is None:
            return Operand(raw=token, kind="reg", reg=token)
        index, scale = parsed
        return Operand(
            raw=token,
            kind="mem",
            mem_base=None,
            mem_offset=off,
            mem_index=index,
            mem_scale=scale,
            space=_space_for_addr(off if off >= 0 else off + 0x1_0000_0000),
        )
    m = MEM_IND.match(token)
    if m:
        base = m.group(1).strip()
        return Operand(
            raw=token,
            kind="mem",
            mem_base=base,
            mem_offset=0,
            space=MemSpace.REG_INDIRECT,
        )
    if HEX_LIT.match(token):
        return Operand(raw=token, kind="imm", imm=int(token, 16))
    if FLOAT_LIT.match(token):
        return Operand(raw=token, kind="fp_imm")
    if token.lower() in ("fp0", "fp1", "fp2", "fp3"):
        return Operand(raw=token, kind="reg", reg=token.lower())
    if token.startswith("0x") and "(" not in token:
        return Operand(raw=token, kind="label", imm=int(token, 16))
    if REG_G.match(token) or REG_R.match(token) or REG_SF.match(token) or token in ("fp", "pfp", "rip"):
        return Operand(raw=token, kind="reg", reg=token.lower())
    return Operand(raw=token, kind="reg", reg=token)


def parse_operands(raw_ops: list[str]) -> list[Operand]:
    return [parse_operand(op) for op in raw_ops]
