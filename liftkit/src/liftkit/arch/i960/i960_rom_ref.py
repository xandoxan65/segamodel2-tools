"""ROM / RAM virtual address → host pointer expressions for lifted lda."""

from __future__ import annotations

from liftkit.arch.i960.i960_rom_backend import rom_ref_annotation
from liftkit.arch.i960.i960_symbols import lookup_symbol_name
from liftkit.arch.i960.memory_map import MAINCPU_SIZE, WORKRAM_BASE, WORKRAM_SIZE

CRX_RAM_BASE = 0x0020_0000
CRX_RAM_SIZE = 0x0004_0000
CPU_WAIT_BASE = 0x00E0_0000
CPU_WAIT_SIZE = 0x38


def _comment(addr: int) -> str | None:
    name = lookup_symbol_name(addr)
    note = rom_ref_annotation(addr)
    if name and note:
        return f"{note} /* sym:{name} */"
    if name:
        return f"/* rom:{name} */"
    return note


def vaddr_ptr_expr(vaddr: int) -> tuple[str, str | None]:
    """Return (C expression, optional comment) for an i960 virtual address used as a pointer."""
    note = _comment(vaddr)
    if vaddr < MAINCPU_SIZE:
        expr = f"(uintptr_t)(model2_maincpu_rom + 0x{vaddr:x})"
    elif CRX_RAM_BASE <= vaddr < CRX_RAM_BASE + CRX_RAM_SIZE:
        expr = f"(uintptr_t)(model2_crx_ram + 0x{vaddr - CRX_RAM_BASE:x})"
    elif WORKRAM_BASE <= vaddr < WORKRAM_BASE + WORKRAM_SIZE:
        expr = f"(uintptr_t)(model2_workram + 0x{vaddr - WORKRAM_BASE:x})"
    elif CPU_WAIT_BASE <= vaddr < CPU_WAIT_BASE + CPU_WAIT_SIZE:
        expr = f"(uintptr_t)(model2_cpu_wait + 0x{vaddr - CPU_WAIT_BASE:x})"
    else:
        expr = f"(uintptr_t)i960_vaddr_ptr(0x{vaddr:x})"
    return expr, note


def rom_addr_expr(addr: int) -> tuple[str, str | None]:
    """Alias for lda / absolute references (legacy name)."""
    return vaddr_ptr_expr(addr)


def maincpu_rom_ptr_expr(rom_off: int) -> tuple[str, str | None]:
    """Pointer into the deinterleaved maincpu image."""
    return vaddr_ptr_expr(rom_off)
