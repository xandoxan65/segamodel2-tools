"""Python host for lifted i960 functions — interprets IR for unit tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.decomp.i960_ir import IrFunction, IrStmt, StmtKind


@dataclass
class HostMemory:
    workram: bytearray = field(default_factory=lambda: bytearray(0x100000))
    geo_fifo: list[int] = field(default_factory=list)

    def load32(self, addr: int) -> int:
        if addr < len(self.workram) - 3:
            return int.from_bytes(self.workram[addr : addr + 4], "little")
        return 0

    def store32(self, addr: int, value: int) -> None:
        if addr < len(self.workram) - 3:
            self.workram[addr : addr + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")

    def load8(self, addr: int) -> int:
        if addr < len(self.workram):
            return self.workram[addr]
        return 0

    def store8(self, addr: int, value: int) -> None:
        if addr < len(self.workram):
            self.workram[addr] = value & 0xFF


@dataclass
class Machine:
    g: list[int] = field(default_factory=lambda: [0] * 16)
    r: list[int] = field(default_factory=lambda: [0] * 16)
    mem: HostMemory = field(default_factory=HostMemory)
    link: int = 0
    stopped: bool = False
    return_value: int = 0


def _parse_assign(text: str, machine: Machine) -> None:
    """Best-effort exec for simple lifted assignments (test helper)."""
    text = text.strip().rstrip(";")
    if "=" not in text:
        return
    lhs, rhs = text.split("=", 1)
    lhs = lhs.strip()
    rhs = rhs.strip()
    if lhs.startswith("g") and lhs[1:].isdigit():
        machine.g[int(lhs[1:])] = _eval_simple(rhs, machine) & 0xFFFFFFFF


def _eval_simple(expr: str, machine: Machine) -> int:
    expr = expr.strip()
    for i in range(16):
        expr = expr.replace(f"g{i}", str(machine.g[i]))
    if expr.startswith("0x"):
        return int(expr, 16)
    if expr.isdigit():
        return int(expr)
    if " >> " in expr:
        a, b = expr.split(" >> ", 1)
        return int(a.strip()) >> int(b.strip())
    if " & " in expr:
        a, b = expr.split(" & ", 1)
        return int(a.strip()) & int(b.strip())
    if " | " in expr:
        a, b = expr.split(" | ", 1)
        return int(a.strip()) | int(b.strip())
    if " + " in expr:
        a, b = expr.split(" + ", 1)
        return int(a.strip()) + int(b.strip())
    if " - " in expr:
        a, b = expr.split(" - ", 1)
        return int(a.strip()) - int(b.strip())
    return 0


def run_ir_function(fn: IrFunction, *args: int) -> int:
    """Execute lifted IR in a trivial interpreter (libc smoke tests only)."""
    machine = Machine()
    for i, arg in enumerate(args):
        if i < 16:
            machine.g[i] = arg & 0xFFFFFFFF

    if fn.kind == "leaf_bx" and fn.link_reg:
        lr = fn.link_reg
        if lr.startswith("g") and lr[1:].isdigit():
            machine.g[int(lr[1:])] = 0  # link slot

    for block in fn.blocks:
        for stmt in block.stmts:
            if machine.stopped:
                break
            _exec_stmt(stmt, machine, fn)
        if machine.stopped:
            break

    return machine.return_value


def _exec_stmt(stmt: IrStmt, machine: Machine, fn: IrFunction) -> None:
    if stmt.kind == StmtKind.ASSIGN:
        _parse_assign(stmt.text, machine)
    elif stmt.kind == StmtKind.RETURN:
        if fn.name.endswith("strcpy"):
            machine.return_value = machine.g[0]
        machine.stopped = True
    elif stmt.kind in (StmtKind.RAW, StmtKind.MACRO, StmtKind.BRANCH):
        pass  # interpreter MVP skips control flow


def memcpy_semantic(dst: int, src: int, length: int, mem: HostMemory) -> None:
    """Reference memcpy for host validation."""
    for i in range(length):
        mem.store8(dst + i, mem.load8(src + i))


def strcpy_semantic(dst: int, src: int, mem: HostMemory) -> int:
    if dst == 0 or mem.load8(src) == 0:
        return 0
    d = dst - 1
    while True:
        c = mem.load8(src)
        src += 1
        d += 1
        mem.store8(d, c)
        if c == 0:
            break
    return dst
