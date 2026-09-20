"""i960-ML intermediate representation and CFG lift."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from tools.decomp.disasm_parse import Insn, SliceDocument
from tools.decomp.i960_macros import (
    FunctionProfile,
    MacroStmt,
    apply_macros,
    detect_function_profile,
)
from tools.decomp.i960_regs import I960_REG_TYPE


class StmtKind(str, Enum):
    LABEL = "label"
    COMMENT = "comment"
    MACRO = "macro"
    ASSIGN = "assign"
    BRANCH = "branch"
    CALL = "call"
    RETURN = "return"
    RAW = "raw"
    DATA = "data"


@dataclass
class IrArg:
    reg: str
    name: str
    ctype: str = "unsigned"


@dataclass
class IrStmt:
    kind: StmtKind
    text: str
    addr: int | None = None
    words: list[int] = field(default_factory=list)
    target: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class IrBlock:
    addr: int
    stmts: list[IrStmt] = field(default_factory=list)


@dataclass
class IrFunction:
    name: str
    addr: int
    length: int
    kind: str
    args: list[IrArg]
    link_reg: str | None
    blocks: list[IrBlock]
    entry: int
    source: str = ""
    regions: list[Any] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        from tools.decomp.i960_cfg import regions_to_json

        return {
            "name": self.name,
            "addr": f"0x{self.addr:x}",
            "length": self.length,
            "kind": self.kind,
            "link_reg": self.link_reg,
            "entry": f"0x{self.entry:x}",
            "source": self.source,
            "args": [asdict(a) for a in self.args],
            "regions": regions_to_json(self.regions),
            "blocks": [
                {
                    "addr": f"0x{b.addr:x}",
                    "stmts": [
                        {
                            "kind": s.kind.value,
                            "text": s.text,
                            "addr": f"0x{s.addr:x}" if s.addr is not None else None,
                            "words": [f"0x{w:08x}" for w in s.words],
                            "target": f"0x{s.target:x}" if s.target is not None else None,
                            "meta": s.meta,
                        }
                        for s in b.stmts
                    ],
                }
                for b in self.blocks
            ],
        }


def _macro_to_ir(stmt: MacroStmt) -> IrStmt:
    kind_map = {
        "macro": StmtKind.MACRO,
        "assign": StmtKind.ASSIGN,
        "branch": StmtKind.BRANCH,
        "call": StmtKind.CALL,
        "return": StmtKind.RETURN,
        "raw": StmtKind.RAW,
        "data": StmtKind.DATA,
    }
    return IrStmt(
        kind=kind_map.get(stmt.kind, StmtKind.RAW),
        text=stmt.text,
        addr=stmt.addr,
        words=list(stmt.words),
        target=stmt.meta.get("target"),
        meta=dict(stmt.meta),
    )


def _parse_target(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        token = value.strip()
        if token.startswith("0x"):
            return int(token, 16)
    return None


def _block_starts(doc: SliceDocument, macro_stmts: list[MacroStmt]) -> list[int]:
    starts = {doc.base}
    for insn in doc.insns:
        starts.add(insn.addr)
    for stmt in macro_stmts:
        target = _parse_target(stmt.meta.get("target"))
        if target is not None:
            starts.add(target)
    return sorted(starts)


def _assign_block(stmts: list[IrStmt], block_addr: int, next_block: int | None) -> IrBlock:
    return IrBlock(addr=block_addr, stmts=stmts)


def lift_macros_to_blocks(doc: SliceDocument, macro_stmts: list[MacroStmt]) -> list[IrBlock]:
    """Partition macro stmts into basic blocks keyed by insn address."""
    by_addr: dict[int, list[IrStmt]] = {}
    for ms in macro_stmts:
        if ms.addr is None:
            continue
        by_addr.setdefault(ms.addr, []).append(_macro_to_ir(ms))

    block_addrs = _block_starts(doc, macro_stmts)
    blocks: list[IrBlock] = []
    for addr in block_addrs:
        if addr in by_addr:
            block_stmts = [IrStmt(kind=StmtKind.LABEL, text=f"L_{addr:08x}:", addr=addr)]
            block_stmts.extend(by_addr[addr])
            blocks.append(IrBlock(addr=addr, stmts=block_stmts))
    if not blocks and by_addr:
        for addr in sorted(by_addr):
            blocks.append(IrBlock(addr=addr, stmts=by_addr[addr]))
    return blocks


def _infer_args(profile: FunctionProfile, name: str) -> list[IrArg]:
    if profile.args:
        return [
            IrArg(reg=reg, name=arg, ctype=I960_REG_TYPE)
            for reg, arg in profile.args
        ]
    return [IrArg(reg="g0", name="arg0", ctype=I960_REG_TYPE)]


def lift_slice(
    doc: SliceDocument,
    *,
    name: str,
    profile: FunctionProfile | None = None,
) -> IrFunction:
    profile = profile or detect_function_profile(doc.insns)
    macro_stmts = apply_macros(doc, profile)
    blocks = lift_macros_to_blocks(doc, macro_stmts)
    args = _infer_args(profile, name)
    fn = IrFunction(
        name=name,
        addr=doc.base,
        length=doc.length,
        kind=profile.kind.value,
        args=args,
        link_reg=profile.link_reg,
        blocks=blocks,
        entry=doc.base,
        source=doc.source,
    )
    return fn


def write_ir_json(fn: IrFunction, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fn.to_json(), indent=2) + "\n", encoding="utf-8")
