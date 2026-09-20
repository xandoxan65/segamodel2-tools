"""Model 2 i960 convention macros applied to structured disasm."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from liftkit.arch.i960.disasm_parse import Insn, SliceDocument
from liftkit.arch.i960.i960_ops import (
    ac_branch_cond,
    bbs_cond,
    cmpibg_cond,
    cmpibge_cond,
    cmpibe_cond,
    cmpible_cond,
    cmpibl_cond,
    cmpibne_cond,
    cmpobge_cond,
    cmpob_reg_cond,
    cmpobne_cond,
    insn_lower,
    lower_movq_stmts,
)
from liftkit.arch.i960.i960_regs import is_i960_reg, reg_assign


class FuncKind(str, Enum):
    LEAF_BX = "leaf_bx"
    LEAF_RET = "leaf_ret"
    FRAME = "frame"
    UNKNOWN = "unknown"


@dataclass
class MacroArg:
    name: str
    value: str


@dataclass
class MacroStmt:
    kind: str
    text: str
    addr: int | None = None
    words: list[int] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionProfile:
    kind: FuncKind = FuncKind.UNKNOWN
    link_reg: str | None = None
    args: list[tuple[str, str]] = field(default_factory=list)  # (reg, name)
    marshal_detected: bool = False


ARG_NAMES = ("arg0", "arg1", "arg2", "arg3", "arg4", "arg5")


def detect_function_profile(insns: list[Insn]) -> FunctionProfile:
    profile = FunctionProfile()
    if len(insns) >= 2:
        i0, i1 = insns[0], insns[1]
        if (
            i0.mnemonic == "mov"
            and len(i0.operands) == 2
            and i0.operands[0] == "g14"
            and i1.mnemonic == "mov"
            and len(i1.operands) == 2
            and i1.operands[0] in ("0", "0x0")
            and i1.operands[1] == "g14"
        ):
            profile.kind = FuncKind.LEAF_BX
            profile.link_reg = i0.operands[1]
            profile.args = [("g0", "arg0"), ("g1", "arg1"), ("g2", "arg2")]
            return profile

    if _detect_frame_marshal(insns):
        profile.kind = FuncKind.FRAME
        profile.marshal_detected = True
        profile.args = [("g0", "arg0"), ("g1", "arg1"), ("g2", "arg2")]
        return profile

    profile.kind = FuncKind.LEAF_RET
    profile.args = [("g0", "arg0"), ("g1", "arg1"), ("g2", "arg2")]
    return profile


def _detect_frame_marshal(insns: list[Insn]) -> bool:
    """Detect g14→g13 va-block marshal prologue (frame functions with call)."""
    for idx, insn in enumerate(insns):
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        if insn.operands[0] != "g14" or insn.operands[1] != "g13":
            continue
        for later in insns[idx + 1 : idx + 20]:
            if later.mnemonic in ("st", "stq") and len(later.operands) == 2:
                return True
            if later.mnemonic == "call":
                break
    return False


def reg_alias(reg: str, profile: FunctionProfile) -> str:
    for bound, name in profile.args:
        if reg == bound:
            return name
    return reg


def apply_macros(doc: SliceDocument, profile: FunctionProfile | None = None) -> list[MacroStmt]:
    insns = doc.insns
    profile = profile or detect_function_profile(insns)
    if profile.kind == FuncKind.LEAF_RET and not profile.args:
        profile.args = [("g0", "arg0"), ("g1", "arg1"), ("g2", "arg2")]

    out: list[MacroStmt] = []
    skip = 0
    last_compare: tuple[str, list[str]] | None = None

    if profile.kind == FuncKind.LEAF_BX and len(insns) >= 2 and profile.link_reg:
        link = profile.link_reg
        out.append(
            MacroStmt(
                kind="assign",
                text=f"{reg_assign(link, 'g14')};",
                addr=insns[0].addr,
                words=list(insns[0].words),
                meta={"leaf_prologue": True, "link_reg": link},
            )
        )
        out.append(
            MacroStmt(
                kind="assign",
                text="g14 = 0;",
                addr=insns[1].addr,
                words=list(insns[1].words),
                meta={"leaf_prologue": True},
            )
        )
        skip = 2

    idx = skip
    while idx < len(insns):
        insn = insns[idx]
        if insn.is_data or insn.mnemonic is None:
            out.append(
                MacroStmt(
                    kind="data",
                    text=f"/* data */ .long {', '.join(f'0x{w:08x}' for w in insn.words)}",
                    addr=insn.addr,
                    words=list(insn.words),
                )
            )
            idx += 1
            continue

        mn = insn.mnemonic
        ops = [_alias_reg(op, profile) for op in insn.operands]

        lowered = _lower_branch(mn, ops, insn, last_compare)
        if lowered is not None:
            out.append(lowered)
            idx += 1
            if mn.startswith("b") and mn not in ("bal", "bbc", "bbs"):
                last_compare = None
            continue

        if mn == "ret":
            if profile.kind == FuncKind.LEAF_BX:
                idx += 1
                continue
            out.append(
                MacroStmt(
                    kind="return",
                    text="return;",
                    addr=insn.addr,
                    words=list(insn.words),
                    meta={"style": "ret"},
                )
            )
            idx += 1
            continue

        if mn == "bx" and len(ops) == 1 and ops[0].startswith("("):
            link = ops[0].strip("()")
            tail = insns[idx + 1 :]
            terminal = not any(
                i.mnemonic not in (None, "?", "ret", "bx") and not i.is_data for i in tail[:8]
            )
            if profile.kind == FuncKind.LEAF_BX and terminal:
                out.append(
                    MacroStmt(
                        kind="return",
                        text="/* leaf bx */",
                        addr=insn.addr,
                        words=list(insn.words),
                        meta={"style": "leaf_bx", "link_reg": link},
                    )
                )
            else:
                out.append(
                    MacroStmt(
                        kind="assign",
                        text=f"i960_call_indirect({link});",
                        addr=insn.addr,
                        words=list(insn.words),
                        meta={"bx_dispatch": True, "link_reg": link},
                    )
                )
            idx += 1
            continue

        if mn in ("call", "callx", "bal") and ops:
            target = ops[0]
            target_addr = int(target, 16) if target.startswith("0x") else None
            out.append(
                MacroStmt(
                    kind="call",
                    text=f"call {target};",
                    addr=insn.addr,
                    words=list(insn.words),
                    meta={"target": target_addr, "target_name": target},
                )
            )
            idx += 1
            last_compare = None
            continue

        if mn in ("cmpi", "cmpo"):
            last_compare = (mn, ops)
            idx += 1
            continue

        if mn in ("cmpr", "cmprl"):
            last_compare = (mn, ops)
            idx += 1
            continue

        if mn == "movq":
            movq = lower_movq_stmts(insn.operands)
            if movq:
                for expr, stmt_meta in movq:
                    out.append(
                        MacroStmt(
                            kind="assign",
                            text=f"{_alias_regs_in_expr(expr, profile)};",
                            addr=insn.addr,
                            words=list(insn.words),
                            meta={"mnemonic": mn, "operands": ops, **stmt_meta},
                        )
                    )
                idx += 1
                continue

        expr, lower_meta = insn_lower(mn, ops)
        if expr:
            expr = _alias_regs_in_expr(expr, profile)
            stmt_meta = {"mnemonic": mn, "operands": ops}
            stmt_meta.update(lower_meta)
            out.append(
                MacroStmt(
                    kind="assign",
                    text=f"{expr};",
                    addr=insn.addr,
                    words=list(insn.words),
                    meta=stmt_meta,
                )
            )
        else:
            asm = f"{mn} {', '.join(ops)}" if ops else mn
            out.append(
                MacroStmt(
                    kind="raw",
                    text=f"/* lift: {asm} @ 0x{insn.addr:x} */",
                    addr=insn.addr,
                    words=list(insn.words),
                    meta={"mnemonic": mn, "operands": ops},
                )
            )

        idx += 1

    return out


def emit_lifted_text(stmts: list[MacroStmt], *, name: str, profile: FunctionProfile, doc: SliceDocument) -> str:
    lines = [
        f"/* lifted from {doc.source} */",
        f"/* @rom 0x{doc.base:x} +0x{doc.length:x} {name} */",
        f"/* kind: {profile.kind.value} */",
        "",
    ]
    if profile.args:
        sig = ", ".join(f"{typ} {nm}" for _, nm in profile.args for typ in ["register"])
        lines.append(f"void {name}({sig});")
        lines.append("")
    for stmt in stmts:
        if stmt.addr is not None:
            lines.append(f"L_{stmt.addr:08x}:")
        lines.append(f"  {stmt.text}")
    return "\n".join(lines) + "\n"


def _alias_reg(token: str, profile: FunctionProfile) -> str:
    return token


def _alias_regs_in_expr(expr: str, profile: FunctionProfile) -> str:
    return expr


def _lower_branch(
    mn: str,
    ops: list[str],
    insn: Insn,
    last_compare: tuple[str, list[str]] | None,
) -> MacroStmt | None:
    if mn.startswith("cmpib") or mn.startswith("cmpob") or mn in ("bbc", "bbs"):
        if len(ops) < 3:
            return None
        imm, reg, target = ops[0], ops[1], ops[2]
        if mn.startswith("cmpob") and is_i960_reg(imm) and is_i960_reg(reg):
            cond = cmpob_reg_cond(mn, imm, reg)
            if cond is None:
                return None
        elif mn == "cmpibge":
            cond = cmpibge_cond(imm, reg)
        elif mn == "cmpibg":
            cond = cmpibg_cond(imm, reg)
        elif mn == "cmpibe":
            cond = cmpibe_cond(imm, reg)
        elif mn == "cmpible":
            cond = cmpible_cond(imm, reg)
        elif mn == "cmpibl":
            cond = cmpibl_cond(imm, reg)
        elif mn == "cmpibne":
            cond = cmpibne_cond(imm, reg)
        elif mn == "cmpobge":
            cond = cmpobge_cond(imm, reg)
        elif mn == "cmpobne":
            cond = cmpobne_cond(imm, reg)
        elif mn == "bbs":
            cond = bbs_cond(imm, reg)
        elif mn == "bbc":
            cond = f"!({bbs_cond(imm, reg)})"
        else:
            return None
        return MacroStmt(
            kind="branch",
            text=f"if ({cond}) goto L_{int(target, 16):08x};",
            addr=insn.addr,
            words=list(insn.words),
            meta={"target": int(target, 16), "fused": True},
        )

    if mn.startswith("b") and mn not in ("bal", "bbc", "bbs") and ops and ops[0].startswith("0x"):
        target = int(ops[0], 16)
        prior_mnemonic, prior_ops = last_compare if last_compare else (None, [])
        cond = ac_branch_cond(mn, prior_mnemonic, prior_ops)
        if cond:
            text = f"if ({cond}) goto L_{target:08x};"
        elif mn == "b":
            text = f"goto L_{target:08x};"
        else:
            text = f"if (/* ac.{mn} */) goto L_{target:08x};"
        return MacroStmt(
            kind="branch",
            text=text,
            addr=insn.addr,
            words=list(insn.words),
            meta={"target": target, "mnemonic": mn},
        )
    return None
