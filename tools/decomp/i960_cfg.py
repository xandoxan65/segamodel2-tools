"""CFG analysis and structured control-flow detection for i960-ML IR."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Union

from tools.decomp.i960_ir import IrBlock, IrFunction, IrStmt, StmtKind

_BRANCH_COND = re.compile(r"if\s*\((.+)\)\s*goto\s+L_([0-9a-fA-F]+)\s*;")


@dataclass
class IfThenRegion:
    """if (cond) { then } — branch skips then-body when false (fallthrough is then)."""

    branch_addr: int
    condition: str
    invert: bool
    then_addrs: list[int]
    join_addr: int

    def to_json(self) -> dict:
        return {
            "kind": "if_then",
            "branch_addr": f"0x{self.branch_addr:x}",
            "condition": self.condition,
            "invert": self.invert,
            "then_addrs": [f"0x{a:x}" for a in self.then_addrs],
            "join_addr": f"0x{self.join_addr:x}",
        }


@dataclass
class IfElseRegion:
    """if (cond) { then } else { else } — diamond with merge point."""

    branch_addr: int
    condition: str
    then_addrs: list[int]
    else_addrs: list[int]
    join_addr: int | None

    def to_json(self) -> dict:
        return {
            "kind": "if_else",
            "branch_addr": f"0x{self.branch_addr:x}",
            "condition": self.condition,
            "then_addrs": [f"0x{a:x}" for a in self.then_addrs],
            "else_addrs": [f"0x{a:x}" for a in self.else_addrs],
            "join_addr": f"0x{self.join_addr:x}" if self.join_addr is not None else None,
        }


@dataclass
class WhileRegion:
    """do { body } while (cond) — backward branch at tail jumps to head."""

    head_addr: int
    tail_addr: int
    condition: str
    body_addrs: list[int]
    post_test: bool = True

    def to_json(self) -> dict:
        return {
            "kind": "do_while" if self.post_test else "while",
            "head_addr": f"0x{self.head_addr:x}",
            "tail_addr": f"0x{self.tail_addr:x}",
            "condition": self.condition,
            "body_addrs": [f"0x{a:x}" for a in self.body_addrs],
            "post_test": self.post_test,
        }


StructuredRegion = Union[IfThenRegion, IfElseRegion, WhileRegion]


def regions_to_json(regions: list[StructuredRegion]) -> list[dict]:
    return [r.to_json() for r in regions]


@dataclass
class CfgGraph:
    blocks: list[int]
    edges: list[CfgEdge] = field(default_factory=list)
    block_map: dict[int, IrBlock] = field(default_factory=dict)

    def succs(self, addr: int) -> list[tuple[int, str]]:
        return [(e.dst, e.kind) for e in self.edges if e.src == addr]

    def fallthrough(self, addr: int) -> int | None:
        for dst, kind in self.succs(addr):
            if kind == "fallthrough":
                return dst
        return None

    def preds(self, addr: int) -> list[int]:
        return [e.src for e in self.edges if e.dst == addr]


@dataclass
class CfgEdge:
    src: int
    dst: int
    kind: Literal["fallthrough", "branch", "unconditional"]


def build_cfg(fn: IrFunction) -> CfgGraph:
    ordered = sorted(fn.blocks, key=lambda b: b.addr)
    addrs = [b.addr for b in ordered]
    block_map = {b.addr: b for b in ordered}
    edges: list[CfgEdge] = []

    for i, block in enumerate(ordered):
        term = _terminator(block)
        if term == "return" or term == "call":
            continue
        if term == "branch":
            branch = _branch_stmt(block)
            assert branch is not None
            target = branch.target
            if target is not None and target in block_map:
                edges.append(CfgEdge(block.addr, target, "branch"))
            if i + 1 < len(ordered):
                edges.append(CfgEdge(block.addr, ordered[i + 1].addr, "fallthrough"))
        elif i + 1 < len(ordered):
            edges.append(CfgEdge(block.addr, ordered[i + 1].addr, "fallthrough"))

    return CfgGraph(blocks=addrs, edges=edges, block_map=block_map)


def find_structured_regions(fn: IrFunction) -> list[StructuredRegion]:
    cfg = build_cfg(fn)
    regions: list[StructuredRegion] = []
    consumed: set[int] = set()

    for addr in cfg.blocks:
        if addr in consumed:
            continue
        block = cfg.block_map.get(addr)
        if block is None or _terminator(block) != "branch":
            continue
        branch = _branch_stmt(block)
        if branch is None or branch.target is None:
            continue
        cond = _parse_branch_cond(branch.text)
        if cond is None:
            continue

        else_addr = branch.target
        then_start = cfg.fallthrough(addr)
        if then_start is None:
            continue

        while_loop = _try_while_loop(cfg, addr, cond, else_addr)
        if while_loop is not None:
            regions.append(while_loop)
            consumed.add(while_loop.tail_addr)
            consumed.update(while_loop.body_addrs)
            consumed.add(while_loop.head_addr)
            continue

        if else_addr <= addr:
            continue

        if_then = _try_if_then(cfg, addr, cond, then_start, else_addr)
        if if_then is not None:
            regions.append(if_then)
            consumed.add(addr)
            consumed.update(if_then.then_addrs)
            continue

        if_else = _try_if_else(cfg, addr, cond, then_start, else_addr)
        if if_else is not None:
            regions.append(if_else)
            consumed.add(addr)
            consumed.update(if_else.then_addrs)
            consumed.update(if_else.else_addrs)
            continue

        early = _try_if_else_early_exit(cfg, addr, cond, then_start, else_addr)
        if early is not None:
            regions.append(early)
            consumed.add(addr)
            consumed.update(early.then_addrs)
            consumed.update(early.else_addrs)

    return regions


def _try_while_loop(
    cfg: CfgGraph,
    tail_addr: int,
    condition: str,
    target: int,
) -> WhileRegion | None:
    """Backward branch at tail: if (cond) goto head; body is head..tail (exclusive)."""
    if target >= tail_addr:
        return None
    head = target
    if head not in cfg.block_map or tail_addr not in cfg.block_map:
        return None

    body: list[int] = []
    cur = head
    seen: set[int] = set()
    while cur not in seen and cur != tail_addr:
        seen.add(cur)
        body.append(cur)
        block = cfg.block_map.get(cur)
        if block is None or _terminator(block) != "fall":
            return None
        nxt = cfg.fallthrough(cur)
        if nxt is None:
            return None
        cur = nxt

    if cur != tail_addr:
        return None
    if not body or not _has_executable_stmts(cfg, body):
        return None

    return WhileRegion(
        head_addr=head,
        tail_addr=tail_addr,
        condition=condition,
        body_addrs=body,
    )


def _try_if_then(
    cfg: CfgGraph,
    branch_addr: int,
    condition: str,
    then_start: int,
    join_addr: int,
) -> IfThenRegion | None:
    if then_start == join_addr:
        return None
    then_chain = _linear_chain(cfg, then_start, join_addr)
    if not then_chain:
        return None
    then_body = [a for a in then_chain if a != join_addr]
    if not then_body:
        return None
    # Stop before a block that is also entered from outside the if
    # (e.g. early `goto` merge into the middle of the fallthrough chain).
    # If the then-entry itself has an external predecessor (loop header),
    # this is not a pure if-then.
    trimmed: list[int] = []
    for addr in then_body:
        allowed_preds = {branch_addr} | set(trimmed)
        external = [p for p in cfg.preds(addr) if p not in allowed_preds]
        if external:
            if not trimmed:
                return None
            join_addr = addr
            break
        trimmed.append(addr)
    then_body = trimmed
    if not then_body:
        return None
    last = then_body[-1]
    block = cfg.block_map.get(last)
    if block is None:
        return None
    if _terminator(block) != "fall":
        return None
    if cfg.fallthrough(last) != join_addr:
        return None
    if not _has_executable_stmts(cfg, then_body):
        return None
    return IfThenRegion(
        branch_addr=branch_addr,
        condition=condition,
        invert=True,
        then_addrs=then_body,
        join_addr=join_addr,
    )


def _has_executable_stmts(cfg: CfgGraph, addrs: list[int]) -> bool:
    for addr in addrs:
        block = cfg.block_map.get(addr)
        if block is None:
            continue
        for stmt in block.stmts:
            if stmt.kind in (StmtKind.ASSIGN, StmtKind.MACRO, StmtKind.CALL, StmtKind.RETURN):
                return True
    return False


def _try_if_else(
    cfg: CfgGraph,
    branch_addr: int,
    condition: str,
    then_start: int,
    else_start: int,
) -> IfElseRegion | None:
    if then_start == else_start:
        return None
    if _has_internal_branch(cfg, then_start, else_start):
        return None
    if _has_internal_branch(cfg, else_start, None):
        return None

    then_chain = _collect_until_stop(cfg, then_start, stop={else_start}, max_blocks=12)
    else_chain = _collect_until_stop(cfg, else_start, stop=set(), max_blocks=12)

    then_end = then_chain[-1] if then_chain else then_start
    else_end = else_chain[-1] if else_chain else else_start

    merge = _find_merge(cfg, then_end, else_end, else_start)
    if merge is None:
        if _terminator(cfg.block_map.get(then_end, IrBlock(then_end))) == "return":
            return None
        return None

    then_addrs = [a for a in then_chain if a != merge]
    else_addrs = [a for a in else_chain if a != merge]

    if not then_addrs and not else_addrs:
        return None

    return IfElseRegion(
        branch_addr=branch_addr,
        condition=condition,
        then_addrs=then_addrs,
        else_addrs=else_addrs,
        join_addr=merge,
    )


def _try_if_else_early_exit(
    cfg: CfgGraph,
    branch_addr: int,
    condition: str,
    then_start: int,
    else_start: int,
) -> IfElseRegion | None:
    if then_start == else_start:
        return None
    then_chain = _collect_until_stop(cfg, then_start, stop={else_start}, max_blocks=8)
    if not then_chain:
        return None
    last = then_chain[-1]
    block = cfg.block_map.get(last)
    if block is None or _terminator(block) != "return":
        return None
    if _has_internal_branch(cfg, then_start, else_start):
        return None
    else_block = cfg.block_map.get(else_start)
    if else_block is None:
        return None
    if _terminator(else_block) != "return" and cfg.fallthrough(else_start) is not None:
        return None
    return IfElseRegion(
        branch_addr=branch_addr,
        condition=condition,
        then_addrs=then_chain,
        else_addrs=[else_start],
        join_addr=None,
    )


def _terminator(block: IrBlock) -> str:
    for stmt in reversed(block.stmts):
        if stmt.kind == StmtKind.LABEL:
            continue
        if stmt.kind == StmtKind.RETURN:
            return "return"
        if stmt.kind == StmtKind.CALL:
            return "call"
        if stmt.kind == StmtKind.BRANCH:
            return "branch"
        return "fall"
    return "fall"


def _branch_stmt(block: IrBlock) -> IrStmt | None:
    for stmt in reversed(block.stmts):
        if stmt.kind == StmtKind.BRANCH:
            return stmt
    return None


def _parse_branch_cond(text: str) -> str | None:
    match = _BRANCH_COND.match(text.strip())
    if match:
        return match.group(1).strip()
    return None


def _linear_chain(cfg: CfgGraph, start: int, join: int) -> list[int]:
    chain: list[int] = []
    cur = start
    seen: set[int] = set()
    while cur not in seen and len(chain) < 16:
        seen.add(cur)
        chain.append(cur)
        if cur == join:
            break
        block = cfg.block_map.get(cur)
        if block is None or _terminator(block) != "fall":
            break
        nxt = cfg.fallthrough(cur)
        if nxt is None:
            break
        cur = nxt
    return chain


def _reachable_from(cfg: CfgGraph, start: int, *, limit: int) -> set[int]:
    seen: set[int] = set()
    stack = [start]
    while stack and len(seen) < limit:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for dst, _ in cfg.succs(cur):
            stack.append(dst)
    return seen


def _has_internal_branch(cfg: CfgGraph, start: int, stop: int | None) -> bool:
    chain = _linear_chain(cfg, start, stop if stop else start + 0x1000)
    for addr in chain:
        if stop and addr == stop:
            break
        block = cfg.block_map.get(addr)
        if block and _terminator(block) == "branch":
            return True
    return False


def _collect_until_stop(
    cfg: CfgGraph,
    start: int,
    *,
    stop: set[int],
    max_blocks: int,
) -> list[int]:
    out: list[int] = []
    cur = start
    seen: set[int] = set()
    while cur not in seen and len(out) < max_blocks:
        if cur in stop:
            break
        seen.add(cur)
        out.append(cur)
        block = cfg.block_map.get(cur)
        if block is None:
            break
        term = _terminator(block)
        if term == "return":
            break
        if term == "branch":
            branch = _branch_stmt(block)
            if branch and branch.target is not None:
                ft = cfg.fallthrough(cur)
                if ft is not None and branch.target > cur:
                    break
            break
        nxt = cfg.fallthrough(cur)
        if nxt is None:
            break
        cur = nxt
    return out


def _find_merge(cfg: CfgGraph, then_end: int, else_end: int, else_start: int) -> int | None:
    then_reach = _reachable_from(cfg, then_end, limit=20)
    else_reach = _reachable_from(cfg, else_end, limit=20)
    common = (then_reach & else_reach) - {then_end, else_end}
    if not common:
        then_ft = cfg.fallthrough(then_end)
        if then_ft is not None and then_ft in else_reach:
            return then_ft
        if cfg.fallthrough(else_end) == then_ft and then_ft is not None:
            return then_ft
        return None
    return min(common)
