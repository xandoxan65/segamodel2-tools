"""Shared IR sketch — arch backends currently use their own IR; this is the target shape."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OpKind(str, Enum):
    ASSIGN = "assign"
    LOAD = "load"
    STORE = "store"
    CALL = "call"
    RETURN = "return"
    BRANCH = "branch"
    CBRANCH = "cbranch"
    LABEL = "label"
    COMMENT = "comment"


@dataclass
class IrOp:
    kind: OpKind
    dest: str | None = None
    args: list[str] = field(default_factory=list)
    addr: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class IrFunctionSketch:
    """Arch-neutral IR sketch for future shared CFG/emit."""

    name: str
    arch: str
    entry: int
    ops: list[IrOp] = field(default_factory=list)
