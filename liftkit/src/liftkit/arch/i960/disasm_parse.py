#!/usr/bin/env python3
"""Parse MAME i960dasm listings into structured JSON insn streams."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from liftkit.arch.i960.mame_to_gas960 import (
    ParsedLine,
    branch_target_addresses,
    iter_mame_lines,
)

SLICE_NAME = re.compile(r"maincpu_([0-9a-fA-F]+)_([0-9a-fA-F]+)\.asm$")


@dataclass
class Insn:
    addr: int
    words: list[int]
    mnemonic: str | None
    operands: list[str]
    is_data: bool = False

    @property
    def size(self) -> int:
        return len(self.words) * 4

    def to_json(self) -> dict[str, Any]:
        return {
            "addr": f"0x{self.addr:x}",
            "words": [f"0x{w:08x}" for w in self.words],
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "is_data": self.is_data,
        }

    @classmethod
    def from_parsed(cls, line: ParsedLine) -> Insn:
        ops = _split_operands(line.operands) if line.operands else []
        return cls(
            addr=line.address,
            words=list(line.words),
            mnemonic=line.mnemonic,
            operands=ops,
            is_data=line.is_data,
        )


@dataclass
class SliceDocument:
    source: str
    base: int
    length: int
    insns: list[Insn] = field(default_factory=list)

    @property
    def end(self) -> int:
        if not self.insns:
            return self.base
        last = self.insns[-1]
        return last.addr + last.size

    def branch_targets(self) -> set[int]:
        targets: set[int] = set()
        for insn in self.insns:
            if insn.mnemonic and insn.operands:
                ops = ", ".join(insn.operands)
                for addr in branch_target_addresses(insn.mnemonic, ops):
                    targets.add(addr)
        return targets

    def to_json(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "base": f"0x{self.base:x}",
            "length": self.length,
            "end": f"0x{self.end:x}",
            "insn_count": len(self.insns),
            "insns": [i.to_json() for i in self.insns],
        }


def _split_operands(operands: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in operands:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_slice_name(path: Path) -> tuple[int, int] | None:
    match = SLICE_NAME.match(path.name)
    if not match:
        return None
    return int(match.group(1), 16), int(match.group(2), 16)


def parse_slice_text(text: str, *, source: str = "", base: int | None = None) -> SliceDocument:
    insns = [Insn.from_parsed(line) for line in iter_mame_lines(text)]
    if not insns:
        raise ValueError("no MAME disasm lines parsed")
    slice_base = base if base is not None else insns[0].addr
    parsed = parse_slice_name(Path(source)) if source else None
    length = parsed[1] if parsed else (insns[-1].addr + insns[-1].size - slice_base)
    return SliceDocument(source=source, base=slice_base, length=length, insns=insns)


def parse_slice_file(path: Path, *, base: int | None = None) -> SliceDocument:
    text = path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_slice_name(path)
    slice_base = base
    if slice_base is None and parsed is not None:
        slice_base = parsed[0]
    return parse_slice_text(text, source=path.as_posix(), base=slice_base)


def iter_slice_insns(path: Path) -> Iterator[Insn]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in iter_mame_lines(text):
        yield Insn.from_parsed(line)


def write_slice_json(doc: SliceDocument, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc.to_json(), indent=2) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse MAME i960 disasm slice to JSON")
    ap.add_argument("input", type=Path, help="MAME .asm slice")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output .json path")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None, help="Slice base address")
    args = ap.parse_args()
    doc = parse_slice_file(args.input, base=args.base)
    write_slice_json(doc, args.output)
    print(
        f"Wrote {args.output} ({len(doc.insns)} insns, "
        f"base 0x{doc.base:x} len 0x{doc.length:x})"
    )


if __name__ == "__main__":
    main()
