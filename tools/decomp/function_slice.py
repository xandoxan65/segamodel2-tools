#!/usr/bin/env python3
"""Resolve functions.yaml names to tight maincpu disasm slices for Ghidra/reasm."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from tools.decomp.disasm_paths import DECOMP_DISASM, MAINCPU_SUBDIR
from tools.decomp.export_symbols import load_functions_yaml
from tools.decomp.mame_to_gas960 import iter_mame_lines
from tools.decomp.symbol_kind import lookup_symbol_kind
from tools.decomp.workspace import DECOMP_ROOT, resolve_in_repo

SLICE_NAME = re.compile(r"^maincpu_([0-9a-f]+)_([0-9a-f]+)\.asm$", re.I)
CALL_MNEMONICS = frozenset({"call", "callx", "calls", "callj", "bal"})
DEFAULT_FUNCTIONS_YAML = DECOMP_ROOT / "symbols/functions.yaml"
LIFT_SLICES = DECOMP_ROOT / "out" / "lift" / "slices"
MAME_LINE = re.compile(r"^([0-9A-Fa-f]{8}):\s+(.*)$")


@dataclass(frozen=True)
class FunctionSlicePlan:
    name: str
    address: int
    length: int
    slice_path: Path
    source: str  # disasm | extracted | generated
    note: str


def parse_address(value: int | str) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def lookup_function(name: str, *, functions_yaml: Path | None = None) -> dict:
    path = resolve_in_repo(functions_yaml or DEFAULT_FUNCTIONS_YAML)
    rows = load_functions_yaml(path)
    matches = [row for row in rows if str(row.get("name", "")) == name]
    if not matches:
        known = ", ".join(sorted(str(r.get("name", "")) for r in rows if r.get("name")))
        raise KeyError(f"unknown function {name!r} in {path} (known: {known})")
    if len(matches) > 1:
        raise KeyError(f"ambiguous function name {name!r}: {len(matches)} entries in {path}")
    return matches[0]


def iter_maincpu_slices(disasm_root: Path | None = None) -> list[tuple[Path, int, int]]:
    root = resolve_in_repo(disasm_root or DECOMP_DISASM / MAINCPU_SUBDIR)
    rows: list[tuple[Path, int, int]] = []
    if not root.is_dir():
        return rows
    for path in sorted(root.glob("maincpu_*.asm")):
        match = SLICE_NAME.match(path.name)
        if not match:
            continue
        start = int(match.group(1), 16)
        length = int(match.group(2), 16)
        rows.append((path, start, length))
    return rows


def infer_rodata_length(mame_text: str, entry: int, *, max_length: int) -> int:
    """Bytes of contiguous data words from entry until the first real instruction."""
    end = entry
    for line in iter_mame_lines(mame_text):
        if line.address < entry:
            continue
        if line.address >= entry + max_length:
            break
        if line.is_data:
            end = max(end, line.address + line.size)
            continue
        if line.mnemonic is not None:
            break
    span = end - entry
    return min(max(span, 4), max_length)


def infer_function_length(mame_text: str, entry: int, *, max_length: int) -> int:
    """Bytes from entry to first top-level ret (call-balanced), capped by max_length."""
    depth = 0
    started = False
    for line in iter_mame_lines(mame_text):
        if line.address < entry:
            continue
        if line.address >= entry + max_length:
            break
        if not started:
            if line.address != entry:
                continue
            started = True
        if line.is_data:
            continue
        assert line.mnemonic is not None
        mnemonic = line.mnemonic.lower()
        if mnemonic in CALL_MNEMONICS:
            depth += 1
            continue
        if mnemonic == "ret":
            if depth <= 1:
                end = line.address + line.size
                span = end - entry
                return min(max(span, 4), max_length)
            depth -= 1
    return max_length


def _align_length(length: int, *, align: int = 0x10) -> int:
    if length <= 0:
        return align
    return ((length + align - 1) // align) * align


def extract_mame_slice_lines(mame_text: str, start: int, length: int) -> str:
    end = start + length
    out: list[str] = []
    for raw in mame_text.splitlines():
        match = MAME_LINE.match(raw.strip())
        if not match:
            continue
        addr = int(match.group(1), 16)
        if start <= addr < end:
            out.append(raw.rstrip())
    if not out:
        raise ValueError(f"no MAME lines in 0x{start:x}+0x{length:x}")
    return "\n".join(out) + "\n"


def pick_containing_slice(address: int, slices: list[tuple[Path, int, int]]) -> tuple[Path, int, int] | None:
    containing = [
        (path, start, length)
        for path, start, length in slices
        if start <= address < start + length
    ]
    if not containing:
        return None
    at_entry = [row for row in containing if row[1] == address]
    pool = at_entry if at_entry else containing
    return min(pool, key=lambda row: row[2])


def plan_function_slice(
    name: str,
    *,
    functions_yaml: Path | None = None,
    disasm_root: Path | None = None,
    lift_slices_dir: Path | None = None,
) -> FunctionSlicePlan:
    row = lookup_function(name, functions_yaml=functions_yaml)
    address = parse_address(row["address"])
    symbol_kind = lookup_symbol_kind(name, address, functions_yaml=functions_yaml, row=row)
    slices = iter_maincpu_slices(disasm_root)
    picked = pick_containing_slice(address, slices)
    if picked is None:
        raise FileNotFoundError(
            f"no disasm/maincpu slice contains {name} @ 0x{address:x} — "
            f"run: python3 -m tools.disasm.mame_dasm --address 0x{address:x} --length <len>"
        )

    source_path, source_start, source_length = picked
    source_text = source_path.read_text(encoding="utf-8", errors="replace")
    max_span = source_start + source_length - address

    if symbol_kind == "rodata":
        if "length" in row:
            length = _align_length(parse_address(row["length"]), align=4)
        else:
            length = _align_length(
                infer_rodata_length(source_text, address, max_length=max_span),
                align=4,
            )
        note = f"rodata block 0x{length:x} B"
    else:
        raw_len = infer_function_length(source_text, address, max_length=max_span)
        length = _align_length(raw_len)
        note = None

    at_entry = source_start == address
    if symbol_kind != "rodata":
        tight_ok = (
            at_entry
            and raw_len >= 0x30
            and raw_len <= source_length
            and raw_len <= (source_length * 3) // 4
            and raw_len >= max(0x30, source_length // 20)
        )
        if tight_ok:
            length = _align_length(raw_len)
        elif at_entry and raw_len < max(0x30, source_length // 20):
            return FunctionSlicePlan(
                name=name,
                address=address,
                length=source_length,
                slice_path=source_path,
                source="disasm",
                note=(
                    f"full slice {source_path.name} "
                    f"(inferred 0x{raw_len:x} unreliable for this symbol)"
                ),
            )
        elif at_entry and raw_len >= source_length:
            length = source_length

    exact = source_path if source_start == address and source_length == length else None
    if exact is not None:
        return FunctionSlicePlan(
            name=name,
            address=address,
            length=length,
            slice_path=exact,
            source="disasm",
            note=note or f"exact disasm slice ({source_path.name})",
        )

    # Prefer an existing on-disk slice with same start+length (any path).
    for path, start, span in slices:
        if start == address and span == length:
            rel = path.relative_to(DECOMP_ROOT) if path.is_relative_to(DECOMP_ROOT) else path
            return FunctionSlicePlan(
                name=name,
                address=address,
                length=length,
                slice_path=path,
                source="disasm",
                note=note or f"matched slice {rel} (inferred 0x{length:x} bytes)",
            )

    out_dir = resolve_in_repo(lift_slices_dir or LIFT_SLICES)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"maincpu_{address:08x}_{length:x}.asm"
    out_path.write_text(extract_mame_slice_lines(source_text, address, length), encoding="utf-8")
    extract_note = (
        f"extracted 0x{length:x} B from {source_path.relative_to(DECOMP_ROOT)} "
        f"(was 0x{source_length:x} B)"
        if source_path.is_relative_to(DECOMP_ROOT)
        else f"extracted 0x{length:x} B from {source_path.name}"
    )
    return FunctionSlicePlan(
        name=name,
        address=address,
        length=length,
        slice_path=out_path,
        source="extracted",
        note=note or extract_note,
    )
