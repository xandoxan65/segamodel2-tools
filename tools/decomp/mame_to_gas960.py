#!/usr/bin/env python3
"""Translate MAME i960dasm listings to gas960 assembly."""

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Set, Union

MAME_LINE = re.compile(r"^([0-9A-Fa-f]{8}):\s+(.*)$")
HEX_WORD = re.compile(r"^[0-9A-Fa-f]{8}$")
HEX_LIT = re.compile(r"^0x[0-9a-fA-F]+$")
SF_REG = re.compile(r"\bsf\d+\b", re.IGNORECASE)
FLOAT_LIT = re.compile(r"[+-]?\d+\.\d")
GAS_UNSUPPORTED_PREFIXES = ("condwait", "sendserv", "alterbit")
GAS_UNSUPPORTED_EXACT = frozenset({"send", "fmark", "modify", "sinr"})
GAS_RAW_MNEMONICS = frozenset(
    {"ldob", "stob", "ldib", "stib", "ldos", "stl", "spanbit", "faulte", "ret", "flushreg"}
)


@dataclass(frozen=True)
class ParsedLine:
    address: int
    words: tuple[int, ...]
    mnemonic: Optional[str]
    operands: Optional[str]

    @property
    def is_data(self) -> bool:
        return self.mnemonic is None

    @property
    def size(self) -> int:
        return len(self.words) * 4


def label_name(address: int) -> str:
    return f"L_{address:08x}"


def parse_hex_token(token: str) -> Optional[int]:
    token = token.strip()
    if HEX_LIT.match(token):
        return int(token, 16)
    return None


def operand_parts(operands: str) -> List[str]:
    return [part.strip() for part in operands.split(",") if part.strip()]


def branch_target_addresses(mnemonic: str, operands: str) -> List[int]:
    """Return absolute branch/call targets encoded in operands."""
    if not operands:
        return []
    parts = operand_parts(operands)
    if not parts:
        return []

    if mnemonic in ("cmpi", "cmpo"):
        return []

    if mnemonic.startswith("cmp"):
        addr = parse_hex_token(parts[-1])
        return [addr] if addr is not None else []

    if mnemonic in ("call", "callx", "calls", "callj", "bal"):
        addr = parse_hex_token(parts[0])
        return [addr] if addr is not None else []

    if mnemonic.startswith("b"):
        if mnemonic in ("bbc", "bbs"):
            addr = parse_hex_token(parts[-1])
            return [addr] if addr is not None else []
        addr = parse_hex_token(parts[0])
        return [addr] if addr is not None else []

    return []


def rewrite_branch_operands(mnemonic: str, operands: str) -> str:
    parts = operand_parts(operands)
    if not parts:
        return operands

    targets = branch_target_addresses(mnemonic, operands)
    if not targets:
        return operands

    if mnemonic.startswith("cmp") or mnemonic in ("bbc", "bbs"):
        addr = parse_hex_token(parts[-1])
        if addr is not None:
            parts[-1] = label_name(addr)
    else:
        addr = parse_hex_token(parts[0])
        if addr is not None:
            parts[0] = label_name(addr)

    return ", ".join(parts)


def use_raw_words(line: ParsedLine, *, slice_addrs: Optional[Set[int]] = None) -> bool:
    """Emit MAME hex words when gas960 syntax is unreliable on i960-KB."""
    if line.is_data:
        return True
    assert line.mnemonic is not None
    assert line.operands is not None
    mnemonic = line.mnemonic
    operands = line.operands
    if SF_REG.search(operands) or SF_REG.search(mnemonic):
        return True
    if FLOAT_LIT.search(operands):
        return True
    if "?" in operands:
        return True
    if mnemonic.startswith(GAS_UNSUPPORTED_PREFIXES) or mnemonic in GAS_UNSUPPORTED_EXACT:
        return True
    if mnemonic in GAS_RAW_MNEMONICS:
        return True
    if mnemonic.startswith("call") or mnemonic == "bal":
        return True
    if mnemonic.startswith("fault") or mnemonic.startswith("flush"):
        return True
    if mnemonic.startswith("test"):
        return True
    if mnemonic.startswith("cmp") and mnemonic not in ("cmpi", "cmpo"):
        return True
    if len(line.words) > 1:
        return True
    if slice_addrs is not None:
        targets = branch_target_addresses(mnemonic, operands)
        for addr in targets:
            if addr not in slice_addrs or addr == line.address:
                return True
    return False


def parse_mame_line(line: str) -> Optional[ParsedLine]:
    line = line.strip()
    if not line or line.startswith(";"):
        return None
    match = MAME_LINE.match(line)
    if not match:
        return None

    address = int(match.group(1), 16)
    tokens = match.group(2).split()
    hex_tokens: list[str] = []
    while tokens and HEX_WORD.match(tokens[0]):
        hex_tokens.append(tokens.pop(0))

    if not hex_tokens:
        return None

    words = tuple(int(token, 16) for token in hex_tokens)

    if tokens and tokens[0] == "?":
        return ParsedLine(address, words, None, None)

    if not tokens:
        if len(words) == 1:
            return ParsedLine(address, words, None, None)
        return None

    mnemonic = tokens[0].lower()
    operands = " ".join(tokens[1:])
    return ParsedLine(address, words, mnemonic, operands)


def iter_mame_lines(text: str) -> Iterator[ParsedLine]:
    for line in text.splitlines():
        parsed = parse_mame_line(line)
        if parsed is not None:
            yield parsed


def reference_bytes_from_mame(
    text: str,
    *,
    slice_base: int,
    length: int,
) -> bytes:
    """Build expected ROM bytes from a MAME listing (gaps filled with zero)."""
    buf = bytearray(length)
    for entry in iter_mame_lines(text):
        offset = entry.address - slice_base
        if offset < 0 or offset + entry.size > length:
            continue
        for index, word in enumerate(entry.words):
            struct.pack_into("<I", buf, offset + index * 4, word)
    return bytes(buf)


def emit_long_words(words: Sequence[int]) -> List[str]:
    return [f"\t.long 0x{word:08x}" for word in words]


def emit_gas_instruction(line: ParsedLine) -> List[str]:
    assert line.mnemonic is not None
    operands = rewrite_branch_operands(line.mnemonic, line.operands or "")
    if operands:
        return [f"\t{line.mnemonic}\t{operands}"]
    return [f"\t{line.mnemonic}"]


def emit_line_body(
    line: ParsedLine,
    *,
    emit_mode: str = "gas",
    slice_addrs: Optional[Set[int]] = None,
) -> List[str]:
    if emit_mode == "bytes" or use_raw_words(line, slice_addrs=slice_addrs):
        return emit_long_words(line.words)
    return emit_gas_instruction(line)


def fill_gap_lines(
    out: List[str],
    *,
    gap_start: int,
    gap_end: int,
    rom_slice: bytes,
    slice_base: int,
) -> None:
    for addr in range(gap_start, gap_end, 4):
        offset = addr - slice_base
        word = int.from_bytes(rom_slice[offset : offset + 4], "little")
        out.append(f"\t.org 0x{addr:x}")
        out.append(f"\t.long 0x{word:08x}")


def translate_mame_asm(
    text: str,
    *,
    base_address: Optional[int] = None,
    section: str = ".text",
    rom_slice: Optional[bytes] = None,
    slice_base: Optional[int] = None,
    emit_mode: str = "gas",
) -> tuple[str, dict[str, int]]:
    entries = list(iter_mame_lines(text))
    if not entries:
        raise ValueError("no MAME disasm lines parsed")

    slice_start = slice_base if slice_base is not None else (
        base_address if base_address is not None else entries[0].address
    )

    slice_addrs: Set[int] = {entry.address for entry in entries}
    branch_targets: Set[int] = set()
    for entry in entries:
        if entry.mnemonic:
            for addr in branch_target_addresses(entry.mnemonic, entry.operands or ""):
                branch_targets.add(addr)

    external_targets = sorted(branch_targets - slice_addrs)

    out: List[str] = [f"\t{section}", "\t.align 4", f"\t.org 0x{slice_start:x}"]
    cursor = slice_start

    for entry in entries:
        if entry.address > cursor:
            if rom_slice is not None:
                fill_gap_lines(
                    out,
                    gap_start=cursor,
                    gap_end=entry.address,
                    rom_slice=rom_slice,
                    slice_base=slice_start,
                )
            else:
                out.append(f"\t.org 0x{entry.address:x}")

        out.append(f"{label_name(entry.address)}:")
        out.extend(emit_line_body(entry, emit_mode=emit_mode, slice_addrs=slice_addrs))
        cursor = entry.address + entry.size

    if rom_slice is not None:
        slice_end = slice_start + len(rom_slice)
        if cursor < slice_end:
            fill_gap_lines(
                out,
                gap_start=cursor,
                gap_end=slice_end,
                rom_slice=rom_slice,
                slice_base=slice_start,
            )

    for addr in external_targets:
        out.append(f".set {label_name(addr)}, 0x{addr:x}")

    stats = {
        "lines_in": len(text.splitlines()),
        "lines_out": len(entries),
        "slice_base": slice_start,
        "slice_end": entries[-1].address + entries[-1].size,
        "data_lines": sum(1 for e in entries if e.is_data),
        "insn_lines": sum(1 for e in entries if not e.is_data),
        "raw_word_lines": sum(1 for e in entries if use_raw_words(e, slice_addrs=slice_addrs)),
        "branch_targets": len(branch_targets),
        "external_targets": len(external_targets),
        "emit_mode": emit_mode,
    }
    return "\n".join(out) + "\n", stats


def translate_file(
    in_path: Path,
    out_path: Path,
    *,
    base_address: Optional[int] = None,
    rom_slice: Optional[bytes] = None,
    slice_base: Optional[int] = None,
    emit_mode: str = "gas",
) -> dict[str, int]:
    text = in_path.read_text(encoding="utf-8", errors="replace")
    gas, stats = translate_mame_asm(
        text,
        base_address=base_address,
        rom_slice=rom_slice,
        slice_base=slice_base,
        emit_mode=emit_mode,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(gas, encoding="utf-8")
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Convert MAME i960dasm listing to gas960")
    ap.add_argument("input", type=Path, help="MAME .asm slice")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output .s path")
    ap.add_argument(
        "--mode",
        choices=("gas", "bytes"),
        default="gas",
        help="gas: mnemonic output where possible; bytes: MAME hex words only",
    )
    ap.add_argument(
        "--base",
        type=lambda s: int(s, 0),
        default=None,
        help="Slice base address (default: first line address)",
    )
    args = ap.parse_args()
    stats = translate_file(args.input, args.output, base_address=args.base, emit_mode=args.mode)
    print(
        f"Wrote {args.output} ({stats['insn_lines']} insns, "
        f"{stats['data_lines']} data, {stats['raw_word_lines']} raw, "
        f"{stats['external_targets']} external labels, base 0x{stats['slice_base']:x})"
    )


if __name__ == "__main__":
    main()
