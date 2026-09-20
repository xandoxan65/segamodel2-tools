#!/usr/bin/env python3
"""Text peephole transforms on i960-elf-gcc -S output (tier 3)."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class PeepholeRule:
    name: str
    apply: Callable[[str], tuple[str, bool]]


def _strip_leafproc_wrapper(text: str) -> tuple[str, bool]:
    """Drop .leafproc, lda LR1,g14 prologue, and LR1: ret epilogue."""
    applied = False
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if ".leafproc" in line:
            applied = True
            continue
        if re.fullmatch(r"lda\s+LR1,g14", stripped):
            applied = True
            continue
        if re.fullmatch(r"LR1:\s*ret", stripped):
            applied = True
            continue
        out.append(line)
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + trailing, applied


def _strip_ldob_sign_extend(text: str) -> tuple[str, bool]:
    """Remove shlo/shro 24 after byte load (char compare uses raw byte in ROM)."""
    applied = False
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"shlo\s+24,g\d+,g\d+", stripped) or re.fullmatch(
            r"shro\s+24,g\d+,g\d+", stripped
        ):
            applied = True
            continue
        out.append(line)
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + trailing, applied


def _cmpobe_zero_to_cmpi_be(text: str) -> tuple[str, bool]:
    """cmpobe 0,gN,L → cmpi gN,0 + be L (Model 2 compares)."""
    applied = False
    out: list[str] = []
    pattern = re.compile(r"^(\t)cmpobe\t0,(g\d+),(\w+)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            applied = True
            indent, reg, label = match.groups()
            out.append(f"{indent}cmpi\t{reg},0")
            out.append(f"{indent}be\t{label}")
            continue
        out.append(line)
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + trailing, applied


def _cmpobne_zero_to_cmpibne(text: str) -> tuple[str, bool]:
    """cmpobne 0,gN,L → cmpibne 0,gN,L (byte branch opcode)."""
    applied = False
    out: list[str] = []
    pattern = re.compile(r"^(\t)cmpobne\t0,(g\d+),(\w+)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            applied = True
            indent, reg, label = match.groups()
            out.append(f"{indent}cmpibne\t0,{reg},{label}")
            continue
        out.append(line)
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + trailing, applied


def _promote_g1_src_to_g6(text: str) -> tuple[str, bool]:
    """Use g6 + lda post-increment for src walk (strcpy-style loops)."""
    if "ldob\t(g1)" not in text and "ldob (g1)" not in text:
        return text, False

    applied = False
    has_mov = bool(re.search(r"mov\tg1,g6", text))
    lines = text.splitlines()
    out: list[str] = []
    for line in lines:
        out.append(line)
        if not has_mov and re.fullmatch(r"cmpi\tg0,0", line.strip()):
            out.append("\tmov\tg1,g6")
            has_mov = True
            applied = True

    result_lines: list[str] = []
    for line in out:
        if "(g1)" in line:
            line = line.replace("(g1)", "(g6)")
            applied = True
        result_lines.append(line)

    result = "\n".join(result_lines)
    if "addo\tg1,1,g1" in result:
        result = re.sub(r"\taddo\tg1,1,g1", "\tlda\t0x1(g6),g6", result)
        applied = True
    trailing = "\n" if text.endswith("\n") else ""
    return result + trailing, applied


def _src_null_check_cmpibne_g1(text: str) -> tuple[str, bool]:
    """ldob (g6),g4 / cmp*ne 0,g4,L → cmpibne 0,g1,L (ROM tests *src without load)."""
    pattern = re.compile(
        r"^(\t)ldob\t\(g6\),g\d+\n"
        r"\1cmp(?:i|o)?bne\t0,g\d+,(\w+)\s*\n",
        re.MULTILINE,
    )
    if not pattern.search(text):
        return text, False
    patched, count = pattern.subn(r"\1cmpibne\t0,g1,\2\n", text)
    trailing = "\n" if text.endswith("\n") else ""
    return patched + ("" if patched.endswith("\n") else trailing), count > 0


def _swap_stob_lda_in_loop(text: str) -> tuple[str, bool]:
    """addo g5,1,g5 / stob / lda 0x1(g6),g6 → addo / lda / stob (ROM store order)."""
    pattern = re.compile(
        r"^(\taddo\tg5,1,g5)\n"
        r"\tstob\tg4,\(g5\)\n"
        r"(\tlda\t0x1\(g6\),g6)\n",
        re.MULTILINE,
    )
    if not pattern.search(text):
        return text, False
    patched, count = pattern.subn(r"\1\n\2\n\tstob\tg4,(g5)\n", text)
    trailing = "\n" if text.endswith("\n") else ""
    return patched + ("" if patched.endswith("\n") else trailing), count > 0


def _collapse_blank_lines(text: str) -> tuple[str, bool]:
    lines = text.splitlines()
    out: list[str] = []
    prev_blank = False
    changed = False
    for line in lines:
        blank = not line.strip()
        if blank and prev_blank:
            changed = True
            continue
        out.append(line)
        prev_blank = blank
    trailing = "\n" if text.endswith("\n") else ""
    result = "\n".join(out) + trailing
    return result, changed


DEFAULT_RULES: tuple[PeepholeRule, ...] = (
    PeepholeRule("strip_leafproc_wrapper", _strip_leafproc_wrapper),
    PeepholeRule("strip_ldob_sign_extend", _strip_ldob_sign_extend),
    PeepholeRule("cmpobe_zero_to_cmpi_be", _cmpobe_zero_to_cmpi_be),
    PeepholeRule("cmpobne_zero_to_cmpibne", _cmpobne_zero_to_cmpibne),
    PeepholeRule("promote_g1_src_to_g6", _promote_g1_src_to_g6),
    PeepholeRule("src_null_check_cmpibne_g1", _src_null_check_cmpibne_g1),
    PeepholeRule("swap_stob_lda_in_loop", _swap_stob_lda_in_loop),
    PeepholeRule("collapse_blank_lines", _collapse_blank_lines),
)


def peephole_i960_gas(
    text: str,
    *,
    rules: tuple[PeepholeRule, ...] = DEFAULT_RULES,
) -> tuple[str, list[str]]:
    """Return (transformed asm, names of rules that fired at least once)."""
    applied: list[str] = []
    current = text
    for rule in rules:
        current, fired = rule.apply(current)
        if fired:
            applied.append(rule.name)
    return current, applied


def main() -> None:
    ap = argparse.ArgumentParser(description="Apply tier-3 peephole rules to i960 gas .s")
    ap.add_argument("input", type=Path, help="gcc -S output")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Patched .s (default: stdout)",
    )
    ap.add_argument(
        "--list-rules",
        action="store_true",
        help="Print rule names and exit",
    )
    args = ap.parse_args()

    if args.list_rules:
        for rule in DEFAULT_RULES:
            print(rule.name)
        return

    text = args.input.read_text(encoding="utf-8", errors="replace")
    patched, rules_applied = peephole_i960_gas(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(patched, encoding="utf-8")
    else:
        print(patched, end="")
    if rules_applied:
        print(f"# peephole rules: {', '.join(rules_applied)}", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
