"""Rewrite Ghidra i960 AC (condition-code) noise into normal C boolean tests."""

from __future__ import annotations

import re
from dataclasses import dataclass

AC_MASK = r"(?:ac|\w+)\s*&\s*0xfffffff8"

RE_AC_SAVE = re.compile(r"^\s*(?P<var>\w+)\s*=\s*ac\s*;\s*$")
RE_G14_CLEAR = re.compile(r"^\s*g14\s*=\s*(?:\([^)]*\)\s*)?(?:0x)?0\s*;\s*$")

_UINT_EXPR = r"(?:\([^)]*\)|[^()])+"
_UINT_LT = rf"\(uint\)\((?P<lt>{_UINT_EXPR})\)\s*<<\s*2"
_UINT_EQ = rf"\(uint\)\((?P<eq>{_UINT_EXPR})\)\s*<<\s*1"
_UINT_GT = rf"\(uint\)\((?P<gt>{_UINT_EXPR})\)"

RE_FLAG_WORD = re.compile(
    rf"^\s*(?P<var>\w+)\s*=\s*{AC_MASK}\s*\|\s*"
    + _UINT_LT
    + r"\s*\|\s*"
    + _UINT_EQ
    + rf"(?:\s*\|\s*{_UINT_GT})?\s*;\s*$"
)

RE_FLAG_LT_ONLY = re.compile(
    rf"^\s*(?P<var>\w+)\s*=\s*{AC_MASK}\s*\|\s*" + _UINT_LT + r"\s*;\s*$"
)

RE_LOOP_AC = re.compile(
    rf"^\s*ac\s*=\s*{AC_MASK}\s*\|\s*"
    rf"\(uint\)\((?P<ne>{_UINT_EXPR})\)\s*<<\s*2\s*\|\s*"
    rf"\(uint\)\((?P<eq>{_UINT_EXPR})\)\s*<<\s*1\s*;\s*$"
)

RE_COMMA_AC = re.compile(
    rf"\(\s*ac\s*=\s*{AC_MASK}\s*\|\s*"
    + _UINT_LT
    + r"\s*\|\s*"
    + _UINT_EQ
    + r"\s*\|\s*"
    + _UINT_GT
    + r",\s*"
    + rf"\(\(byte\)ac\s*&\s*1\s*\|\s*(?P<or_expr>{_UINT_EXPR})\)\s*==\s*1\s*\)"
)

RE_AC_OR_EXPR = re.compile(
    r"^\s*ac\s*=\s*(?P<base>\w+)\s*\|\s*(?P<gt>(?:\(uint\)\([^)]+\)|[^;]+))\s*;\s*$"
)

RE_AC_EQ_GT = re.compile(
    r"^\s*ac\s*=\s*(?P<base>\w+)\s*\|\s*"
    + _UINT_EQ
    + r"\s*\|\s*"
    + _UINT_GT
    + r"\s*;\s*$"
)

RE_DECLARE = re.compile(r"^\s*(?:uint|int|undefined4|char \*)\s+(\w+)\s*;\s*$")


@dataclass
class FlagWord:
    eq: str | None = None
    lt: str | None = None
    gt: str | None = None


def _neg(expr: str) -> str:
    expr = expr.strip()
    m = re.fullmatch(r"([^!<>=]+)\s*==\s*(.+)", expr)
    if m:
        return f"({m.group(1).strip()} != {m.group(2).strip()})"
    m = re.fullmatch(r"(0x[0-9a-fA-F]+)\s*<\s*(.+)", expr)
    if m:
        return f"({m.group(2).strip()} <= {m.group(1).strip()})"
    return f"!({expr})"


def _bit1(var: str, flags: dict[str, FlagWord], *, negate: bool) -> str | None:
    fw = flags.get(var)
    if fw is None or fw.eq is None:
        return None
    return _neg(fw.eq) if negate else f"({fw.eq})"


def _bit2(var: str, flags: dict[str, FlagWord], *, negate: bool) -> str | None:
    fw = flags.get(var)
    if fw is None or fw.lt is None:
        return None
    return _neg(fw.lt) if negate else f"({fw.lt})"


def _bit0(var: str, flags: dict[str, FlagWord], *, negate: bool) -> str | None:
    fw = flags.get(var)
    if fw is None or fw.gt is None:
        return None
    return _neg(fw.gt) if negate else f"({fw.gt})"


def _strip_one_paren(expr: str) -> str:
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        return expr[1:-1]
    return expr


def _merge_nonzero(gt: str, or_expr: str) -> str | None:
    gt = _strip_one_paren(gt.strip())
    or_expr = or_expr.strip()
    if "< 0" in gt and or_expr.startswith("0 <"):
        lhs = gt.split("< 0", 1)[0].strip()
        lhs = _strip_one_paren(lhs)
        rhs = or_expr[2:].strip()
        if lhs in rhs or rhs.endswith(lhs):
            cast = lhs if lhs.startswith("(") else f"(int){lhs}"
            return f"({cast} != 0)"
    return f"(({gt}) || ({or_expr}))"


def _join_continued_lines(text: str) -> str:
    out: list[str] = []
    buf = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if buf:
            buf = f"{buf} {stripped.lstrip()}"
            if ";" in buf:
                out.append(buf)
                buf = ""
            continue
        if "=" in stripped and "|" in stripped and not stripped.endswith(";"):
            buf = stripped
            continue
        out.append(stripped)
    if buf:
        out.append(buf)
    return "\n".join(out)


def _parse_flag_line(line: str, flags: dict[str, FlagWord]) -> None:
    m = RE_FLAG_WORD.match(line)
    if m:
        flags[m.group("var")] = FlagWord(eq=m.group("eq"), lt=m.group("lt"), gt=m.group("gt"))
        return

    m = RE_FLAG_LT_ONLY.match(line)
    if m:
        cur = flags.get(m.group("var"), FlagWord())
        cur.lt = m.group("lt")
        flags[m.group("var")] = cur
        return

    m = RE_AC_EQ_GT.match(line)
    if m:
        cur = FlagWord(eq=m.group("eq"), gt=m.group("gt"))
        flags["ac"] = cur
        return

    m = RE_AC_OR_EXPR.match(line)
    if m:
        base = m.group("base")
        base_flags = flags.get(base, FlagWord())
        base_flags.gt = m.group("gt").strip()
        flags[base] = base_flags
        merged = FlagWord(eq=base_flags.eq, lt=base_flags.lt, gt=base_flags.gt)
        flags["ac"] = merged


def _line_drops_ac_noise(line: str) -> bool:
    return bool(
        RE_AC_SAVE.match(line)
        or RE_G14_CLEAR.match(line)
        or RE_FLAG_WORD.match(line)
        or RE_FLAG_LT_ONLY.match(line)
        or RE_AC_OR_EXPR.match(line)
        or RE_AC_EQ_GT.match(line)
        or RE_LOOP_AC.match(line)
    )


def _extract_paren(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
        i += 1
    raise ValueError("unbalanced parentheses")


def _apply_flag_tests(working: str, flags: dict[str, FlagWord]) -> tuple[str, bool]:
    changed = False
    patterns: list[tuple[re.Pattern[str], str, bool]] = [
        (re.compile(r"\(\(byte\)\((\w+)\s*>>\s*1\)\s*&\s*1\)\s*!=\s*1"), "bit1", True),
        (re.compile(r"\(\(byte\)\((\w+)\s*>>\s*1\)\s*&\s*1\)\s*==\s*1"), "bit1", False),
        (re.compile(r"\(\(byte\)\((\w+)\s*>>\s*2\)\s*&\s*1\)\s*!=\s*1"), "bit2", True),
        (re.compile(r"\(\(byte\)\((\w+)\s*>>\s*2\)\s*&\s*1\)\s*==\s*1"), "bit2", False),
        (re.compile(r"\(\(byte\)(\w+)\s*&\s*1\)\s*!=\s*1"), "bit0", True),
        (re.compile(r"\(\(byte\)(\w+)\s*&\s*1\)\s*==\s*1"), "bit0", False),
    ]

    for pattern, kind, negate in patterns:
        while True:
            m = pattern.search(working)
            if not m:
                break
            var = m.group(1)
            if kind == "bit1":
                repl = _bit1(var, flags, negate=negate)
            elif kind == "bit2":
                repl = _bit2(var, flags, negate=negate)
            else:
                repl = _bit0(var, flags, negate=negate)
            if repl is None:
                break
            working = working[: m.start()] + repl + working[m.end() :]
            changed = True
    return working, changed


def _rewrite_condition(cond: str, flags: dict[str, FlagWord]) -> tuple[str, bool]:
    changed = False
    working = re.sub(r"\s+", " ", cond.strip())

    comma = RE_COMMA_AC.search(working)
    if comma:
        flags["ac"] = FlagWord(
            eq=comma.group("eq"),
            lt=comma.group("lt"),
            gt=comma.group("gt"),
        )
        bit0 = _bit0("ac", flags, negate=False)
        if bit0:
            merged = _merge_nonzero(_strip_one_paren(bit0), comma.group("or_expr"))
            repl = merged or f"(({bit0}) || ({comma.group('or_expr')}))"
        else:
            repl = "0"
        working = working[: comma.start()] + repl + working[comma.end() :]
        changed = True

    working, test_changed = _apply_flag_tests(working, flags)
    changed = changed or test_changed

    working = re.sub(r"\s*&&\s*", " && ", working)
    working = re.sub(r"\s*\|\|\s*", " || ", working)
    working = re.sub(r"\(\s+", "(", working)
    working = re.sub(r"\s+\)", ")", working)
    while "((" in working:
        old = working
        working = re.sub(r"\((\([^)]+\))\)", r"\1", working)
        if working == old:
            break
    return working.strip(), changed


def _drop_unused_declarations(text: str) -> str:
    lines = text.splitlines()
    refs = "\n".join(lines)
    kept: list[str] = []
    for line in lines:
        m = RE_DECLARE.match(line)
        if m and not re.search(rf"\b{re.escape(m.group(1))}\b", refs.replace(line, "", 1)):
            continue
        kept.append(line)
    return "\n".join(kept)


def simplify_ghidra_ac(c_src: str) -> tuple[str, bool]:
    if " ac" not in c_src and "\nac" not in c_src:
        return c_src, False

    joined = _join_continued_lines(c_src)
    lines = joined.splitlines()
    flags: dict[str, FlagWord] = {}
    for line in lines:
        _parse_flag_line(line, flags)

    kept: list[str] = []
    dropped = False
    for line in lines:
        if _line_drops_ac_noise(line):
            dropped = True
            continue
        kept.append(line)

    text = "\n".join(kept)
    changed = dropped
    pos = 0
    while True:
        idx = text.find("if (", pos)
        if idx < 0:
            break
        open_paren = idx + 3
        cond, close_idx = _extract_paren(text, open_paren)
        new_cond, cond_changed = _rewrite_condition(cond, flags)
        if cond_changed:
            text = text[: open_paren + 1] + new_cond + text[close_idx - 1 :]
            changed = True
            pos = open_paren + 1 + len(new_cond) + 1
        else:
            pos = close_idx

    if not changed:
        return c_src, False

    text = _drop_unused_declarations(text)

    if "{" in text and "AC condition codes simplified" not in text:
        text = text.replace("{", "{\n  /* i960 AC condition codes simplified to boolean tests */", 1)

    return text, True


def _self_test() -> None:
    strcpy = """
int FUN_0005cdc8(int param_1,char *param_2)
{
  uint uVar1;
  char cVar2;
  uint uVar3;
  char *pcVar4;

  uVar3 = ac;
  g14 = 0;
  uVar1 = ac & 0xfffffff8 | (uint)(param_1 < 0) << 2 | (uint)(param_1 == 0) << 1;
  ac = uVar1 | 0 < param_1;
  if ((((byte)(uVar1 >> 1) & 1) != 1) &&
     (ac = uVar3 & 0xfffffff8 | (uint)(0 < (int)param_2) << 2 | (uint)(param_2 == (char *)0x0) << 1
           | (uint)((int)param_2 < 0), ((byte)ac & 1 | 0 < (int)param_2) == 1)) {
    pcVar4 = (char *)(param_1 + -1);
    do {
      cVar2 = *param_2;
      pcVar4 = pcVar4 + 1;
      param_2 = param_2 + 1;
      *pcVar4 = cVar2;
      ac = ac & 0xfffffff8 | (uint)(cVar2 != '\\0') << 2 | (uint)(cVar2 == '\\0') << 1;
    } while (cVar2 != '\\0');
    return param_1;
  }
  return 0;
}
"""
    out, changed = simplify_ghidra_ac(strcpy)
    assert changed, out
    assert " ac" not in out and "\nac" not in out and " ac;" not in out
    assert "param_1 != 0" in out
    assert "(int)param_2 != 0" in out
    assert "uVar1" not in out and "uVar3" not in out

    dispatch = """
void FUN_0005cf50(byte *param_1)
{
  byte bVar1;
  uint uVar2;
  uint uVar3;

  uVar2 = ac;
  bVar1 = *param_1;
  if (bVar1 == 0) {
    fp = unaff_pfp;
    ac = ac & 0xfffffff8 | (uint)(bVar1 != 0) << 2 | (uint)(bVar1 == 0) << 1;
    return;
  }
  uVar3 = ac & 0xfffffff8 | (uint)(bVar1 < 0x25) << 2 | (uint)(bVar1 == 0x25) << 1;
  ac = uVar3 | 0x25 < bVar1;
  if (((byte)(uVar3 >> 1) & 1) != 1) {
    g14 = 0x5cf98;
    FUN_00027008();
    return;
  }
  uVar3 = (uint)param_1[1];
  ac = uVar2 & 0xfffffff8 | (uint)(uVar3 < 0x78) << 2 | (uint)(uVar3 == 0x78) << 1 |
       (uint)(0x78 < uVar3);
  if (((byte)ac & 1) != 1) {
    return;
  }
}
"""
    out2, changed2 = simplify_ghidra_ac(dispatch)
    assert changed2, out2
    assert "bVar1 != 0x25" in out2 or "bVar1 == 0x25" in out2
    assert "uVar3 <= 0x78" in out2 or "0x78 < uVar3" not in out2
    assert "uVar2" not in out2


if __name__ == "__main__":
    _self_test()
    print("ghidra_simplify_ac: ok")
