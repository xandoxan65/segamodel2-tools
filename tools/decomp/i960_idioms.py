"""Register-faithful idiom recognition on macro stmt streams."""

from __future__ import annotations

import re

from tools.decomp.i960_macros import MacroStmt

_FP_SLOT_LDA = re.compile(
    r"^\s*\w+\s*=\s*\(u32\)i960_fp_slot\(0x([0-9a-fA-F]+)\)\s*;?\s*$"
    r"|^\s*\w+\s*=\s*\(u32\)\(\(uintptr_t\)fp\s*\+\s*0x([0-9a-fA-F]+)\)\s*;?\s*$"
)
_ST_INTRINSIC = re.compile(
    r"^i960_st_u(8|16|32|64)\(I960_(?:REG|FP),\s*(\w+),\s*0x([0-9a-fA-F]+),\s*\(u\d+\)(\w+)\)\s*;?\s*$"
)


def _frame_lda_offset(stmt: MacroStmt) -> int | None:
    frame = stmt.meta.get("frame")
    if isinstance(frame, dict) and frame.get("base") == "fp":
        return int(frame.get("offset", 0))
    m = _FP_SLOT_LDA.match(stmt.text.strip().rstrip(";"))
    if m:
        return int(m.group(1) or m.group(2), 16)
    return None


def _parse_st_intrinsic(text: str) -> tuple[str, str, int, str] | None:
    m = _ST_INTRINSIC.match(text.strip().rstrip(";"))
    if not m:
        return None
    width, base, off_s, value = m.group(1), m.group(2), m.group(3), m.group(4)
    return width, base, int(off_s, 16), value


def _try_fp_va_slots(stmts: list[MacroStmt], idx: int) -> list[MacroStmt] | None:
    if idx >= len(stmts):
        return None
    s0 = stmts[idx]
    if s0.kind != "assign":
        return None
    fp_off = _frame_lda_offset(s0)
    if fp_off is None:
        return None
    dst_m = re.match(r"^\s*(\w+)\s*=", s0.text)
    if not dst_m:
        return None
    slot_reg = dst_m.group(1)

    st1_idx = st2_idx = None
    st1_val = st2_val = None
    for j in range(idx + 1, min(idx + 8, len(stmts))):
        if stmts[j].kind != "assign":
            continue
        parsed = _parse_st_intrinsic(stmts[j].text)
        if not parsed:
            continue
        _, base, off, val = parsed
        if base != slot_reg:
            continue
        if off == 0 and st1_idx is None:
            st1_idx, st1_val = j, val
        elif off == 4 and st2_idx is None:
            st2_idx, st2_val = j, val
        if st1_idx is not None and st2_idx is not None:
            break
    if st1_idx is None or st2_idx is None:
        return None

    skip = {idx, st1_idx, st2_idx}
    middle = [stmts[k] for k in range(idx + 1, max(st1_idx, st2_idx) + 1) if k not in skip]
    after = stmts[max(st1_idx, st2_idx) + 1 :]
    slot_base = fp_off
    return (
        stmts[:idx]
        + [
            MacroStmt(
                kind="macro",
                text=f"/* va_list pointer @ fp+0x{fp_off:x} */",
                addr=s0.addr,
                meta={"idiom": "va_list_fp", "fp_offset": fp_off},
            ),
            MacroStmt(
                kind="assign",
                text=f"i960_st_u32(I960_FP, fp, 0x{slot_base:x}, (u32){st1_val});",
                addr=stmts[st1_idx].addr,
                words=list(stmts[st1_idx].words),
                meta={"idiom": "va_list_fp"},
            ),
            MacroStmt(
                kind="assign",
                text=f"i960_st_u32(I960_FP, fp, 0x{slot_base + 4:x}, (u32){st2_val});",
                addr=stmts[st2_idx].addr,
                words=list(stmts[st2_idx].words),
                meta={"idiom": "va_list_fp"},
            ),
        ]
        + middle
        + after
    )


def _apply_fp_va_slots(stmts: list[MacroStmt]) -> list[MacroStmt]:
    for i in range(len(stmts)):
        rewritten = _try_fp_va_slots(stmts, i)
        if rewritten is not None:
            return _apply_fp_va_slots(rewritten)
    return stmts


def _apply_printf_marshal_banner(stmts: list[MacroStmt]) -> list[MacroStmt]:
    out: list[MacroStmt] = []
    i = 0
    while i < len(stmts):
        stmt = stmts[i]
        if (
            stmt.kind == "assign"
            and "g13" in stmt.text
            and "g14" in stmt.text
            and stmt.text.strip().startswith("g13")
        ):
            end = i
            found_call = False
            while end < len(stmts):
                if stmts[end].kind == "call":
                    found_call = True
                    break
                end += 1
            if found_call:
                out.append(
                    MacroStmt(
                        kind="macro",
                        text="/* printf va-block marshal (g0 fmt, g4/g8 extras → g13, then dispatch) */",
                        addr=stmt.addr,
                        meta={"idiom": "printf_marshal"},
                    )
                )
                out.extend(stmts[i : end + 1])
                i = end + 1
                continue
        out.append(stmt)
        i += 1
    return out


def apply_idioms(stmts: list[MacroStmt]) -> list[MacroStmt]:
    return _apply_printf_marshal_banner(_apply_fp_va_slots(stmts))
