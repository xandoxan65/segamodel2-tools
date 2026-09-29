"""i960 lowering: compare-and-branch widths and multi-register moves.

Each case compiles the lowered C against a word-array memory and runs it, so
what is checked is the value the statement computes, not its spelling.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from liftkit.arch.i960.i960_ops import cmp_branch_cond, insn_lower, lower_multi_mov_stmts

CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

PRELUDE = r"""
#include <stdint.h>
#include <stdio.h>
typedef unsigned int u32;
typedef signed int i32;
typedef enum { I960_REG, I960_FP, I960_WORKRAM, I960_ROM, I960_MMIO, I960_ABS } i960_space;
static u32 mem[64];
static u32 i960_ld_u32(i960_space s, u32 base, u32 off) { (void)s; return mem[(base + off) / 4]; }
static void i960_st_u32(i960_space s, u32 base, u32 off, u32 v) { (void)s; mem[(base + off) / 4] = v; }
static uintptr_t g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15;
static uintptr_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
"""


def run_c(body: str, tmp_path) -> list[int]:
    """Compile ``body`` into main() and return the integers it prints."""
    if CC is None:
        pytest.skip("no C compiler")
    src = tmp_path / "t.c"
    exe = tmp_path / "t"
    src.write_text(PRELUDE + "int main(void) {\n" + body + "\nreturn 0;\n}\n")
    subprocess.run([CC, "-std=c99", "-w", "-o", str(exe), str(src)], check=True)
    out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
    return [int(v, 0) for v in out.split()]


def show(*regs: str) -> str:
    return "".join(f'printf("0x%x ", (unsigned)({r}));' for r in regs)


@pytest.mark.parametrize(
    "mn, src1, reg_value, taken",
    [
        # Literal against a register whose low byte is 0: all 32 bits count.
        ("cmpibge", "0", 0x100, 0),
        ("cmpibe", "0", 0x100, 0),
        ("cmpibne", "0", 0x100, 1),
        ("cmpobne", "0", 0x100, 1),
        # Signed against unsigned: -1 is below 5 for cmpib, above it for cmpob.
        ("cmpibl", "5", 0xFFFFFFFF, 0),
        ("cmpibg", "5", 0xFFFFFFFF, 1),
        ("cmpobl", "5", 0xFFFFFFFF, 1),
        ("cmpobge", "5", 0xFFFFFFFF, 0),
        ("cmpible", "31", 0x1F, 1),
        ("cmpoble", "31", 0x11F, 1),
    ],
)
def test_cmp_branch_is_full_word(mn, src1, reg_value, taken, tmp_path):
    cond = cmp_branch_cond(mn, src1, "g4")
    assert cond is not None
    body = f"g4 = 0x{reg_value:x}u; printf(\"%d \", ({cond}) ? 1 : 0);"
    assert run_c(body, tmp_path) == [taken]


def test_cmpob_two_registers(tmp_path):
    cond = cmp_branch_cond("cmpobg", "g5", "g4")
    body = "g5 = 0x80000000u; g4 = 1; " + f'printf("%d ", ({cond}) ? 1 : 0);'
    assert run_c(body, tmp_path) == [1]


def _lower(mn: str, operands: list[str]) -> str:
    expr, _ = insn_lower(mn, operands)
    assert expr is not None, f"{mn} {operands} not lowered"
    return expr + ";"


def test_ldl_fills_both_registers(tmp_path):
    body = (
        "for (int i = 0; i < 64; i++) mem[i] = 0x1000 + i; g4 = 8;"
        + _lower("ldl", ["0x10(g4)", "g6"])
        + show("g6", "g7")
    )
    assert run_c(body, tmp_path) == [0x1006, 0x1007]


def test_ldq_fills_four_registers(tmp_path):
    body = (
        "for (int i = 0; i < 64; i++) mem[i] = 0x2000 + i; g4 = 0x20; g5 = 1;"
        + _lower("ldq", ["(g4)[g5*4]", "r4"])
        + show("r4", "r5", "r6", "r7")
    )
    assert run_c(body, tmp_path) == [0x2009, 0x200A, 0x200B, 0x200C]


def test_ldt_from_absolute_address(tmp_path):
    body = (
        "for (int i = 0; i < 64; i++) mem[i] = 0x3000 + i;"
        + _lower("ldt", ["0x40", "g8"])
        + show("g8", "g9", "g10")
    )
    assert run_c(body, tmp_path) == [0x3010, 0x3011, 0x3012]


def test_stl_and_stq_store_every_register(tmp_path):
    body = (
        "g4 = 0; g6 = 0xAAAA; g7 = 0xBBBB; r8 = 1; r9 = 2; r10 = 3; r11 = 4;"
        + _lower("stl", ["g6", "0x8(g4)"])
        + _lower("stq", ["r8", "0x40(g4)"])
        + show("mem[2]", "mem[3]", "mem[16]", "mem[17]", "mem[18]", "mem[19]")
    )
    assert run_c(body, tmp_path) == [0xAAAA, 0xBBBB, 1, 2, 3, 4]


def test_misaligned_group_is_not_lowered():
    assert insn_lower("ldl", ["0x10(g4)", "g5"])[0] is None
    assert insn_lower("ldq", ["0x10(g4)", "g6"])[0] is None


@pytest.mark.parametrize(
    "mn, operands, setup, regs, expected",
    [
        ("movl", ["g4", "g6"], "g4 = 1; g5 = 2;", ["g6", "g7"], [1, 2]),
        ("movt", ["g4", "r8"], "g4 = 1; g5 = 2; g6 = 3;", ["r8", "r9", "r10"], [1, 2, 3]),
        ("movq", ["r4", "g8"], "r4 = 1; r5 = 2; r6 = 3; r7 = 4;", ["g8", "g9", "g10", "g11"], [1, 2, 3, 4]),
        ("movl", ["3", "g6"], "g6 = 9; g7 = 9;", ["g6", "g7"], [3, 0]),
    ],
)
def test_multi_mov(mn, operands, setup, regs, expected, tmp_path):
    stmts = lower_multi_mov_stmts(mn, operands)
    assert len(stmts) == len(regs)
    body = setup + "".join(f"{text};" for text, _ in stmts) + show(*regs)
    assert run_c(body, tmp_path) == expected


def test_fused_branch_uses_full_word_compare():
    from liftkit.arch.i960.disasm_parse import Insn
    from liftkit.arch.i960.i960_macros import _lower_branch

    insn = Insn(addr=0x100, words=[0], mnemonic="cmpobl", operands=["5", "g4", "0x120"])
    stmt = _lower_branch("cmpobl", insn.operands, insn, None)
    assert stmt is not None
    assert stmt.text == "if ((u32)5 < (u32)g4) goto L_00000120;"
