"""Unit tests for i960 operand EA parsing and lda/ld lowering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

DECOMP_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(DECOMP_ROOT))

from tools.decomp.i960_operand import parse_operand, signed_disp  # noqa: E402
from tools.decomp.i960_ops import format_lda_expr, insn_lower  # noqa: E402
from tools.decomp.i960_emit_c import EmitContext, _emit_if_then, _emit_if_else  # noqa: E402
from tools.decomp.i960_cfg import IfThenRegion, IfElseRegion  # noqa: E402
from tools.decomp.i960_ir import IrBlock, IrFunction, IrStmt, StmtKind  # noqa: E402


class OperandEaTests(unittest.TestCase):
    def test_signed_disp(self) -> None:
        self.assertEqual(signed_disp(0x18), 0x18)
        self.assertEqual(signed_disp(0xFFFFFFFF), -1)

    def test_base_scaled_index(self) -> None:
        op = parse_operand("(r8)[r8*8]")
        self.assertEqual(op.kind, "mem")
        self.assertEqual(op.mem_base, "r8")
        self.assertEqual(op.mem_offset, 0)
        self.assertEqual(op.mem_index, "r8")
        self.assertEqual(op.mem_scale, 8)

    def test_disp_base_index(self) -> None:
        op = parse_operand("0xffffffff(g9)[g6]")
        self.assertEqual(op.kind, "mem")
        self.assertEqual(op.mem_base, "g9")
        self.assertEqual(op.mem_offset, -1)
        self.assertEqual(op.mem_index, "g6")
        self.assertEqual(op.mem_scale, 1)

    def test_disp_base_scaled(self) -> None:
        op = parse_operand("0x18(g5)[g4*4]")
        self.assertEqual(op.mem_base, "g5")
        self.assertEqual(op.mem_offset, 0x18)
        self.assertEqual(op.mem_index, "g4")
        self.assertEqual(op.mem_scale, 4)

    def test_abs_scaled(self) -> None:
        op = parse_operand("0x1000[g4*4]")
        self.assertIsNone(op.mem_base)
        self.assertEqual(op.mem_offset, 0x1000)
        self.assertEqual(op.mem_index, "g4")
        self.assertEqual(op.mem_scale, 4)

    def test_lda_scaled(self) -> None:
        expr, _ = format_lda_expr(parse_operand("(r8)[r8*8]"), "g4")
        self.assertEqual(expr, "g4 = r8 + (u32)(r8 << 3)")

    def test_lda_neg_disp_index(self) -> None:
        expr, _ = format_lda_expr(parse_operand("0xffffffff(g9)[g6]"), "g4")
        self.assertEqual(expr, "g4 = g9 - 0x1 + (u32)g6")

    def test_ld_base_scaled(self) -> None:
        text, meta = insn_lower("ld", ["0x18(g5)[g4*4]", "g4"])
        assert text is not None
        self.assertIn("i960_ld_u32", text)
        self.assertIn("g5", text)
        self.assertIn("0x18 + ((u32)(g4 << 2))", text)
        self.assertEqual(meta["mem"]["width"], "u32")

    def test_notbit_andnot(self) -> None:
        text, _ = insn_lower("notbit", ["31", "g4", "g4"])
        self.assertEqual(text, "g4 = g4 ^ (1u << 31)")
        text, _ = insn_lower("andnot", ["g0", "g4", "g4"])
        self.assertEqual(text, "g4 = g4 & ~g0")

    def test_cpysre(self) -> None:
        text, meta = insn_lower("cpysre", ["fp0", "fp1", "fp2"])
        self.assertEqual(text, "fp2 = copysign(fp1, fp0)")
        self.assertTrue(meta.get("fp"))


class CfgIfThenTests(unittest.TestCase):
    def test_trim_external_merge(self) -> None:
        from tools.decomp.i960_cfg import build_cfg, find_structured_regions

        # Early goto into merge mid-chain must not swallow the merge into then.
        #   B0: if (c) goto JOIN_SKIP
        #   B1..B2: then body
        #   MERGE: (also targeted by early goto) fall to JOIN_SKIP
        #   JOIN_SKIP: ...
        blocks = [
            IrBlock(
                0x100,
                [
                    IrStmt(
                        StmtKind.BRANCH,
                        "if (g0 != 0) goto L_00000120;",
                        addr=0x100,
                        target=0x120,
                    )
                ],
            ),
            IrBlock(0x104, [IrStmt(StmtKind.ASSIGN, "g1 = 1;", addr=0x104)]),
            IrBlock(0x108, [IrStmt(StmtKind.ASSIGN, "g2 = 2;", addr=0x108)]),
            IrBlock(0x10C, [IrStmt(StmtKind.ASSIGN, "g3 = 3;", addr=0x10C)]),
            IrBlock(0x120, [IrStmt(StmtKind.ASSIGN, "g4 = 4;", addr=0x120)]),
            IrBlock(
                0x0F0,
                [
                    IrStmt(
                        StmtKind.BRANCH,
                        "goto L_0000010c;",
                        addr=0x0F0,
                        target=0x10C,
                    )
                ],
            ),
        ]
        fn = IrFunction(
            name="t",
            addr=0x0F0,
            length=0x40,
            kind="leaf",
            args=[],
            link_reg=None,
            blocks=blocks,
            entry=0x0F0,
        )
        regions = find_structured_regions(fn)
        if_thens = [r for r in regions if r.__class__.__name__ == "IfThenRegion"]
        self.assertEqual(len(if_thens), 1)
        region = if_thens[0]
        self.assertEqual(region.then_addrs, [0x104, 0x108])
        self.assertEqual(region.join_addr, 0x10C)

    def test_reject_loop_header_then(self) -> None:
        from tools.decomp.i960_cfg import find_structured_regions

        # if (n<=0) goto OUT; LOOP: ...; if (i<n) goto LOOP; OUT:
        blocks = [
            IrBlock(
                0x200,
                [
                    IrStmt(
                        StmtKind.BRANCH,
                        "if (r8 <= 0) goto L_00000220;",
                        addr=0x200,
                        target=0x220,
                    )
                ],
            ),
            IrBlock(0x204, [IrStmt(StmtKind.ASSIGN, "r4 = 1;", addr=0x204)]),
            IrBlock(
                0x208,
                [
                    IrStmt(
                        StmtKind.BRANCH,
                        "if (r13 < r8) goto L_00000204;",
                        addr=0x208,
                        target=0x204,
                    )
                ],
            ),
            IrBlock(0x220, [IrStmt(StmtKind.ASSIGN, "g0 = 0;", addr=0x220)]),
        ]
        fn = IrFunction(
            name="t",
            addr=0x200,
            length=0x30,
            kind="leaf",
            args=[],
            link_reg=None,
            blocks=blocks,
            entry=0x200,
        )
        regions = find_structured_regions(fn)
        if_thens = [r for r in regions if r.__class__.__name__ == "IfThenRegion"]
        self.assertEqual(if_thens, [])


class EmitBraceTests(unittest.TestCase):
    def _ctx(self, *blocks: IrBlock) -> EmitContext:
        fn = IrFunction(
            name="t",
            addr=0,
            length=0x100,
            kind="leaf",
            args=[],
            link_reg=None,
            blocks=list(blocks),
            entry=blocks[0].addr if blocks else 0,
        )
        return EmitContext(fn=fn)

    def _block(self, addr: int, *texts: str) -> IrBlock:
        stmts = [
            IrStmt(kind=StmtKind.ASSIGN, text=t, addr=addr, meta={}) for t in texts
        ]
        return IrBlock(addr=addr, stmts=stmts)

    def test_if_then_braces(self) -> None:
        then = self._block(0x100, "g0 = 1;", "g1 = 2;")
        region = IfThenRegion(
            branch_addr=0xF0,
            condition="g4 != 0",
            invert=False,
            then_addrs=[0x100],
            join_addr=0x110,
        )
        lines = _emit_if_then(
            region,
            {0x100: then},
            set(),
            self._ctx(then),
            base_indent=4,
        )
        self.assertEqual(lines[0], "    if (g4 != 0) {")
        self.assertTrue(any("g0 = 1" in ln for ln in lines))
        self.assertEqual(lines[-1], "    }")

    def test_if_else_braces(self) -> None:
        fall = self._block(0x200, "g0 = 1;")
        taken = self._block(0x210, "g0 = 2;")
        region = IfElseRegion(
            branch_addr=0x1F0,
            condition="g4 != 0",
            else_addrs=[0x200],
            then_addrs=[0x210],
            join_addr=0x220,
        )
        lines = _emit_if_else(
            region,
            {0x200: fall, 0x210: taken},
            set(),
            self._ctx(fall, taken),
            base_indent=4,
        )
        joined = "\n".join(lines)
        self.assertIn("if (g4 != 0) {", joined)
        self.assertIn("} else {", joined)
        self.assertTrue(joined.rstrip().endswith("}"))


if __name__ == "__main__":
    unittest.main()
