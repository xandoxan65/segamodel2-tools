"""MB86233/MB86234 disassembler — port of MAME mb86233d.cpp (ISA reference).

Disassembles the Model 2A TGP program blob uploaded from workram @ 0x5F9E94
(ROM mirror: maincpu + (vaddr - 0x59F000)).
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

REGNAMES = [
    "b0", "b1", "x0", "x1", "x2", "i0", "i1", "i2", "sp", "pag", "vsm", "dmc",
    "c0", "c1", "pc", "-",
    "a", "ah", "al", "b", "bh", "bl", "c", "ch", "cl", "d", "dh", "dl",
    "p", "ph", "pl", "sft",
    "rf0", "rf1", "rf2", "rf3", "rf4", "rf5", "rf6", "rf7",
    "rf8", "rf9", "rfa", "rfb", "rfc", "rfd", "rfe", "rff",
    "sio0", "si1", "pio", "pioa", "rpc", "r?35", "r?36", "r?37",
    "pad", "mod", "ear", "st", "mask", "tim", "cx", "dx",
]

CONDS = {
    0x00: "zrd", 0x01: "ged", 0x02: "led",
    0x0a: "gpio0", 0x0b: "gpio1", 0x0c: "gpio2",
    0x10: "zc0", 0x11: "zc1", 0x12: "gpio3", 0x16: "alw",
}

ALU0 = {
    0x01: "andd", 0x02: "orad", 0x03: "eord", 0x04: "notd", 0x05: "fcpd",
    0x06: "fadd", 0x07: "fsbd", 0x08: "fml", 0x09: "fmsd", 0x0a: "fmrd",
    0x0b: "fabd", 0x0c: "fsmd", 0x0d: "fspd", 0x0e: "cxfd", 0x0f: "cfxd",
    0x10: "fdvd", 0x11: "fned", 0x13: "d=b+a", 0x14: "d=b-a",
    0x16: "lsrd", 0x17: "lsld", 0x18: "asrd", 0x19: "asld",
    0x1a: "addd", 0x1b: "subd",
}


def condition(cond: int, invert: bool) -> str:
    name = CONDS.get(cond, f"cond({cond:02x})")
    return ("!" + name) if invert else name


def regs(reg: int) -> str:
    return REGNAMES[reg & 0x3F]


def memory(reg: int, x1: bool, bank: bool) -> str:
    xn = "x1" if x1 else "x0"
    bxn = "bx1" if x1 else "bx0"
    mode = reg & 0x180
    if mode == 0x000:
        a = 0x200 | (reg & 0x7F) if bank else (reg & 0x7F)
        return f"${a}" if a >= 10 else f"${a}"
    if mode == 0x080:
        a = 0x200 | (reg & 0x7F) if bank else (reg & 0x7F)
        prefix = f"${a}" if (bank or (reg & 0x7F)) else ""
        if prefix and a < 10 and not bank:
            prefix = f"${a}"
        return f"{prefix}({xn})"
    if mode == 0x100:
        a = 0x200 | (reg & 0x7F) if bank else (reg & 0x7F)
        prefix = f"${a}" if (bank or (reg & 0x7F)) else ""
        return f"{prefix}({xn}+)"
    # 0x180
    brack_l = "[" if (reg & 0x40) else "("
    brack_r = "]" if (reg & 0x40) else ")"
    base = bxn if not (reg & 0x20) else xn
    if reg & 0x10:
        off = 0x10 - (reg & 0xF)
        return f"{brack_l}{base}-{off}{brack_r}" + ("+0x200" if bank else "")
    if reg & 0xF:
        return f"{brack_l}{base}+{reg & 0xF}{brack_r}" + ("+0x200" if bank else "")
    return f"{brack_l}{base}{brack_r}" + ("+0x200" if bank else "")


def alu0_func(alu: int) -> str:
    if alu == 0:
        return ""
    return ALU0.get(alu, f"alu0_func({alu:02x})")


def disassemble(opcode: int) -> str:
    top = (opcode >> 26) & 0x3F

    if top == 0x00:
        r1 = opcode & 0x1FF
        r2 = (opcode >> 9) & 0x1FF
        alu = (opcode >> 21) & 0x1F
        op = (opcode >> 18) & 0x7
        pre = f"{alu0_func(alu)} : " if alu else ""
        if op in (0, 1):
            return f"{pre}lab {memory(r1, False, False)}, {memory(r2, True, False)} (e)"
        if op == 3:
            return f"{pre}lab {memory(r1, False, False)}, {memory(r2, True, True)}"
        if op == 4:
            return f"{pre}lab {memory(r1, False, True)}, {memory(r2, True, False)}"
        return f"{pre}lab {{{op}}} {memory(r1, False, False)}, {memory(r2, True, False)}"

    if top == 0x07:
        r1 = opcode & 0x1FF
        r2 = (opcode >> 9) & 0x1FF
        alu = (opcode >> 21) & 0x1F
        op = (opcode >> 18) & 0x7
        pre = ""
        if alu:
            if (opcode & 0x001FFFFF) == 0x1F1E10:
                return alu0_func(alu)
            pre = f"{alu0_func(alu)} : "
        if op == 0:
            return f"{pre}mov {{0}} {memory(r1, False, False)}, {memory(r2, True, False)} (e)"
        if op == 1:
            return f"{pre}mov {memory(r1, False, False)}, {memory(r2, True, False)} (e)"
        if op == 2:
            return f"{pre}mov {memory(r1, False, False)} (e), {memory(r2, True, False)}"
        if op == 3:
            return f"{pre}mov {memory(r1, False, False)}, {memory(r2, True, True)}"
        if op == 4:
            return f"{pre}mov {memory(r1, False, True)}, {memory(r2, True, False)}"
        if op == 5:
            return f"{pre}mov {memory(r1, False, False)} (o), {memory(r2, True, False)}"
        if op == 7:
            sub = r2 >> 6
            if sub == 0:
                return f"{pre}mov {regs(r2 & 0x3F)}, {memory(r1, True, False)}"
            if sub == 1:
                return f"{pre}mov {regs(r2 & 0x3F)}, {memory(r1, True, False)} (e)"
            if sub == 2:
                return f"{pre}mov {memory(r1, True, True)}, {regs(r2 & 0x3F)}"
            if sub == 3:
                return f"{pre}mov {memory(r1, True, False)}, {regs(r2 & 0x3F)}"
            if sub == 4:
                return f"{pre}mov {memory(r1, True, False)} (e), {regs(r2 & 0x3F)}"
            if sub == 5:
                return f"{pre}mov {memory(r1, False, False)} (o), {regs(r2 & 0x3F)}"
            if sub == 6:
                return f"{pre}mov {regs(r1 & 0x3F)}, {regs(r2 & 0x3F)}"
            return f"{pre}mov {{r2 {sub}}} {memory(r1, False, False)}, {regs(r2 & 0x3F)}"
        return f"{pre}mov {{{op}}} {memory(r1, False, False)}, {memory(r2, True, False)}"

    if top == 0x0D:
        sub2 = (opcode >> 17) & 7
        if sub2 == 5:
            round_mode = ["rn", "rp", "rm", "rz"][(opcode >> 1) & 3]
            fp = " fp" if (opcode & 1) else ""
            return f"stmh{fp} {round_mode}"
        return f"unk {top:02x}.{sub2}"

    if top == 0x0E:
        inst = ["lipl", "lia", "lib", "lid"][(opcode >> 24) & 3]
        return f"{inst} #0x{opcode & 0xFFFFFF:x}"

    if top == 0x0F:
        alu = (opcode >> 20) & 0x1F
        sub2 = (opcode >> 17) & 7
        pre = f"{alu0_func(alu)} : " if alu else ""
        if sub2 == 0:
            rl2 = [
                "?0", "?1", "a", "b", "d", "?5", "?6", "?7",
                "?8", "?9", "?a", "?b", "?c", "?d", "?e", "?f",
            ]
            names = [rl2[i] for i in range(16) if opcode & (1 << i)]
            return pre + "clr0 " + ", ".join(names) if names else pre + "clr0"
        if sub2 == 1:
            return f"{pre}clr1 #0x{opcode & 0xFFFF:04x}"
        if sub2 == 2:
            if opcode & 0x8000:
                return f"{pre}rep {regs(opcode & 0x3F)}"
            n = opcode & 0xFF
            return f"{pre}rep #0x100" if n == 0 else f"{pre}rep #{n}"
        if sub2 == 3:
            return f"{pre}set #0x{opcode & 0xFFFF:04x}"
        return f"{pre}unk {top:02x}.{sub2}"

    if 0x10 <= top <= 0x1F:
        return f"ldi #0x{opcode & 0xFFFFFF:x}, {REGNAMES[(opcode >> 24) & 0x3F]}"

    if top in (0x2F, 0x3F):
        cond = (opcode >> 20) & 0x1F
        subtype = (opcode >> 17) & 7
        data = opcode & 0xFFFF
        invert = bool(opcode & 0x40000000)
        c = condition(cond, invert)
        if subtype == 0:
            return f"brif {c} #0x{data:x}"
        if subtype == 1:
            tgt = regs(opcode & 0x1F) if (opcode & 0x4000) else f"({memory(opcode & 0x1FF, False, False)})"
            return f"brul {c} {tgt}"
        if subtype == 2:
            return f"bsif {c} #0x{data:x}"
        if subtype == 3:
            tgt = regs(opcode & 0x1F) if (opcode & 0x4000) else f"({memory(opcode & 0x1FF, False, False)})"
            return f"bsul {c} {tgt}"
        if subtype == 5:
            return f"rtif {c}"
        if subtype == 6:
            return (
                f"ldif {c} {memory(data & 0x1FF, False, False)}, "
                f"{regs((data >> 9) & 0x3F)}"
            )
        if subtype == 7:
            return "iret"
        return f"unk {top:02x}.{subtype}"

    return f"unk {top:02x}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--bin",
        type=Path,
        default=Path("decomp/src/tgp/firmware/srally_tgp_program.bin"),
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("decomp/disasm/tgp/srally_tgp_program.asm"),
    )
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--count", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    blob = args.bin.read_bytes()
    words = list(struct.unpack("<" + "I" * (len(blob) // 4), blob))
    start = args.start
    end = len(words) if args.count == 0 else min(len(words), start + args.count)

    lines = [
        f"; MB86234 TGP program — srallycb",
        f"; source: workram 0x5F9E94 (ROM mirror maincpu+(va-0x59F000))",
        f"; words: {len(words)} (count @ 0x5FB898)",
        f"; ISA: MAME mb86233d (reference)",
        f";",
        f"; Vectors: 0→#0x10 reset; 1..5 irq stubs; 4→#0xa",
        f"; FIFO dispatch: validate opcode @0x70; table base 0xAF+opcode (bsul)",
        f";   0x52 → 0x101 → handler 0x58A (road query / fill slot $68+$103)",
        f";   0x53 → 0x102 → handler 0x63C (16 floats + flag; bit7 in flag>>16)",
        f"; See decomp/src/tgp/firmware/README.md",
        "",
    ]
    for pc in range(start, end):
        op = words[pc]
        lines.append(f"{pc:04x}: {op:08x}  {disassemble(op)}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")
    print(f"wrote {args.out} ({end - start} insns)")


if __name__ == "__main__":
    main()
