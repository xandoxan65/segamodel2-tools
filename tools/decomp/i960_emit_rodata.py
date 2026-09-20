"""Emit static ROM data as C arrays (rodata symbols, not functions)."""

from __future__ import annotations

from tools.decomp.disasm_parse import SliceDocument


def _rodata_comment(name: str, addr: int) -> str:
    if name == "boot_prcb":
        return "i960 Processor Control Block (PRCB) — loaded by hardware at reset"
    if name == "boot_rom_header":
        return "i960 reset/boot header (SAT, PRCB pointer, initial IP)"
    return "ROM constant block"


def emit_rodata_c(doc: SliceDocument, *, name: str) -> str:
    words: list[tuple[int, int]] = []
    for insn in doc.insns:
        if not insn.words:
            continue
        base = insn.addr
        for idx, word in enumerate(insn.words):
            words.append((base + idx * 4, word))

    lines = [
        "/* Auto-lifted ROM constant block — not executable code. */",
        f"/* source: {doc.source} */",
        f"// @rom 0x{doc.base:x} +0x{doc.length:x} {name}",
        "",
        '#include "../i960_lift.h"',
        "",
        f"/* {_rodata_comment(name, doc.base)} */",
        f"const u32 {name}[] = {{",
    ]

    for offset, word in words:
        rel = offset - doc.base
        lines.append(f"    0x{word:08x}u, /* +0x{rel:03x} */")

    lines.extend(
        [
            "};",
            "",
            f"#define {name.upper()}_WORD_COUNT (sizeof({name}) / sizeof({name}[0]))",
            f"#define {name.upper()}_ROM_ADDR 0x{doc.base:08x}u",
            "",
        ]
    )
    return "\n".join(lines)
