#!/usr/bin/env python3
"""Generate decomp/include/model2_memory.h from i960_memory constants."""

from __future__ import annotations

import argparse
from pathlib import Path

import tools.i960_memory as mem


def generate_header() -> str:
    lines = [
        "/* Auto-generated from tools/i960_memory.py — documentation stub, not linked yet. */",
        "#ifndef MODEL2_MEMORY_H",
        "#define MODEL2_MEMORY_H",
        "",
        "/* i960 / Model 2A address map */",
    ]
    for name, value in sorted(vars(mem).items()):
        if name.startswith("_") or not isinstance(value, int):
            continue
        if name in ("GEO_OP_MATRIX", "GEO_OP_OBJECT", "GEO_OP_END"):
            lines.append(f"#define {name} 0x{value:08X}u")
        elif "SIZE" in name or "COUNT" in name or "WORDS" in name or "BYTES" in name:
            lines.append(f"#define {name} 0x{value:X}u")
        else:
            lines.append(f"#define {name} 0x{value:08X}u")
    lines.extend(["", "#endif", ""])
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate model2_memory.h")
    ap.add_argument("--out", type=Path, default=Path("decomp/include/model2_memory.h"))
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(generate_header(), encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
