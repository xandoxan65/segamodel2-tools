#!/usr/bin/env python3
"""Export geo/copro FIFO binary captures to JSON for viewer replay."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


def read_u32_words(path: Path) -> list[int]:
    data = path.read_bytes()
    if len(data) % 4:
        raise SystemExit(f"{path}: size not multiple of 4")
    return list(struct.unpack(f"<{len(data) // 4}I", data))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prg", type=Path, help="prg_fifo .bin from I960_GEO_DUMP")
    ap.add_argument("--copro", type=Path, help="copro_fifo .bin from I960_COPRO_DUMP")
    ap.add_argument("-o", "--out", type=Path, required=True, help="output JSON")
    args = ap.parse_args()

    doc: dict[str, object] = {"format": "segamod2_geo_fifo_v1"}
    if args.prg:
        doc["prg_fifo"] = [f"0x{w:08x}" for w in read_u32_words(args.prg)]
    if args.copro:
        doc["copro_fifo"] = [f"0x{w:08x}" for w in read_u32_words(args.copro)]

    if "prg_fifo" not in doc and "copro_fifo" not in doc:
        ap.error("provide --prg and/or --copro")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
