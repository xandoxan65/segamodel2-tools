#!/usr/bin/env python3
"""Compare assembled bytes to a maincpu ROM slice; print first mismatches."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.decomp.reasm_slice import REPO_ROOT, count_mismatch_bytes, sha256
from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir


def first_mismatch(rebuilt: bytes, reference: bytes) -> dict | None:
    span = min(len(rebuilt), len(reference))
    for index in range(span):
        if rebuilt[index] != reference[index]:
            return {
                "offset": index,
                "rom_byte": f"0x{reference[index]:02x}",
                "got_byte": f"0x{rebuilt[index]:02x}",
                "rom_context": reference[max(0, index - 4) : index + 4].hex(),
                "got_context": rebuilt[max(0, index - 4) : index + 4].hex(),
            }
    if len(rebuilt) != len(reference):
        return {
            "offset": span,
            "rom_byte": None,
            "got_byte": None,
            "note": f"length rom=0x{len(reference):x} got=0x{len(rebuilt):x}",
        }
    return None


def compare_bytes(reference: bytes, rebuilt: bytes, *, base: int) -> dict:
    match = reference == rebuilt
    row: dict = {
        "base": f"0x{base:08x}",
        "length": len(reference),
        "match": match,
        "mismatch_bytes": 0 if match else count_mismatch_bytes(rebuilt, reference),
        "reference_sha256": sha256(reference),
        "rebuilt_sha256": sha256(rebuilt),
    }
    if not match:
        diff = first_mismatch(rebuilt, reference)
        if diff:
            row["first_diff"] = diff
            row["first_diff"]["rom_addr"] = f"0x{base + diff['offset']:08x}"
    return row


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare binary blob to maincpu ROM slice")
    ap.add_argument("--rom", required=True, help="0x<base>:0x<len> hex slice spec")
    ap.add_argument("--blob", type=Path, required=True, help="Binary file to compare")
    ap.add_argument("--blob-offset", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    from tools.decomp.c_reasm_slice import parse_rom_spec

    base, length = parse_rom_spec(args.rom)
    maincpu_raw, _ = load_maincpu_words(resolve_rom_dir(args.rom_dir))
    reference = maincpu_raw[base : base + length]

    blob = args.blob.read_bytes()
    end = args.blob_offset + length
    if end > len(blob):
        raise SystemExit(
            f"blob too small: need offset 0x{args.blob_offset:x}+0x{length:x}, got 0x{len(blob):x}"
        )
    rebuilt = blob[args.blob_offset : end]

    report = compare_bytes(reference, rebuilt, base=base)
    text = json.dumps(report, indent=2) + "\n"
    if args.report:
        path = args.report if args.report.is_absolute() else REPO_ROOT / args.report
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"report → {path}")
    else:
        print(text, end="")

    if not report["match"]:
        diff = report.get("first_diff", {})
        print(
            f"FAIL mismatch_bytes={report['mismatch_bytes']} "
            f"first @ {diff.get('rom_addr', '?')} "
            f"rom={diff.get('rom_byte')} got={diff.get('got_byte')}"
        )
        raise SystemExit(1)
    print("PASS")


if __name__ == "__main__":
    main()
