#!/usr/bin/env python3
"""Assemble a MAME disasm slice via i960-elf-gcc and compare to ROM bytes."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.reasm_slice import (
    REPO_ROOT,
    CONTAINER_RUN,
    LINK_SCRIPT,
    count_mismatch_bytes,
    extract_slice_blob,
    iter_maincpu_slices,
    parse_slice_path,
    repo_rel,
    reasm_slice,
    run_container,
    sha256,
    slice_reference_bytes,
)
from tools.decomp.mame_to_gas960 import translate_file
from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir


def gcc_reasm_slice(
    slice_asm: Path,
    *,
    work_dir: Path,
    rom_dir: Path | None,
    keep_intermediates: bool = False,
    emit_mode: str = "bytes",
    compare_gas: bool = True,
) -> dict:
    """Translate slice → .s, assemble with i960-elf-gcc -mkb, link, compare to ROM."""
    base, length = parse_slice_path(slice_asm)
    work_dir.mkdir(parents=True, exist_ok=True)

    gas_path = work_dir / slice_asm.with_suffix(".s").name
    gcc_obj = work_dir / slice_asm.with_suffix(".gcc.o").name
    gcc_elf = work_dir / slice_asm.with_suffix(".gcc.elf").name

    maincpu_raw, _ = load_maincpu_words(resolve_rom_dir(rom_dir))
    reference, reference_source = slice_reference_bytes(
        slice_asm,
        base=base,
        length=length,
        maincpu_raw=maincpu_raw,
    )

    stats = translate_file(
        slice_asm,
        gas_path,
        base_address=base,
        rom_slice=reference,
        slice_base=base,
        emit_mode=emit_mode,
    )

    env = os.environ.copy()
    env.setdefault("I960_DECOMP_IMAGE", "segamod2/i960-decomp:12.1.2")

    prev_image = os.environ.get("I960_DECOMP_IMAGE")
    os.environ["I960_DECOMP_IMAGE"] = env["I960_DECOMP_IMAGE"]
    try:
        run_container("i960-elf-gcc", "-mkb", "-c", "-o", repo_rel(gcc_obj), repo_rel(gas_path))
        run_container(
            "i960-elf-ld",
            "-T",
            repo_rel(LINK_SCRIPT),
            "-o",
            repo_rel(gcc_elf),
            repo_rel(gcc_obj),
        )
    finally:
        if prev_image is None:
            os.environ.pop("I960_DECOMP_IMAGE", None)
        else:
            os.environ["I960_DECOMP_IMAGE"] = prev_image

    rebuilt = extract_slice_blob(gcc_elf, base, length)
    match = rebuilt == reference

    gas_match: bool | None = None
    gas_mismatch_bytes: int | None = None
    if compare_gas:
        gas_report = reasm_slice(
            slice_asm,
            work_dir=work_dir / "gas_check",
            rom_dir=rom_dir,
            keep_intermediates=False,
            emit_mode=emit_mode,
        )
        gas_match = gas_report["match"]
        gas_mismatch_bytes = gas_report["mismatch_bytes"]

    if not keep_intermediates:
        for path in (
            gas_path,
            gcc_obj,
            gcc_elf,
            gcc_elf.with_suffix(".bin"),
        ):
            full = REPO_ROOT / path
            if full.is_file():
                full.unlink()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "slice": slice_asm.as_posix(),
        "base": f"0x{base:08x}",
        "length": length,
        "assembler": "i960-elf-gcc -mkb",
        "match": match,
        "reference_source": reference_source,
        "reference_sha256": sha256(reference),
        "rebuilt_sha256": sha256(rebuilt),
        "translation": stats,
        "mismatch_bytes": 0 if match else count_mismatch_bytes(rebuilt, reference),
        "gas_match": gas_match,
        "gas_mismatch_bytes": gas_mismatch_bytes,
    }


def gcc_reasm_all(
    *,
    disasm_dir: Path,
    work_dir: Path,
    rom_dir: Path | None,
    keep_intermediates: bool = False,
    emit_mode: str = "bytes",
    compare_gas: bool = False,
) -> dict:
    slices = iter_maincpu_slices(disasm_dir)
    results = []
    passed = 0
    for slice_asm in slices:
        try:
            row = gcc_reasm_slice(
                slice_asm,
                work_dir=work_dir / slice_asm.stem,
                rom_dir=rom_dir,
                keep_intermediates=keep_intermediates,
                emit_mode=emit_mode,
                compare_gas=compare_gas,
            )
        except (subprocess.CalledProcessError, ValueError, FileNotFoundError) as exc:
            row = {
                "slice_name": slice_asm.name,
                "slice": slice_asm.as_posix(),
                "match": False,
                "error": str(exc),
                "mismatch_bytes": -1,
            }
        row["slice_name"] = slice_asm.name
        results.append(row)
        if row.get("match"):
            passed += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "ok": passed == len(results),
        "slices": results,
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Assemble MAME disasm slice with i960-elf-gcc and compare to ROM",
    )
    ap.add_argument("--slice", type=Path, default=None)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--disasm-dir", type=Path, default=Path("decomp/disasm/maincpu"))
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--work-dir", type=Path, default=Path("out/decomp/gcc_reasm"))
    ap.add_argument("--keep", action="store_true")
    ap.add_argument(
        "--mode",
        choices=("gas", "bytes"),
        default="bytes",
        help="Translator mode (bytes recommended for ROM verify)",
    )
    ap.add_argument(
        "--compare-gas",
        action="store_true",
        help="Also run gas reasm on single-slice runs",
    )
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    work_dir = args.work_dir if args.work_dir.is_absolute() else REPO_ROOT / args.work_dir

    if args.all:
        disasm_dir = args.disasm_dir if args.disasm_dir.is_absolute() else REPO_ROOT / args.disasm_dir
        report = gcc_reasm_all(
            disasm_dir=disasm_dir,
            work_dir=work_dir,
            rom_dir=args.rom_dir,
            keep_intermediates=args.keep,
            emit_mode=args.mode,
            compare_gas=False,
        )
        report_path = work_dir / "gcc_reasm_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        status = "PASS" if report["ok"] else "FAIL"
        print(f"GCC reasm {status} {report['passed']}/{report['total']} slices")
        print(f"  report → {report_path}")
        if not report["ok"]:
            for row in report["slices"]:
                if not row.get("match"):
                    if "error" in row:
                        print(f"  FAIL {row['slice_name']}: {row['error']}")
                    else:
                        print(
                            f"  FAIL {row['slice_name']} "
                            f"mismatch_bytes={row['mismatch_bytes']} ref={row.get('reference_source')}"
                        )
            raise SystemExit(1)
        return

    if args.slice is None:
        raise SystemExit("pass --slice or --all")

    slice_asm = args.slice if args.slice.is_absolute() else REPO_ROOT / args.slice
    if not slice_asm.is_file():
        raise SystemExit(f"slice not found: {slice_asm}")

    report = gcc_reasm_slice(
        slice_asm,
        work_dir=work_dir / slice_asm.stem,
        rom_dir=args.rom_dir,
        keep_intermediates=args.keep,
        emit_mode=args.mode,
        compare_gas=args.compare_gas,
    )
    report_path = args.report
    if report_path is None:
        report_path = work_dir / f"{slice_asm.stem}.json"
    elif not report_path.is_absolute():
        report_path = REPO_ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    status = "PASS" if report["match"] else "FAIL"
    print(f"GCC reasm {status} {slice_asm.name} @ {report['base']} len 0x{report['length']:x}")
    if report.get("gas_match") is not None:
        gas_status = "PASS" if report["gas_match"] else "FAIL"
        print(f"  gas cross-check: {gas_status}")
    print(f"  report → {report_path}")
    if not report["match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
