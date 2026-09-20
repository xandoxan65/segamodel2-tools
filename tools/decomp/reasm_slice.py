#!/usr/bin/env python3
"""Assemble a MAME disasm slice via the i960 container and compare to ROM bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from tools.decomp.mame_to_gas960 import reference_bytes_from_mame, translate_file
from tools.i960_memory import MAINCPU_SIZE
from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_RUN = REPO_ROOT / "tooling/i960/container/run-decomp.sh"
LINK_SCRIPT = REPO_ROOT / "tooling/i960/link/maincpu-slice.ld"
SLICE_NAME = re.compile(r"^maincpu_([0-9a-f]+)_([0-9a-f]+)\.asm$", re.I)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_slice_path(path: Path) -> tuple[int, int]:
    match = SLICE_NAME.match(path.name)
    if not match:
        raise ValueError(f"expected maincpu_<addr>_<len>.asm, got {path.name}")
    base = int(match.group(1), 16)
    length = int(match.group(2), 16)
    return base, length


def repo_rel(path: Path) -> str:
    resolved = path if path.is_absolute() else REPO_ROOT / path
    return resolved.resolve().relative_to(REPO_ROOT.resolve()).as_posix()


def run_container(*args: str) -> None:
    if not CONTAINER_RUN.is_file():
        raise FileNotFoundError(f"missing container wrapper: {CONTAINER_RUN}")
    cmd = ["bash", str(CONTAINER_RUN), *args]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def extract_slice_blob(elf_rel: Path, base: int, length: int) -> bytes:
    """Return maincpu ROM bytes for [base, base+length) from a linked ELF."""
    bin_rel = elf_rel.with_suffix(".bin")
    run_container(
        "i960-elf-objcopy",
        "-O",
        "binary",
        "-j",
        ".text",
        repo_rel(elf_rel),
        repo_rel(bin_rel),
    )
    blob = (REPO_ROOT / bin_rel).read_bytes()
    if base + length > len(blob):
        raise ValueError(
            f"linked image too small: need 0x{base + length:x} bytes, got 0x{len(blob):x}"
        )
    return blob[base : base + length]


def count_mismatch_bytes(rebuilt: bytes, reference: bytes) -> int:
    span = max(len(rebuilt), len(reference))
    mismatches = abs(len(rebuilt) - len(reference))
    for index in range(min(len(rebuilt), len(reference))):
        if rebuilt[index] != reference[index]:
            mismatches += 1
    return mismatches


def slice_reference_bytes(
    slice_asm: Path,
    *,
    base: int,
    length: int,
    maincpu_raw: bytes,
) -> tuple[bytes, str]:
    """Return expected bytes and a short source tag (rom | mame)."""
    if base + length <= len(maincpu_raw):
        return maincpu_raw[base : base + length], "rom"
    text = slice_asm.read_text(encoding="utf-8", errors="replace")
    return reference_bytes_from_mame(text, slice_base=base, length=length), "mame"


def reasm_slice(
    slice_asm: Path,
    *,
    work_dir: Path,
    rom_dir: Path | None,
    keep_intermediates: bool = False,
    emit_mode: str = "gas",
) -> dict:
    base, length = parse_slice_path(slice_asm)
    work_dir.mkdir(parents=True, exist_ok=True)

    gas_path = work_dir / slice_asm.with_suffix(".s").name
    obj_path = work_dir / slice_asm.with_suffix(".o").name
    elf_path = work_dir / slice_asm.with_suffix(".elf").name

    maincpu_raw, _ = load_maincpu_words(resolve_rom_dir(rom_dir))
    reference, reference_source = slice_reference_bytes(
        slice_asm,
        base=base,
        length=length,
        maincpu_raw=maincpu_raw,
    )
    out_of_rom = base >= MAINCPU_SIZE

    stats = translate_file(
        slice_asm,
        gas_path,
        base_address=base,
        rom_slice=reference,
        slice_base=base,
        emit_mode=emit_mode,
    )

    run_container("i960-elf-as", "-AKB", "-o", repo_rel(obj_path), repo_rel(gas_path))
    run_container(
        "i960-elf-ld",
        "-T",
        repo_rel(LINK_SCRIPT),
        "-o",
        repo_rel(elf_path),
        repo_rel(obj_path),
    )

    rebuilt = extract_slice_blob(elf_path, base, length)
    match = rebuilt == reference

    if not keep_intermediates:
        for path in (gas_path, obj_path, elf_path, elf_path.with_suffix(".bin")):
            full = REPO_ROOT / path
            if full.is_file():
                full.unlink()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "slice": slice_asm.as_posix(),
        "base": f"0x{base:08x}",
        "length": length,
        "match": match,
        "reference_source": reference_source,
        "out_of_maincpu_rom": out_of_rom,
        "reference_sha256": sha256(reference),
        "rebuilt_sha256": sha256(rebuilt),
        "translation": stats,
        "mismatch_bytes": 0 if match else count_mismatch_bytes(rebuilt, reference),
    }


def iter_maincpu_slices(disasm_dir: Path) -> List[Path]:
    slices: List[Path] = []
    for path in sorted(disasm_dir.glob("maincpu_*.asm")):
        if path.is_file() and SLICE_NAME.match(path.name):
            slices.append(path)
    return slices


def reasm_all(
    *,
    disasm_dir: Path,
    work_dir: Path,
    rom_dir: Path | None,
    keep_intermediates: bool = False,
    emit_mode: str = "gas",
) -> dict:
    slices = iter_maincpu_slices(disasm_dir)
    results: List[dict] = []
    passed = 0
    for slice_asm in slices:
        try:
            row = reasm_slice(
                slice_asm,
                work_dir=work_dir / slice_asm.stem,
                rom_dir=rom_dir,
                keep_intermediates=keep_intermediates,
                emit_mode=emit_mode,
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
    ap = argparse.ArgumentParser(description="Reassemble MAME disasm slice and compare to ROM")
    ap.add_argument(
        "--slice",
        type=Path,
        default=None,
        help="Path to decomp/disasm/maincpu/maincpu_<addr>_<len>.asm",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Reassemble every maincpu_*.asm slice under --disasm-dir",
    )
    ap.add_argument(
        "--disasm-dir",
        type=Path,
        default=Path("decomp/disasm/maincpu"),
        help="Directory of MAME slices (with --all)",
    )
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=Path("out/decomp/reasm"),
        help="Intermediate gas/o/elf output directory",
    )
    ap.add_argument("--keep", action="store_true", help="Keep translated .s / .o / .elf")
    ap.add_argument(
        "--mode",
        choices=("gas", "bytes"),
        default="gas",
        help="Translator output mode (bytes = MAME hex only, best for verify)",
    )
    ap.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Write JSON report (default: out/decomp/reasm/<slice>.json)",
    )
    args = ap.parse_args()

    work_dir = args.work_dir if args.work_dir.is_absolute() else REPO_ROOT / args.work_dir

    if args.all:
        disasm_dir = args.disasm_dir if args.disasm_dir.is_absolute() else REPO_ROOT / args.disasm_dir
        report = reasm_all(
            disasm_dir=disasm_dir,
            work_dir=work_dir,
            rom_dir=args.rom_dir,
            keep_intermediates=args.keep,
            emit_mode=args.mode,
        )
        report_path = work_dir / "reasm_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        status = "PASS" if report["ok"] else "FAIL"
        print(f"Reasm {status} {report['passed']}/{report['total']} slices")
        print(f"  report → {report_path}")
        if not report["ok"]:
            for row in report["slices"]:
                if not row.get("match"):
                    if "error" in row:
                        print(f"  FAIL {row['slice_name']}: {row['error']}")
                    else:
                        src = row.get("reference_source", "?")
                        extra = " (workram — MAME reference)" if row.get("out_of_maincpu_rom") else ""
                        print(
                            f"  FAIL {row['slice_name']} mismatch_bytes={row['mismatch_bytes']}"
                            f" ref={src}{extra}"
                        )
            raise SystemExit(1)
        return

    if args.slice is None:
        raise SystemExit("pass --slice or --all")

    slice_asm = args.slice if args.slice.is_absolute() else REPO_ROOT / args.slice
    if not slice_asm.is_file():
        raise SystemExit(f"slice not found: {slice_asm}")

    work_dir = args.work_dir if args.work_dir.is_absolute() else REPO_ROOT / args.work_dir
    report_path = args.report
    if report_path is None:
        report_path = work_dir / f"{slice_asm.stem}.json"
    elif not report_path.is_absolute():
        report_path = REPO_ROOT / report_path

    report = reasm_slice(
        slice_asm,
        work_dir=work_dir / slice_asm.stem,
        rom_dir=args.rom_dir,
        keep_intermediates=args.keep,
        emit_mode=args.mode,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    status = "PASS" if report["match"] else "FAIL"
    print(f"Reasm {status} {slice_asm.name} @ {report['base']} len 0x{report['length']:x}")
    print(f"  report → {report_path}")
    if not report["match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
