#!/usr/bin/env python3
"""Compile hand C via i960-elf-gcc, peephole .s, assemble, compare to ROM slice (tier 3)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.gcc_peephole import peephole_i960_gas
from tools.decomp.i960_gcc_flags import i960_gcc_flags
from tools.decomp.reasm_slice import (
    LINK_SCRIPT,
    REPO_ROOT,
    repo_rel,
    run_container,
    sha256,
)
from tools.decomp.asm_rom_diff import compare_bytes
from tools.i960_scan import load_maincpu_words
from tools.rom_io import resolve_rom_dir

ROM_SPEC = re.compile(
    r"^0x([0-9a-f]+)(?::0x([0-9a-f]+)|:([0-9]+))?$",
    re.I,
)


def parse_rom_spec(spec: str) -> tuple[int, int]:
    match = ROM_SPEC.match(spec.strip())
    if not match:
        raise ValueError(f"expected --rom 0x<base>:0x<len> or 0x<base>:<decimal>, got {spec!r}")
    base = int(match.group(1), 16)
    if match.group(2):
        length = int(match.group(2), 16)
    else:
        length = int(match.group(3))
    if length <= 0:
        raise ValueError(f"ROM slice length must be positive, got {length}")
    return base, length


def extract_text_blob(elf_rel: Path, *, offset: int, length: int) -> bytes:
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
    end = offset + length
    if end > len(blob):
        raise ValueError(
            f"linked .text too small: need 0x{end:x} bytes at offset 0x{offset:x}, "
            f"got 0x{len(blob):x}"
        )
    return blob[offset : end]


def c_reasm_slice(
    c_source: Path,
    *,
    rom_base: int,
    rom_length: int,
    work_dir: Path,
    rom_dir: Path | None,
    keep_intermediates: bool = False,
    skip_peephole: bool = False,
    gcc_extra: list[str] | None = None,
) -> dict:
    work_dir.mkdir(parents=True, exist_ok=True)
    stem = c_source.stem

    raw_s = work_dir / f"{stem}.gcc.s"
    patched_s = work_dir / f"{stem}.s"
    obj_path = work_dir / f"{stem}.o"
    elf_path = work_dir / f"{stem}.elf"

    maincpu_raw, _ = load_maincpu_words(resolve_rom_dir(rom_dir))
    if rom_base + rom_length > len(maincpu_raw):
        raise ValueError(
            f"ROM slice 0x{rom_base:x}+0x{rom_length:x} exceeds maincpu image 0x{len(maincpu_raw):x}"
        )
    reference = maincpu_raw[rom_base : rom_base + rom_length]

    gcc_flags = i960_gcc_flags(gcc_extra)
    run_container(
        "i960-elf-gcc",
        *gcc_flags,
        "-S",
        "-o",
        repo_rel(raw_s),
        repo_rel(c_source if c_source.is_absolute() else REPO_ROOT / c_source),
    )

    raw_text = raw_s.read_text(encoding="utf-8", errors="replace")
    if skip_peephole:
        patched_text = raw_text
        rules_applied: list[str] = []
    else:
        patched_text, rules_applied = peephole_i960_gas(raw_text)
    patched_s.write_text(patched_text, encoding="utf-8")

    run_container("i960-elf-as", "-AKB", "-o", repo_rel(obj_path), repo_rel(patched_s))
    run_container(
        "i960-elf-ld",
        "-T",
        repo_rel(LINK_SCRIPT),
        "-o",
        repo_rel(elf_path),
        repo_rel(obj_path),
    )

    rebuilt = extract_text_blob(elf_path, offset=0, length=rom_length)
    match = rebuilt == reference
    diff_report = compare_bytes(reference, rebuilt, base=rom_base)

    if not keep_intermediates:
        for path in (
            raw_s,
            patched_s,
            obj_path,
            elf_path,
            elf_path.with_suffix(".bin"),
        ):
            if path.is_file():
                path.unlink()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tier": 3,
        "source_c": c_source.as_posix(),
        "rom_base": f"0x{rom_base:08x}",
        "rom_length": rom_length,
        "match": match,
        "reference_sha256": sha256(reference),
        "rebuilt_sha256": sha256(rebuilt),
        "mismatch_bytes": diff_report["mismatch_bytes"],
        "first_diff": diff_report.get("first_diff"),
        "gcc_flags": gcc_flags,
        "peephole": {
            "enabled": not skip_peephole,
            "rules_applied": rules_applied,
        },
        "linked_text_size": len(rebuilt),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="C → gcc -S → peephole → i960-elf-as; compare to maincpu ROM bytes"
    )
    ap.add_argument("--c", type=Path, required=True, dest="c_source", help="Hand C source")
    ap.add_argument(
        "--rom",
        required=True,
        help="ROM slice as 0x<base>:0x<len> (hex) or 0x<base>:<decimal>",
    )
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=Path("out/decomp/c_reasm"),
    )
    ap.add_argument("--keep", action="store_true", help="Keep .s/.o/.elf intermediates")
    ap.add_argument("--no-peephole", action="store_true", help="Assemble raw gcc -S output")
    ap.add_argument(
        "--gcc-extra",
        action="append",
        default=[],
        metavar="FLAG",
        help="Extra flag(s) passed to i960-elf-gcc after I960_GCC_FLAGS",
    )
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    c_source = args.c_source if args.c_source.is_absolute() else REPO_ROOT / args.c_source
    if not c_source.is_file():
        raise SystemExit(f"C source not found: {c_source}")

    try:
        rom_base, rom_length = parse_rom_spec(args.rom)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    work_dir = args.work_dir if args.work_dir.is_absolute() else REPO_ROOT / args.work_dir
    work_dir = work_dir / c_source.stem

    report = c_reasm_slice(
        c_source,
        rom_base=rom_base,
        rom_length=rom_length,
        work_dir=work_dir,
        rom_dir=args.rom_dir,
        keep_intermediates=args.keep,
        skip_peephole=args.no_peephole,
        gcc_extra=args.gcc_extra or None,
    )

    report_path = args.report
    if report_path is None:
        report_path = work_dir / f"{c_source.stem}.json"
    elif not report_path.is_absolute():
        report_path = REPO_ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    status = "PASS" if report["match"] else "FAIL"
    rules = report["peephole"]["rules_applied"]
    peephole_note = f" peephole={rules}" if rules else ""
    print(
        f"C-reasm {status} {c_source.name} @ {report['rom_base']} "
        f"len 0x{report['rom_length']:x}{peephole_note}"
    )
    print(f"  report → {report_path}")
    if not report["match"]:
        print(f"  mismatch_bytes={report['mismatch_bytes']}")
        first = report.get("first_diff")
        if first:
            print(
                f"  first_diff @ {first.get('rom_addr')} "
                f"rom={first.get('rom_byte')} got={first.get('got_byte')}"
            )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
