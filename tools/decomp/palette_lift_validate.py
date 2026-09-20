#!/usr/bin/env python3
"""Tier-validate lifted palette init (upload @ 0x3C80 + lumaram @ 0x4350).

Compares decomp_lift RAM dumps against disasm-backed reference simulators.
No MAME runtime captures — gamma scalars come from maincpu ROM mirrors.

Usage (manual dump + compare):
  cd decomp && make lift-viewer
  PYTHONPATH=. python3 -m tools.decomp.palette_lift_validate \\
      --dump decomp/build/lift/palette_state
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.lift_palette_state import load_lift_palette_state
from tools.decomp.palette_upload_ref import (
    WORKRAM_GAMMA_A,
    WORKRAM_GAMMA_B,
    compare_colorxlat,
    gamma_u32_from_maincpu,
    simulate_geo_palette_lut_upload,
)
from tools.model2_palette import COLORXLAT_WORDS, LUMARAM_BYTES
from tools.rom_io import resolve_rom_dir

DECOMP_ROOT = Path(__file__).resolve().parents[2] / "decomp"
LIFT_BIN = DECOMP_ROOT / "build" / "lift" / "decomp_lift"
DEFAULT_DUMP = DECOMP_ROOT / "build" / "lift" / "palette_state"


def _load_maincpu(repo_root: Path) -> bytes:
    for path in (
        repo_root / "out" / "i960" / "maincpu_deinterleaved.bin",
        repo_root / "decomp" / "out" / "i960" / "maincpu_deinterleaved.bin",
    ):
        if path.is_file():
            return path.read_bytes()
    raise SystemExit(f"maincpu ROM not found under {repo_root}/out/i960/")


def _run_lift_dump(dump_dir: Path, *, repo_root: Path) -> None:
    if not LIFT_BIN.is_file():
        raise SystemExit(f"run: cd decomp && make lift  (missing {LIFT_BIN})")
    dump_dir.mkdir(parents=True, exist_ok=True)
    env = {
        **dict(__import__("os").environ),
        "SEGAMOD2_ROOT": str(repo_root),
        "I960_CGM_SKIP_PY": "1",
        "I960_PALETTE_DUMP": "build/lift/palette_state",
    }
    subprocess.run(
        [str(LIFT_BIN), "--viewer", "track", "--course", "desert", "--palette-only"],
        cwd=str(DECOMP_ROOT),
        env=env,
        check=True,
    )


def _lumaram_summary(lu: bytes) -> dict:
    nz = sum(1 for b in lu[:LUMARAM_BYTES] if b)
    mean = sum(lu[:LUMARAM_BYTES]) / max(len(lu[:LUMARAM_BYTES]), 1)
    return {"nonzero_bytes": nz, "mean": round(mean, 3), "size": len(lu)}


def _sample_colorxlat_words(cx_bytes: bytes, indices: tuple[int, ...]) -> dict:
    out: dict[str, int] = {}
    for idx in indices:
        if idx * 2 + 1 < len(cx_bytes):
            out[str(idx)] = struct.unpack_from("<H", cx_bytes, idx * 2)[0]
    return out


def validate_palette_lift(
    dump_dir: Path,
    *,
    rom_dir: Path,
    maincpu: bytes | None = None,
    check_upload: bool = True,
) -> dict:
    maincpu = maincpu or _load_maincpu(Path(__file__).resolve().parents[2])
    gamma_a = gamma_u32_from_maincpu(maincpu, WORKRAM_GAMMA_A)
    gamma_b = gamma_u32_from_maincpu(maincpu, WORKRAM_GAMMA_B)

    ref_cx = simulate_geo_palette_lut_upload(gamma_a_u32=gamma_a, gamma_b_u32=gamma_b)
    lift_cx_path = dump_dir / "colorxlat.bin"
    if not lift_cx_path.is_file():
        raise SystemExit(f"missing {lift_cx_path}")
    lift_cx = lift_cx_path.read_bytes()[: len(ref_cx)]
    upload = (
        compare_colorxlat(lift_cx, ref_cx)
        if check_upload
        else {"tier": "skipped", "ok": True, "note": "lumaram-only pass"}
    )

    state, _ = load_lift_palette_state(dump_dir)
    lu_path = dump_dir / "lumaram.bin"
    lu_bytes = lu_path.read_bytes() if lu_path.is_file() else bytes(state.lumaram)

    # Spot-check: bank0 luma63 R/G/B word indices in colorxlat layout
    samples = _sample_colorxlat_words(lift_cx, (63, 0x2000 + 63, 0x4000 + 63))
    lu_summary = _lumaram_summary(lu_bytes)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dump_dir": str(dump_dir),
        "gamma_workram": {
            "0x5A2C70": f"0x{gamma_a:08X}",
            "0x5A2C74": f"0x{gamma_b:08X}",
            "gamma_a_f": round(struct.unpack("<f", struct.pack("<I", gamma_a))[0], 6),
            "gamma_b_f": round(struct.unpack("<f", struct.pack("<I", gamma_b))[0], 6),
        },
        "upload_0x3c80": {
            **upload,
            **(
                {
                    "tier": (
                        "effect_match_all_banks"
                        if upload.get("all_banks_ok")
                        else ("effect_match_bank0" if upload.get("bank0_ok") else "failed")
                    ),
                    "samples_bank0_luma63": samples,
                }
                if check_upload
                else {}
            ),
        },
        "lumaram_0x4350": {
            **lu_summary,
            "tier": "present" if lu_summary["nonzero_bytes"] > 100 else "sparse",
            "note": "geo_lumaram_init writes colorxlat; lumaram.bin fills @ 0x4590 pattern",
        },
        "ok": upload.get("ok", True) if check_upload else lu_summary["nonzero_bytes"] > 100,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--upload-skip", action="store_true", help="lumaram-only structural pass")
    ap.add_argument("-o", "--report", type=Path, default=Path("out/decomp/palette_lift_validate.json"))
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    rom_dir = resolve_rom_dir(args.rom_dir)
    dump_dir = args.dump.resolve()

    report = validate_palette_lift(
        dump_dir, rom_dir=rom_dir, check_upload=not args.upload_skip
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    up = report["upload_0x3c80"]
    lu = report["lumaram_0x4350"]
    print(
        f"palette_lift_validate: upload tier={up.get('tier', 'skipped')} "
        f"all_banks={up.get('all_banks_ok', 'n/a')} "
        f"bank0={up.get('bank0_ok', 'n/a')} "
        f"full_match={up.get('match_ratio', 0)*100:.1f}% "
        f"lumaram nz={lu['nonzero_bytes']}",
        file=sys.stderr,
    )
    if not args.upload_skip and not report["ok"]:
        print("bank0:", up.get("bank0_channels"), file=sys.stderr)
        print("post_bank0:", up.get("post_bank0_samples", [])[:4], file=sys.stderr)
        return 1
    if args.upload_skip and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
