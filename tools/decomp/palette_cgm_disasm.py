#!/usr/bin/env python3
"""Disasm-backed CGM / g13 audit (no MAME captures).

Cross-checks Python ``0x1111`` replay assumptions against maincpu slices listed in
``palette_re.PALETTE_DISASM_TARGETS`` and documents open RE gaps when *all* high
colorbase materials look wrong (not just one atlas binding).

  python3 -m tools.decomp.palette_cgm_disasm
  python3 -m tools.decomp.palette_cgm_disasm --mask-sensitivity
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.palette_re import sample_geometry_colorbases
from tools.decomp.palette_cgm_stubs import build_stub_report
from tools.model2_cgm_1111 import CGM_RECORD_1111, replay_1111_record
from tools.model2_cgm_emit import build_emit_report, runtime_upload_paths
from tools.model2_cgm_g13_table import G13_CTRL_BITS, g13_mask_for_slot
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PALRAM_COLORBASE_WORD,
    PaletteState,
    find_cgm_blocks,
    load_palette_from_main_data,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Disasm-backed XOR / upload paths (see decomp/disasm/maincpu/maincpu_029c10_800.asm).
XOR_PATHS = (
    {
        "id": "2a258_batched",
        "rom": "0x2A258",
        "g13_setup": "0x2A234 setbit 6; 0x2A240 setbit 15 → g13=0x8040",
        "role": "# / batched staging XOR (g3>0 inner loop @ 0x2A200)",
        "python": "op_2a200_hash_batch → g13_hash_mask (seed|0x8040)",
        "open": "Inner loop uses fixed 0x8040; Python ORs seed — 4 desert slots differ",
    },
    {
        "id": "2a3ac_table",
        "rom": "0x2A3AC",
        "g13_setup": "g5=g13+(slot<<6); lda 0x8000(g5)[sub]",
        "role": "Format compile @ 0x2A370 fills per-slot masks from bus 0x8000 table",
        "python": "g13_mask_for_slot: 0x8040 [anchor,anchor+24) else (slot<<7)|0x8040",
        "open": "Table fill semantics @ 0x2A3E4 not statically present in ROM",
    },
    {
        "id": "29cd8_chain",
        "rom": "0x29CD8",
        "g13_setup": "g13 = or(staging_ctrl, chain.head_u16); ADD @ 0x29CFC",
        "role": "Compiled thunk path when g2==0 (@ 0x29D60 → 0x29E18)",
        "python": "ingest_u16_add uses g13_for_slot only — no OR with chain head",
        "open": "For XOR, effective mask may be 0x8040|(slot<<7) via head_u16 @ 29CD8",
    },
    {
        "id": "2a4e0_merge",
        "rom": "0x2A4E0",
        "g13_setup": "0x20C958 base + 0x20C95C–0x20C968 bounds",
        "role": "D/U path @ 0x2A62C: read-modify-write @ 0x01080000",
        "python": "op_2a4e0_merge (merge_raw / xor_merge modes — g0/g1 args incomplete)",
        "open": "Compiled D must publish g0/g1/g2 before 0x2A5A0; static 0x005FBF10 row g6=10 unknown",
    },
    {
        "id": "2a5a0_runner",
        "rom": "0x2A5A0",
        "g13_setup": "r5 bit 0 from setbit 0,r9 (@ 0x05D3DC D handler)",
        "role": "FIFO upload loop; bit0 set → 0x2A4E0, clear → r5 flag walk @ 0x2A630",
        "python": "Not executed — format-walk bypasses compiled thunks",
        "open": "Prove g0/g1 mapping from 0x05D860 emit bytecode → 0x2A6E8 wrappers",
    },
    {
        "id": "29e18_descriptor",
        "rom": "0x29E18",
        "g13_setup": "setbit 6 only → g13=0x40; index = descriptor - g13",
        "role": "Alternate batch decode (subo g4,g13 @ 0x29E48)",
        "python": "Not modeled in format-walk replay",
        "open": "May apply to compiled D batches, not direct FIFO walk",
    },
)


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def mask_sensitivity_report(main_data: bytes, needed: set[int]) -> dict:
    """Replay with alternate g13 masks; patch staging imports directly."""
    import tools.model2_cgm_staging as staging_mod

    payload = _desert_1111_payload(main_data)
    orig_mask = staging_mod.g13_mask_for_slot
    orig_hash = staging_mod.g13_hash_mask

    def replay(mask_fn, hash_fn) -> dict[int, int]:
        staging_mod.g13_mask_for_slot = mask_fn
        staging_mod.g13_hash_mask = hash_fn
        st = PaletteState()
        st._install_default_lumaram()
        part = replay_1111_record(st, payload)
        staging_mod.g13_mask_for_slot = orig_mask
        staging_mod.g13_hash_mask = orig_hash
        return part.slots_written

    baseline = replay(orig_mask, orig_hash)

    variants: list[tuple[str, object, object]] = [
        ("current", orig_mask, orig_hash),
        (
            "hash_fixed_8040",
            orig_mask,
            lambda _seed: G13_CTRL_BITS,
        ),
        (
            "d_flat_8040",
            lambda _s, slot, **_: G13_CTRL_BITS,
            orig_hash,
        ),
        (
            "d_slot6_or8040",
            lambda s, slot, **_: (
                G13_CTRL_BITS
                if slot < (s >> 7) + 24
                else ((slot & 0x3FF) << 6) | G13_CTRL_BITS
            ),
            orig_hash,
        ),
        (
            "d_or_head_8040",
            lambda _s, slot, **_: G13_CTRL_BITS | ((slot & 0x3FF) << 7),
            orig_hash,
        ),
        (
            "d_g13_40_only",
            lambda _s, slot, **_: 0x40,
            orig_hash,
        ),
    ]

    rows: list[dict] = []
    for label, mask_fn, hash_fn in variants:
        if label == "current":
            got = baseline
        else:
            got = replay(mask_fn, hash_fn)
        geom_diff = sorted(
            s
            for s in needed
            if (baseline.get(s, 0) & 0x7FFF) != (got.get(s, 0) & 0x7FFF)
        )
        total_diff = sum(
            1
            for s in set(baseline) | set(got)
            if (baseline.get(s, 0) & 0x7FFF) != (got.get(s, 0) & 0x7FFF)
        )
        rows.append(
            {
                "variant": label,
                "geometry_slot_diffs": len(geom_diff),
                "total_slot_diffs": total_diff,
                "example": [
                    {
                        "slot": s,
                        "current": f"0x{baseline.get(s, 0) & 0x7FFF:04x}",
                        "variant": f"0x{got.get(s, 0) & 0x7FFF:04x}",
                    }
                    for s in geom_diff[:4]
                ],
            }
        )
    return {"baseline_slots": len(baseline), "variants": rows}


def pipeline_audit(main_data: bytes, rom_dir: Path) -> dict:
    needed = sample_geometry_colorbases(rom_dir, max_placements=500)
    low = sorted(s for s in needed if s < 14)
    high = sorted(s for s in needed if s >= 14)

    state = load_palette_from_main_data(main_data)
    lumaram_rec = None
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == 0x0010:
            lumaram_rec = {
                "length": rec_len,
                "first_bytes": main_data[off : off + min(rec_len, 16)].hex(),
                "unique_bytes": sorted(set(main_data[off : off + rec_len])),
            }
            break

    leading = [
        slot
        for slot in range(1, 14)
        if state.palram[PALRAM_COLORBASE_WORD + slot] & 0x7FFF
    ]

    return {
        "geometry_colorbases": {
            "total": len(needed),
            "leading_slots_lt_14": len(low),
            "high_slots_ge_14": len(high),
            "note": "Desert track art overwhelmingly uses high slots filled only by 0x1111",
        },
        "leading_header_slots_populated": leading,
        "lumaram_cgm_record": lumaram_rec,
        "lumaram_apply_gap": (
            "Python copies type-0x0010 bytes to lumaram[0..len); hardware dispatches "
            "via 0x05CEC0 template @ 0x005C8BF0 (29C10 @ 0x29FE8). Dest base likely "
            "cursor-relative (<<7), not verified."
        ),
        "replay_gap": (
            "Python walks embedded format strings directly; hardware builds thunks @ "
            "0x005C9118 and dispatches 0x29C10 with chain nodes @ 0x20B950 (29CD8 OR "
            "head into g13). D emit @ 0x05D860 → 0x027008 → 0x027130 → 0x029958 is "
            "not executed — see d_emit_trace."
        ),
        "d_emit_trace": build_emit_report(),
        "upload_stubs": build_stub_report(),
        "d_bytecode_trace": "out/decomp/palette_d_emit_trace.json (python3 -m tools.decomp.palette_d_emit_trace)",
        "test_vectors_warning": (
            "decomp/notes/palette_test_vectors.json replay_slots_* are Python snapshots, "
            "not independent hardware oracles — passing palette_re does not prove hues."
        ),
    }


def build_report(*, mask_sensitivity: bool) -> dict:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    needed = sample_geometry_colorbases(rom_dir, max_placements=500)

    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "xor_paths": XOR_PATHS,
        "pipeline": pipeline_audit(main_data, rom_dir),
        "priority_re": [
            "Trace 0x05D860 emit bytecode → 0x2A6E8 wrapper g0/g1 for 0x2A4E0 merge",
            "Prove D runtime: 0x2A62C merge vs xor_table replay on tier-B vectors",
            "Prove 0x8000 table row values @ 0x2A3AC (vs inferred (slot<<7)|0x8040)",
            "Type 0x0010 lumaram: dest = f(0x20C950<<7) from 0x005C8BF0 thunk disasm",
            "Tier-B vectors: raw u16 @ bin_pos + disasm path → color15 (not replay snapshot)",
        ],
        "d_runtime_paths": runtime_upload_paths(),
    }
    if mask_sensitivity:
        report["mask_sensitivity"] = mask_sensitivity_report(main_data, needed)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="CGM g13 disasm audit report")
    parser.add_argument(
        "--mask-sensitivity",
        action="store_true",
        help="Replay desert 0x1111 with alternate g13 masks",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_cgm_disasm.json",
    )
    args = parser.parse_args()

    report = build_report(mask_sensitivity=args.mask_sensitivity)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.out}")

    pipe = report["pipeline"]["geometry_colorbases"]
    print(
        f"geometry colorbases: {pipe['total']} "
        f"(high≥14: {pipe['high_slots_ge_14']}, leading<14: {pipe['leading_slots_lt_14']})"
    )
    if args.mask_sensitivity:
        for row in report["mask_sensitivity"]["variants"]:
            print(
                f"  {row['variant']:20s} geom_diff={row['geometry_slot_diffs']:3d} "
                f"total_diff={row['total_slot_diffs']:3d}"
            )


if __name__ == "__main__":
    main()
