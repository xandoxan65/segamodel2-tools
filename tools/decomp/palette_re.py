#!/usr/bin/env python3
"""Palette / CGM replay validation for decomp (static ROM replay only)."""

from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from tools.extract.textures import load_sheet_banks_from_main_data
from tools.model2_cgm import (
    CgmReplayState,
    missing_colorbase_slots,
    replay_course_cgm_blocks,
    replay_cgm_block,
)
from tools.i960_tracks import (
    COURSE_TRACK_EXPORTS,
    UI_COURSE_ORDER,
    collect_course_textured_mesh,
)
from tools.model2_catalog import parse_placement_stream
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PALETTE_ROM_FUNCTIONS,
    PALRAM_COLORBASE_WORD,
    PaletteState,
    find_cgm_blocks,
    load_colorxlat_from_rom,
    load_colorxlat_from_staging_mirror,
    load_palette_from_main_data,
    palette_report_dict,
)
from tools.model2_texture import parse_textured_placement, texture_u16_mask
from tools.obj_export import write_textured_obj
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

PALETTE_DISASM_TARGETS = (
    {"addr": 0x012D00, "name": "course_palette_init", "slice": "maincpu/maincpu_012d00_200.asm"},
    {"addr": 0x029C10, "name": "draw_scene_dispatch", "slice": "maincpu/maincpu_029c10_800.asm"},
    {"addr": 0x029EB0, "name": "catalog_draw_setup", "slice": "maincpu/maincpu_029eb0_600.asm"},
    {"addr": 0x029FAC, "name": "cgm_record_loop", "slice": "maincpu/maincpu_029f7c_100.asm"},
    {"addr": 0x02A050, "name": "cgm_leading_colorbase", "slice": "maincpu/maincpu_02a050_150.asm"},
    {"addr": 0x02A0F8, "name": "cgm_record_dispatch", "slice": "maincpu/maincpu_02a0f8_400.asm"},
    {"addr": 0x02A120, "name": "cgm_1111_flush", "slice": "maincpu/maincpu_02a120_e0.asm"},
    {"addr": 0x02A200, "name": "palram_batch_upload", "slice": "maincpu/maincpu_02a0f8_400.asm"},
    {"addr": 0x02A490, "name": "palram_scratch_write", "slice": "maincpu/maincpu_02a0f8_400.asm"},
    {"addr": 0x02A4E0, "name": "palram_bus_merge", "slice": "maincpu/maincpu_02a4e0_120.asm"},
    {"addr": 0x02A5A0, "name": "fifo_upload_runner", "slice": "maincpu/maincpu_02a5a0_2b0.asm"},
    {"addr": 0x026918, "name": "palram_colorbase_upload", "slice": "maincpu/maincpu_026918_80.asm"},
    {"addr": 0x05CE18, "name": "libc_scanf_setup", "slice": "maincpu/maincpu_05ce18_300.asm"},
    {"addr": 0x05CEC0, "name": "libc_printf", "slice": "maincpu/maincpu_05cec0_*.asm"},
    {"addr": 0x05CF50, "name": "libc_printf_dispatch", "slice": "maincpu/maincpu_05cf50_a00.asm"},
)

WORKRAM_THUNKS = (
    {"vaddr": 0x005C8E60, "role": "scanf_thunk_staging", "builder": "0x05CE18 / 0x05CEC0"},
    {"vaddr": 0x005C9118, "role": "format_read_thunks", "builder": "0x05CF50 @ CGM parse"},
)

TEST_VECTORS_PATH = Path("decomp/notes/palette_test_vectors.json")


def validate_test_vectors(
    rom_dir: Path,
    repo_root: Path,
    state: PaletteState,
) -> dict:
    """Compare replay against ROM-derived vectors in decomp/notes/palette_test_vectors.json."""
    path = repo_root / TEST_VECTORS_PATH
    if not path.is_file():
        return {"available": False, "path": str(path)}

    vectors = json.loads(path.read_text(encoding="utf-8"))
    from tools.model2_palette import COLORXLAT_DEF_SCALE, _build_colorxlat_bank_from_def

    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    mismatches: list[dict] = []
    matches = 0

    for slot, expected_hex in vectors.get("leading_slots_header", {}).items():
        slot_i = int(slot)
        expected = int(expected_hex, 16)
        actual = state.palram[PALRAM_COLORBASE_WORD + slot_i] & 0x7FFF
        if actual == expected:
            matches += 1
        else:
            mismatches.append(
                {
                    "check": "leading_slot",
                    "slot": slot_i,
                    "expected": expected_hex,
                    "actual": f"0x{actual:04x}",
                }
            )

    for slot, expected_hex in vectors.get("replay_slots_14_29", {}).items():
        slot_i = int(slot)
        expected = int(expected_hex, 16)
        actual = state.palram[PALRAM_COLORBASE_WORD + slot_i] & 0x7FFF
        if actual == expected:
            matches += 1
        else:
            mismatches.append(
                {
                    "check": "replay_slot_1111",
                    "slot": slot_i,
                    "expected": expected_hex,
                    "actual": f"0x{actual:04x}",
                }
            )

    for slot, expected_hex in vectors.get("replay_slots_high", {}).items():
        slot_i = int(slot)
        expected = int(expected_hex, 16)
        actual = state.palram[PALRAM_COLORBASE_WORD + slot_i] & 0x7FFF
        if actual == expected:
            matches += 1
        else:
            mismatches.append(
                {
                    "check": "replay_slot_high",
                    "slot": slot_i,
                    "expected": expected_hex,
                    "actual": f"0x{actual:04x}",
                }
            )

    r, g, b = _build_colorxlat_bank_from_def(main_data, 0, scale=COLORXLAT_DEF_SCALE)
    for channel, lane, expected in (
        ("r", r, vectors.get("colorxlat_bank0_r_first16", [])),
        ("g", g, vectors.get("colorxlat_bank0_g_first16", [])),
        ("b", b, vectors.get("colorxlat_bank0_b_first16", [])),
    ):
        for i, exp in enumerate(expected[:16]):
            if i < len(lane) and lane[i] == exp:
                matches += 1
            else:
                act = lane[i] if i < len(lane) else None
                mismatches.append(
                    {
                        "check": f"colorxlat_bank0_{channel}",
                        "index": i,
                        "expected": exp,
                        "actual": act,
                    }
                )

    return {
        "available": True,
        "path": str(path),
        "matches": matches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:16],
        "ok": len(mismatches) == 0,
    }


def _words_from_bytes(raw: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def colorxlat_source_for_main_data(main_data: bytes) -> str:
    """Report which colorxlat path load_palette_from_main_data uses (ROM replay)."""
    probe = PaletteState()
    if load_colorxlat_from_rom(probe, main_data):
        return "rom_def"
    if load_colorxlat_from_staging_mirror(probe, main_data):
        return "staging_mirror"
    return "default_linear"


def refresh_textured_course_exports(
    rom_dir: Path,
    scenes_dir: Path,
    *,
    course_ids: tuple[str, ...] | None = None,
) -> list[Path]:
    """Re-bake palette_cache PNGs and textured OBJ/MTL for course tracks."""
    main_data_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    main_data = _words_from_bytes(main_data_raw)
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = _words_from_bytes(poly_raw)
    tex_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    texture_rom = _words_from_bytes(tex_raw)
    tex_mask = texture_u16_mask(len(texture_rom))
    texture_sheets = load_sheet_banks_from_main_data(main_data_raw)
    master_placements = parse_placement_stream(
        main_data,
        polygon_rom,
        polygon_rom_mask=len(polygon_rom) - 1,
    )

    tracks_dir = scenes_dir / "tracks"
    tracks_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    targets = course_ids or tuple(UI_COURSE_ORDER)
    for course_id in targets:
        spec = COURSE_TRACK_EXPORTS.get(course_id)
        if spec is None:
            continue
        palette_state = load_palette_from_main_data(main_data_raw, course_id=course_id)
        ranges = [(int(a), int(b)) for a, b in spec["placement_ranges"]]
        tex_verts, tex_prims, _ = collect_course_textured_mesh(
            master_placements,
            polygon_rom,
            texture_rom,
            ranges,
            exclude_ambient_env=bool(spec.get("exclude_ambient_env")),
            texture_mask=tex_mask,
        )
        if not tex_prims:
            continue
        tex_path = tracks_dir / f"track_{course_id}_textured.obj"
        palette_cache = scenes_dir.parent / "textures" / "palette_cache" / course_id
        write_textured_obj(
            tex_path,
            tex_verts,
            tex_prims,
            mtl_name="sheet0",
            material_by_sheet={0: "sheet0", 1: "sheet1"},
            palette=palette_state,
            texture_sheets=texture_sheets,
            palette_cache_dir=palette_cache,
            out_root=scenes_dir.parent,
            index_sheets_only=False,
        )
        written.extend([tex_path, tex_path.with_suffix(".mtl")])
    return written


def sample_geometry_colorbases(rom_dir: Path, *, max_placements: int = 200) -> set[int]:
    """Collect colorbase indices referenced by textured placement stream polys."""
    main_data = _words_from_bytes(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = _words_from_bytes(poly_raw)
    tex_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["textures"])
    texture_rom = _words_from_bytes(tex_raw)
    poly_mask = len(polygon_rom) - 1
    tex_mask = texture_u16_mask(len(texture_rom))

    placements = parse_placement_stream(main_data, polygon_rom, polygon_rom_mask=poly_mask)
    needed: set[int] = set()
    for rec in placements[:max_placements]:
        col = parse_textured_placement(
            polygon_rom,
            texture_rom,
            matrix=rec.matrix,
            rom_offset=rec.rom_offset,
            obc=rec.obc,
            tpa=rec.tpa,
            tha=rec.tha,
            texture_mask=tex_mask,
        )
        if not col:
            continue
        for prim in col.textured_primitives:
            needed.add(prim.colorbase)
    return needed


def replay_course_detailed(main_data: bytes) -> dict:
    """Per-block CGM replay stats for desert course init path."""
    state = PaletteState()
    state._install_default_lumaram()
    blocks = find_cgm_blocks(main_data)
    by_vaddr = {b.vaddr: b for b in blocks}
    course_blocks = tuple(by_vaddr[v] for v in COURSE_CGM_VADDRS if v in by_vaddr)
    replay = CgmReplayState()
    per_block: list[dict] = []

    for block in course_blocks:
        rec_before = len(replay.records_applied)
        slots_before = len(replay.colorbase_by_slot)
        replay = replay_cgm_block(state, main_data, block, replay)
        per_block.append(
            {
                "vaddr": f"0x{block.vaddr:08x}",
                "version": block.version,
                "leading_slots_added": len(replay.colorbase_by_slot) - slots_before,
                "records_applied": [
                    {"type": f"0x{t:04x}", "length": length}
                    for t, length in replay.records_applied[rec_before:]
                ],
                "replay_1111_slots": len(replay.replay_1111_slots),
                "replay_1111_errors": len(replay.replay_1111_errors),
            }
        )

    return {
        "course_blocks": [f"0x{v:08x}" for v in COURSE_CGM_VADDRS],
        "blocks_replayed": len(course_blocks),
        "colorbase_slots_filled": len(replay.colorbase_by_slot),
        "replay_1111_slots": len(replay.replay_1111_slots),
        "pending_1111_bytes": replay.pending_1111_bytes,
        "replay_1111_errors": replay.replay_1111_errors[:8],
        "per_block": per_block,
        "replay": replay,
    }


def disasm_coverage_for_palette(repo_root: Path) -> list[dict]:
    manifest_path = repo_root / "decomp/disasm/manifest.json"
    slice_files: set[str] = set()
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        slice_files = {row["file"] for row in manifest.get("slices", [])}

    rows: list[dict] = []
    for target in PALETTE_DISASM_TARGETS:
        pattern = target["slice"]
        covered = False
        if pattern:
            if "*" in pattern:
                prefix = pattern.split("*", 1)[0]
                covered = any(f.startswith(prefix) for f in slice_files)
            else:
                covered = pattern in slice_files
        rows.append({**target, "addr": f"0x{target['addr']:06x}", "disasm_covered": covered})
    return rows


def build_palette_re_report(rom_dir: Path, *, repo_root: Path) -> dict:
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    base = palette_report_dict(main_data)
    detailed = replay_course_detailed(main_data)
    replay: CgmReplayState = detailed["replay"]
    state = load_palette_from_main_data(main_data)

    needed = sample_geometry_colorbases(rom_dir)
    missing = missing_colorbase_slots(replay, needed)
    high_slots = sorted(s for s in needed if s >= 14)
    missing_high = sorted(s for s in missing if s >= 14)

    disasm = disasm_coverage_for_palette(repo_root)
    disasm_missing = [r["name"] for r in disasm if not r["disasm_covered"]]
    test_vectors = validate_test_vectors(rom_dir, repo_root, state)

    ok_static = (
        len(missing_high) == 0
        and detailed["pending_1111_bytes"] == 0
        and test_vectors.get("ok", True)
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": ok_static,
        "ok_static": ok_static,
        "validation_level": "static_replay",
        "pipeline": base["pipeline"],
        "colorxlat_source": colorxlat_source_for_main_data(main_data),
        "course_cgm": {
            "vaddrs": [f"0x{v:08x}" for v in COURSE_CGM_VADDRS],
            "blocks_replayed": detailed["blocks_replayed"],
            "per_block": detailed["per_block"],
        },
        "replay": {
            "colorbase_slots_filled": detailed["colorbase_slots_filled"],
            "replay_1111_slots": detailed["replay_1111_slots"],
            "pending_1111_bytes": detailed["pending_1111_bytes"],
            "replay_1111_errors": detailed["replay_1111_errors"],
        },
        "geometry_demand": {
            "placements_sampled": 200,
            "colorbases_seen": len(needed),
            "colorbases_high_slots_ge_14": len(high_slots),
            "missing_slots": missing[:64],
            "missing_high_slots": missing_high[:64],
            "missing_high_count": len(missing_high),
        },
        "disasm_targets": disasm,
        "disasm_gaps": disasm_missing,
        "test_vectors": test_vectors,
        "blocking": [
            item
            for item in (
                "cgm_1111_replay_incomplete" if missing_high else None,
                "pending_1111_bytes" if detailed["pending_1111_bytes"] else None,
                "test_vector_mismatch" if test_vectors.get("available") and not test_vectors.get("ok") else None,
                "disasm_gaps:" + ",".join(disasm_missing) if disasm_missing else None,
            )
            if item
        ],
        "workram_thunks": WORKRAM_THUNKS,
        "rom_functions": base["rom_functions"],
        "palram_samples": base["palram_colorbase_samples"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Palette/CGM replay validation report")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, default=Path("out/decomp/palette_report.json"))
    ap.add_argument(
        "--refresh-textured",
        action="store_true",
        help="Re-bake textured track OBJ/MTL and palette_cache PNGs",
    )
    ap.add_argument(
        "--course",
        action="append",
        default=None,
        help="Limit --refresh-textured to course id(s), e.g. desert",
    )
    args = ap.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    repo_root = args.repo_root.resolve()

    if args.refresh_textured:
        course_ids = tuple(args.course) if args.course else None
        paths = refresh_textured_course_exports(
            rom_dir,
            repo_root / "out/scenes",
            course_ids=course_ids,
        )
        print(f"Refreshed {len(paths)} textured export file(s)")

    report = build_palette_re_report(rom_dir, repo_root=repo_root)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    level = report["validation_level"]
    missing_high = report["geometry_demand"]["missing_high_count"]
    filled = report["course_cgm"]["blocks_replayed"]
    print(
        f"Wrote {args.out} ({level}: {filled} CGM blocks, "
        f"{missing_high} missing high slots, ok={report['ok']})"
    )
    if report["blocking"]:
        print("Blocking:", "; ".join(report["blocking"]))


if __name__ == "__main__":
    main()
