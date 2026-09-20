"""Track / scene tables from i960 RE (static ROM + optional MAME workram dumps)."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

from tools.i960_memory import (
    CATALOG_INDEX_TABLE,
    COURSE_SELECT_INDEX,
    COURSE_VARIANT_INDEX,
    GEO_WORKRAM_WRITE_PTR,
    PLACEMENT_CURSOR,
    SCENE_BATCH_INDEX,
    SCENE_METADATA_TABLE,
    SCENE_ROOT_TABLE_ROM,
)
from tools.i960_scan import load_maincpu_words
from tools.model2_scenes import (
    CPU_SCENE_ANCHORS,
    DRAW_SCRIPT_VADDR,
    parse_cpu_draw_entries,
    parse_draw_script,
)
from tools.model2_texture import texture_u16_mask
from tools.rom_io import load32_word_region, resolve_rom_dir, u32_words, SRALLY_DATA_ROMS

# Menu course titles in maincpu program ROM (not main_data track object names).
UI_COURSE_STRINGS_ROM: dict[str, int] = {
    "desert": 0x0000_9B70,
    "forest": 0x0000_9B90,
    "mountain": 0x0000_9BB0,
    "championship": 0x0000_9BD0,
}

UI_COURSE_ORDER = ("desert", "forest", "mountain", "championship")

# Static placement-stream slices for the four menu courses.
# Each course activates a subset of the shared race draw script @ 0x28656C0.
# Mapping is heuristic (four major geometry batches in script order) until
# workram capture confirms catalog dispatch per course.
COURSE_TRACK_EXPORTS: dict[str, dict[str, object]] = {
    "desert": {
        "title": "Desert Course",
        "track_object": "DESERT16",
        "placement_ranges": [(9, 110)],
        "draw_batches": ["geometry_batch_a"],
        "confidence": "heuristic",
        "note": (
            "Placements 9–110 (geometry_batch_a). Menu index 0 · scene pool @ 0x005CA580."
        ),
    },
    "forest": {
        "title": "Forest Course",
        "track_object": "FOREST16",
        # Contiguous segment_04 tail + segment_05 in one object-local frame.
        "placement_ranges": [(156, 205)],
        "excluded_placement_ranges": [(110, 139), (139, 156)],
        "draw_batches": ["segment_04 (tail)", "segment_05"],
        "confidence": "heuristic",
        "note": (
            "Placements 156–205 (segment_04 tail + segment_05). Viewer merges opening stretch "
            "[110:138] from track_forest_opening (detached local frame). Prop cluster [139:156] excluded. "
            "Menu index 1 · pool @ 0x005E3540."
        ),
    },
    "mountain": {
        "title": "Mountain Course",
        "track_object": "MOUNTAIN16",
        # Main geometry_batch_b chain; prefix/tail sit in separate local frames.
        "placement_ranges": [(277, 337)],
        "excluded_placement_ranges": [(246, 277), (337, 352)],
        "draw_batches": ["geometry_batch_b (core)"],
        "confidence": "heuristic",
        "note": (
            "Placements 277–337 — core geometry_batch_b chain. "
            "Excludes detached prefix [246:276] and tail [338:351]. "
            "Menu index 2 · pool @ 0x005CA6D0."
        ),
    },
    "championship": {
        "title": "Championship",
        "track_object": "LAKESIDE16 / CHAMP_TOP16",
        "placement_ranges": [(382, 511)],
        "draw_batches": ["geometry_batch_c"],
        "confidence": "heuristic",
        "note": (
            "Placements 382–511 (geometry_batch_c). Menu index 3 · multi-leg pool @ 0x005CAAE0. "
            "Excludes placement 456 (ambient env decagon rings @ ROM 0x9ACA84)."
        ),
        "exclude_ambient_env": True,
    },
}

# Detached placement spans that belong to a course but sit in a separate object-local frame.
# Exported as standalone OBJs (like track_ambient_env_rings) — do not merge into course exports.
COURSE_TRACK_SUPPLEMENTS: dict[str, list[dict[str, object]]] = {
    "forest": [
        {
            "id": "track_forest_opening",
            "title": "Forest opening stretch",
            "track_object": "FOREST16",
            "placement_ranges": [(110, 139)],
            "draw_batches": ["segment_04 (head)"],
            "role": "detached_segment",
            "confidence": "heuristic",
            "note": (
                "Placements 110–138 (segment_04 head). ~185-unit centroid gap to main body @ pl 156; "
                "prop cluster [139:156] at origin sits between them in the draw script."
            ),
        },
    ],
}


def collect_course_track_vertices(
    placements: list,
    ranges: list[tuple[int, int]],
    *,
    exclude_ambient_env: bool = False,
) -> tuple[list[tuple[float, float, float]], list[dict[str, object]]]:
    """Gather object-local vertices for a course, optionally skipping env-map rings."""
    from tools.model2_placements import is_ambient_env_ring_placement

    verts: list[tuple[float, float, float]] = []
    excluded: list[dict[str, object]] = []
    for lo, hi in ranges:
        for rec in placements[lo:hi]:
            if exclude_ambient_env and is_ambient_env_ring_placement(rec):
                excluded.append(
                    {
                        "placement_index": rec.placement_index,
                        "oba": f"0x{rec.oba:08x}",
                        "vertices": len(rec.vertices),
                        "role": "ambient_env_ring",
                    }
                )
                continue
            verts.extend(rec.vertices)
    return verts, excluded


def collect_course_track_mesh(
    placements: list,
    polygon_rom: list[int],
    ranges: list[tuple[int, int]],
    *,
    exclude_ambient_env: bool = False,
) -> tuple[
    list[tuple[float, float, float]],
    list[tuple[int, ...]],
    list[tuple[float, float, float]],
    list[dict[str, object]],
]:
    """Gather vertices + faces + MAME normals for mesh export."""
    from tools.model2_placements import apply_placement_mesh, is_ambient_env_ring_placement

    verts: list[tuple[float, float, float]] = []
    faces: list[tuple[int, ...]] = []
    face_normals: list[tuple[float, float, float]] = []
    excluded: list[dict[str, object]] = []
    for lo, hi in ranges:
        for rec in placements[lo:hi]:
            if exclude_ambient_env and is_ambient_env_ring_placement(rec):
                excluded.append(
                    {
                        "placement_index": rec.placement_index,
                        "oba": f"0x{rec.oba:08x}",
                        "vertices": len(rec.vertices),
                        "role": "ambient_env_ring",
                    }
                )
                continue
            hit = apply_placement_mesh(
                polygon_rom,
                matrix=rec.matrix,
                rom_offset=rec.rom_offset,
                obc=rec.obc,
            )
            if hit is None:
                verts.extend(rec.vertices)
                continue
            local_verts, local_faces, local_normals = hit
            base = len(verts)
            verts.extend(local_verts)
            for face, normal in zip(local_faces, local_normals):
                if len(face) >= 3:
                    faces.append(tuple(base + i for i in face))
                    face_normals.append(normal)
    return verts, faces, face_normals, excluded


def merge_textured_collectors(
    collectors: list,
) -> tuple[list[tuple[float, float, float]], list]:
    """Concatenate TexturedMeshCollector outputs with rebased face indices."""
    from tools.model2_texture import TexturedPrimitive

    vertices: list[tuple[float, float, float]] = []
    primitives: list[TexturedPrimitive] = []
    for col in collectors:
        base = len(vertices)
        vertices.extend(col.vertices)
        for prim in col.textured_primitives:
            primitives.append(
                TexturedPrimitive(
                    indices=tuple(base + i for i in prim.indices),
                    attr=prim.attr,
                    uvs=prim.uvs,
                    sheet_index=prim.sheet_index,
                    colorbase=prim.colorbase,
                    lumabase=prim.lumabase,
                    renderer=prim.renderer,
                    translucent=prim.translucent,
                    checker=prim.checker,
                    patch_x=prim.patch_x,
                    patch_y=prim.patch_y,
                    patch_w=prim.patch_w,
                    patch_h=prim.patch_h,
                )
            )
    return vertices, primitives


def collect_course_textured_mesh(
    placements: list,
    polygon_rom: list[int],
    texture_rom: list[int],
    ranges: list[tuple[int, int]],
    *,
    exclude_ambient_env: bool = False,
    texture_mask: int | None = None,
) -> tuple[
    list[tuple[float, float, float]],
    list,
    list[dict[str, object]],
]:
    """Gather vertices + textured primitives (MAME-culled UVs) for textured OBJ export."""
    from tools.model2_placements import is_ambient_env_ring_placement
    from tools.model2_texture import TexturedMeshCollector, parse_textured_placement

    tex_mask = texture_u16_mask(len(texture_rom)) if texture_mask is None else texture_mask
    collectors: list[TexturedMeshCollector] = []
    excluded: list[dict[str, object]] = []
    for lo, hi in ranges:
        for rec in placements[lo:hi]:
            if exclude_ambient_env and is_ambient_env_ring_placement(rec):
                excluded.append(
                    {
                        "placement_index": rec.placement_index,
                        "oba": f"0x{rec.oba:08x}",
                        "vertices": len(rec.vertices),
                        "role": "ambient_env_ring",
                    }
                )
                continue
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
            if col and col.textured_primitives:
                collectors.append(col)
    if not collectors:
        return [], [], excluded
    return (*merge_textured_collectors(collectors), excluded)


def collect_course_track_point_cloud(
    placements: list,
    polygon_rom: list[int],
    ranges: list[tuple[int, int]],
    *,
    exclude_ambient_env: bool = False,
    dedupe: bool = False,
) -> tuple[list[tuple[float, float, float]], list[dict[str, object]]]:
    """Dense point cloud from mesh face corners (strip verts alone are too sparse)."""
    from tools.model2_placements import apply_placement_mesh, is_ambient_env_ring_placement

    points: list[tuple[float, float, float]] = []
    seen: set[tuple[float, float, float]] = set()
    excluded: list[dict[str, object]] = []

    def add_point(v: tuple[float, float, float]) -> None:
        if dedupe:
            key = (round(v[0], 4), round(v[1], 4), round(v[2], 4))
            if key in seen:
                return
            seen.add(key)
        points.append(v)

    for lo, hi in ranges:
        for rec in placements[lo:hi]:
            if exclude_ambient_env and is_ambient_env_ring_placement(rec):
                excluded.append(
                    {
                        "placement_index": rec.placement_index,
                        "oba": f"0x{rec.oba:08x}",
                        "vertices": len(rec.vertices),
                        "role": "ambient_env_ring",
                    }
                )
                continue
            hit = apply_placement_mesh(
                polygon_rom,
                matrix=rec.matrix,
                rom_offset=rec.rom_offset,
                obc=rec.obc,
            )
            if hit is None:
                for v in rec.vertices:
                    add_point(v)
                continue
            local_verts, local_faces, _local_normals = hit
            for face in local_faces:
                for idx in face:
                    if 0 <= idx < len(local_verts):
                        add_point(local_verts[idx])
    return points, excluded


# main_data track object label prefixes (FOREST16, DESERT16, …).
TRACK_OBJECT_PREFIXES = ("DESERT", "FOREST", "MOUNTAIN", "LAKESIDE")

WORKRAM_DUMP_NAMES = (
    "workram_5b4340.bin",
    "workram_5b375c.bin",
    "workram_20a8c4.bin",
    "workram_215380.bin",
    "workram_5b36e0.bin",
    "workram_5ca210.bin",
    "workram_20b940.bin",
)


@dataclass
class SceneRootEntry:
    index: int
    workram_vaddr: int
    rom_table_offset: int


@dataclass
class AnchorDrawLayer:
    anchor: str
    vaddr: int
    draw_layer_index: int | None
    obc: int | None
    oba: int | None


def read_maincpu_cstring(raw: bytes, rom_offset: int, max_len: int = 64) -> str:
    chunk = raw[rom_offset : rom_offset + max_len]
    end = chunk.find(b"\x00")
    if end < 0:
        end = len(chunk)
    return chunk[:end].decode("ascii", errors="replace").strip()


def parse_scene_root_table(rom_dir: Path | None = None) -> list[SceneRootEntry]:
    """Five workram roots @ ROM 0x14760 (used by scene lookup @ 0x014788)."""
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    base = SCENE_ROOT_TABLE_ROM // 4
    entries: list[SceneRootEntry] = []
    for i in range(5):
        w = words[base + i]
        if w == 0:
            break
        entries.append(
            SceneRootEntry(
                index=i,
                workram_vaddr=w,
                rom_table_offset=SCENE_ROOT_TABLE_ROM + i * 4,
            )
        )
    return entries


def anchor_draw_layers(
    draw_layers: list | None = None,
    rom_dir: Path | None = None,
) -> list[AnchorDrawLayer]:
    rom_dir = resolve_rom_dir(rom_dir)
    if draw_layers is None:
        md = u32_words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
        draw_layers = parse_draw_script(md)

    out: list[AnchorDrawLayer] = []
    for name, vaddr in CPU_SCENE_ANCHORS.items():
        if vaddr < DRAW_SCRIPT_VADDR:
            out.append(AnchorDrawLayer(anchor=name, vaddr=vaddr, draw_layer_index=None, obc=None, oba=None))
            continue
        idx = (vaddr - DRAW_SCRIPT_VADDR) // 16
        if 0 <= idx < len(draw_layers):
            layer = draw_layers[idx]
            out.append(
                AnchorDrawLayer(
                    anchor=name,
                    vaddr=vaddr,
                    draw_layer_index=idx,
                    obc=layer.obc,
                    oba=layer.oba,
                )
            )
        else:
            out.append(AnchorDrawLayer(anchor=name, vaddr=vaddr, draw_layer_index=None, obc=None, oba=None))
    return out


def _read_u32_le(path: Path, count: int) -> list[int]:
    data = path.read_bytes()
    return list(struct.unpack(f"<{min(count, len(data) // 4)}I", data[: count * 4]))


def load_workram_captures(capture_dir: Path) -> dict[str, object]:
    """Parse optional workram dump bins from *capture_dir* (lift harness output, not MAME)."""
    capture_dir = capture_dir.resolve()
    out: dict[str, object] = {"capture_dir": str(capture_dir), "present": [], "missing": []}

    for name in WORKRAM_DUMP_NAMES:
        path = capture_dir / name
        if path.is_file():
            out["present"].append(name)
        else:
            out["missing"].append(name)

    catalog_path = capture_dir / "workram_5b4340.bin"
    if catalog_path.is_file():
        vals = _read_u32_le(catalog_path, 8)
        out["catalog_index_table"] = {
            "vaddr": f"0x{CATALOG_INDEX_TABLE:08x}",
            "values": vals,
            "slots": [
                {"scene_batch_index": i, "catalog_index": v, "catalog_vaddr": f"0x{0x02864B40 + v * 16:08x}"}
                for i, v in enumerate(vals[:4])
            ],
        }

    batch_path = capture_dir / "workram_20a8c4.bin"
    if batch_path.is_file():
        vals = _read_u32_le(batch_path, 1)
        out["scene_batch_index"] = {"vaddr": f"0x{SCENE_BATCH_INDEX:08x}", "value": vals[0] if vals else None}

    course_path = capture_dir / "workram_215380.bin"
    if course_path.is_file():
        vals = _read_u32_le(course_path, 1)
        idx = vals[0] if vals else None
        hint = UI_COURSE_ORDER[idx] if idx is not None and 0 <= idx < len(UI_COURSE_ORDER) else None
        out["course_select_index"] = {
            "vaddr": f"0x{COURSE_SELECT_INDEX:08x}",
            "value": idx,
            "ui_course": hint,
        }

    meta_path = capture_dir / "workram_5b375c.bin"
    if meta_path.is_file():
        vals = _read_u32_le(meta_path, 8)
        out["scene_metadata_table"] = {"vaddr": f"0x{SCENE_METADATA_TABLE:08x}", "values": vals}

    dispatch_path = capture_dir / "workram_5ca210.bin"
    if dispatch_path.is_file():
        vals = _read_u32_le(dispatch_path, 32)
        out["catalog_dispatch_by_slot"] = {
            "vaddr": "0x005ca210",
            "catalog_indices": vals,
            "entries": [
                {"slot": i, "catalog_index": v, "catalog_vaddr": f"0x{0x02864B40 + v * 16:08x}"}
                for i, v in enumerate(vals)
                if v < 2000
            ][:16],
        }

    cursor_path = capture_dir / "workram_20b940.bin"
    if cursor_path.is_file():
        vals = _read_u32_le(cursor_path, 1)
        out["placement_cursor_live"] = {"vaddr": "0x0020b940", "value": vals[0] if vals else None}

    return out


def segments_matching_ranges(
    segments: list[dict[str, object]],
    ranges: list[tuple[int, int]],
) -> list[dict[str, object]]:
    """Return placement-segment records whose range exactly matches *ranges*."""
    wanted = {(lo, hi) for lo, hi in ranges}
    out: list[dict[str, object]] = []
    for seg in segments:
        pr = seg.get("placement_range", [0, 0])
        key = (int(pr[0]), int(pr[1]))
        if key in wanted:
            out.append(seg)
    order = {r: i for i, r in enumerate(ranges)}
    out.sort(key=lambda s: order.get(tuple(s.get("placement_range", [0, 0])), 99))
    return out


def segments_overlapping_ranges(
    segments: list[dict[str, object]],
    ranges: list[tuple[int, int]],
) -> list[dict[str, object]]:
    """Draw-script segments that overlap any placement span in *ranges*."""
    out: list[dict[str, object]] = []
    for seg in segments:
        pr = seg.get("placement_range", [0, 0])
        s0, s1 = int(pr[0]), int(pr[1])
        for lo, hi in ranges:
            if s0 < hi and s1 > lo:
                out.append(seg)
                break
    return out


def build_course_track_catalog(
    segments: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Build one catalog record per UI course from COURSE_TRACK_EXPORTS."""
    catalog: list[dict[str, object]] = []
    for course_id in UI_COURSE_ORDER:
        spec = COURSE_TRACK_EXPORTS[course_id]
        ranges = [(int(a), int(b)) for a, b in spec["placement_ranges"]]
        lo = min(r[0] for r in ranges)
        hi = max(r[1] for r in ranges)
        matched = segments_overlapping_ranges(segments, ranges)
        entry: dict[str, object] = {
            "id": f"track_{course_id}",
            "course_id": course_id,
            "title": spec["title"],
            "track_object": spec["track_object"],
            "placement_ranges": ranges,
            "placement_range": [lo, hi],
            "draw_batches": spec["draw_batches"],
            "confidence": spec["confidence"],
            "note": spec["note"],
            "segment_files": [str(s.get("file", "")) for s in matched],
        }
        excluded_ranges = spec.get("excluded_placement_ranges")
        if excluded_ranges:
            entry["excluded_placement_ranges"] = excluded_ranges
        supplements = COURSE_TRACK_SUPPLEMENTS.get(course_id)
        if supplements:
            entry["supplementary_assets"] = [str(s["id"]) for s in supplements]
        catalog.append(entry)
    return catalog


def classify_placement_segment(
    segment_index: int,
    placement_range: tuple[int, int],
    vertices: int,
    draw_layer_index: int,
    *,
    workram: dict[str, object] | None = None,
) -> dict[str, str | int | None]:
    """
    Label a placement segment for the viewer.

    Definitive track names need a workram capture of ``0x005B4340`` at race start.
    Until then we tag geometry tier and draw-batch phase.
    """
    start, end = placement_range
    count = end - start
    label: str | None = None
    confidence = "heuristic"
    tier = "minor"
    if vertices >= 30_000:
        tier = "major_geometry"
    elif vertices >= 10_000:
        tier = "medium_geometry"

    # Draw-script layer jump @ segment 7 marks a second scene phase (layers 20 → 125).
    phase = "phase_a" if draw_layer_index < 100 else "phase_b"

    if workram and "course_select_index" in workram:
        course = workram["course_select_index"]
        if isinstance(course, dict) and course.get("ui_course"):
            # Only name the dominant chunk for the active course when capture exists.
            ui = str(course["ui_course"])
            if tier == "major_geometry" and phase == "phase_a":
                label = ui
                confidence = "workram_course_index"

    if label is None and tier == "major_geometry":
        major_idx = {3: "geometry_batch_a", 9: "geometry_batch_b", 11: "geometry_batch_c"}.get(segment_index)
        if major_idx:
            label = major_idx

    if label is None and count <= 5 and vertices < 2000:
        label = "shared_props"
        confidence = "heuristic"

    return {
        "label": label,
        "confidence": confidence,
        "tier": tier,
        "phase": phase,
        "placement_start": start,
        "placement_end": end,
    }


def build_track_report(
    *,
    rom_dir: Path | None = None,
    capture_dir: Path | None = None,
    placement_segments: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    rom_dir = resolve_rom_dir(rom_dir)
    raw, _ = load_maincpu_words(rom_dir)
    capture_dir = capture_dir or (Path(__file__).resolve().parents[1] / "out" / "i960")
    workram = load_workram_captures(capture_dir)

    md = u32_words(load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]))
    draw_layers = parse_draw_script(md)
    anchors = anchor_draw_layers(draw_layers)

    ui_courses = {
        key: {
            "rom_offset": f"0x{off:06x}",
            "text": read_maincpu_cstring(raw, off),
        }
        for key, off in UI_COURSE_STRINGS_ROM.items()
    }

    segment_labels: list[dict[str, object]] = []
    if placement_segments:
        for seg in placement_segments:
            pr = seg.get("placement_range", [0, 0])
            start, end = int(pr[0]), int(pr[1])
            meta = classify_placement_segment(
                segment_index=len(segment_labels),
                placement_range=(start, end),
                vertices=int(seg.get("vertices", 0)),
                draw_layer_index=int(seg.get("draw_layer_index", 0)),
                workram=workram,
            )
            segment_labels.append({**seg, **meta})

    cpu_draw = parse_cpu_draw_entries(md)

    placement_cursor = {
        "workram_vaddr": f"0x{PLACEMENT_CURSOR:08x}",
        "geo_workram_write_ptr": f"0x{GEO_WORKRAM_WRITE_PTR:08x}",
        "reset_site": "0x00004ba8",
        "feeder_cluster": "0x00023cc8",
        "advance_rule": "cursor += catalog_entry.obc after each ldq 0x2864b40[index*16]",
        "float_adjust_fn": "0x000322f0",
        "draw_script_obc_meaning": "exclusive end placement index (snapshot of 0x20B940 after layer)",
    }

    scene_init = {
        "classifier_fn": "0x000146a8",
        "lookup_fn": "0x00014788",
        "lookup_inputs": {
            "g0": "scene table index (0–5; ROM ptr table @ 0x14760)",
            "g1": "filter mask (often 2)",
            "key_byte": "0x00202050 & 0xff — searched in interval table",
        },
        "metadata_indirect": "ld 0x5b375c[g0*4] → interval list (start,end) pairs",
        "catalog_index_read": "ld 0x5b4340[0x20a8c4*4] @ 0x15690 → catalog row",
        "draw_push_sites": {
            "0x00013e84": "ldq 0x28656c0 → geo FIFO (draw script layer 0)",
            "0x00013f90": "ldq 0x28656e0 (branch on 0x202230)",
            "0x00013ff4": "ldq 0x2865780 (alternate branch)",
            "0x000157bc": "loads 0x2865680 field block (batch @ anchor_157c0)",
            "0x000158ec": "loads 0x2865660 field block (batch @ anchor_158f0)",
        },
        "cpu_draw_entries": [
            {
                "vaddr": f"0x{layer.vaddr:08x}",
                "field_a": layer.field_a,
                "field_b": layer.field_b,
                "oba": f"0x{layer.oba:08x}",
                "obc": layer.obc,
            }
            for layer in cpu_draw
        ],
    }

    return {
        "ui_courses": ui_courses,
        "placement_cursor": placement_cursor,
        "scene_init": scene_init,
        "scene_root_table": [
            {
                "index": e.index,
                "workram_vaddr": f"0x{e.workram_vaddr:08x}",
                "rom_ptr": f"0x{e.rom_table_offset:06x}",
            }
            for e in parse_scene_root_table(rom_dir)
        ],
        "cpu_anchors": [
            {
                "anchor": a.anchor,
                "vaddr": f"0x{a.vaddr:08x}",
                "draw_layer_index": a.draw_layer_index,
                "placement_cursor_obc": a.obc,
                "polygon_oba": f"0x{a.oba:08x}" if a.oba is not None else None,
            }
            for a in anchors
        ],
        "workram_symbols": {
            "catalog_index_table": f"0x{CATALOG_INDEX_TABLE:08x}",
            "scene_metadata_table": f"0x{SCENE_METADATA_TABLE:08x}",
            "scene_batch_index": f"0x{SCENE_BATCH_INDEX:08x}",
            "course_select_index": f"0x{COURSE_SELECT_INDEX:08x}",
            "course_variant_index": f"0x{COURSE_VARIANT_INDEX:08x}",
            "catalog_index_read_site": "0x00015690",
            "scene_lookup_fn": "0x00014788",
            "scene_init_fn": "0x00016164",
        },
        "workram_capture": workram,
        "placement_segments": segment_labels,
        "notes": [
            "0x005B4340 is read-only in maincpu ROM — values are runtime workram (no static store sites found).",
            "Capture workram at course select / race start to resolve catalog_index_table slots.",
            "UI strings @ 0x9B70 are menu labels; track object names (FOREST16, …) live in main_data.",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Build track/scene RE report for srallyc")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--capture-dir", type=Path, default=None)
    ap.add_argument("--segments", type=Path, help="placement_segments.json from extract/scenes")
    ap.add_argument("--out", type=Path, default=Path("out/i960/track_report.json"))
    args = ap.parse_args()

    segments = None
    if args.segments and args.segments.is_file():
        segments = json.loads(args.segments.read_text())

    report = build_track_report(rom_dir=args.rom_dir, capture_dir=args.capture_dir, placement_segments=segments)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    if report["workram_capture"].get("missing"):
        print("Note: optional workram dump bins not present under capture-dir (static RE uses ROM tables).")


if __name__ == "__main__":
    main()
