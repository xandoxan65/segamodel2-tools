"""Vehicle geometry path from i960 RE (distinct from track placement stream)."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from tools.i960_memory import (
    CATALOG_INDEX_ROM_BIAS,
    CATALOG_VADDR,
    COPY_CATALOG_INDEX_TABLE_FN,
    DRAW_CATALOG_SEQUENCE_FN,
    VEHICLE_ASSEMBLY_CATALOG_ROM,
    VEHICLE_BATCH_CATALOG_INDEX,
    VEHICLE_CAR_LOOKUP_FN,
    VEHICLE_CAR_REGISTER_FN,
    VEHICLE_CAR_SETUP_FN,
    VEHICLE_CATALOG_INDEX_A,
    VEHICLE_CATALOG_INDEX_B,
    VEHICLE_CATALOG_SINGLE_FN,
    VEHICLE_DESCRIPTOR_ROM_END,
    VEHICLE_DESCRIPTOR_ROM_START,
    VEHICLE_DRAW_CATALOG_FN,
    VEHICLE_DRAW_LIST_ROM,
    VEHICLE_GEO_FIFO,
    VEHICLE_JUMP_TABLE,
    VEHICLE_MATRIX_FLAGS,
    VEHICLE_MATRIX_TABLE,
    VEHICLE_MODE_FLAG,
    VEHICLE_OBJECT_SETUP_FN,
    VEHICLE_RACE_FX_CATALOG_A,
    VEHICLE_RACE_FX_CATALOG_B,
    VEHICLE_SELECT_MODE,
    VEHICLE_SELECT_PARAM,
    VEHICLE_SELECT_SLOT,
    VEHICLE_STAGING_WORKRAM_A,
    VEHICLE_STAGING_WORKRAM_B,
    VEHICLE_STATE_BYTE,
    VEHICLE_WORKRAM_EXT_ROM,
    VEHICLE_WORKRAM_ROOTS_ROM,
)
from tools.i960_scan import load_maincpu_words
from tools.model2_catalog import parse_catalog
from tools.model2_geo import try_parse_polygon_object
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir


@dataclass(frozen=True)
class VehicleCatalogTable:
    rom_offset: int
    name: str
    catalog_indices: list[int]


@dataclass(frozen=True)
class VehicleRomDescriptor:
    rom_offset: int
    kind: int
    main_data_vaddr: int
    catalog_indices: list[int]


@dataclass(frozen=True)
class VehicleDrawBlock:
    """One static draw-order block from ROM (e.g. race_draw_list segment)."""

    name: str
    catalog_indices: list[int]
    roles: list[str]


# Confirmed body shells from catalog mesh stats (≥1000 verts, span <10).
BODY_SHELL_INDICES: tuple[int, ...] = (96, 97, 98, 99, 106, 107)
WHEEL_INDICES: tuple[int, ...] = tuple(range(132, 144))
TRIM_INDICES: tuple[int, ...] = (78, 79)


def decode_catalog_index_word(value: int) -> int:
    """ROM descriptor words use +0x400 bias for indices ≥ 0x400."""
    if value >= CATALOG_INDEX_ROM_BIAS:
        return value - CATALOG_INDEX_ROM_BIAS
    return value


def _read_catalog_index_run(words: list[int], rom_offset: int, *, max_len: int = 64) -> list[int]:
    """Read consecutive small integers (catalog row ids) from maincpu ROM."""
    base = rom_offset // 4
    out: list[int] = []
    for i in range(max_len):
        if base + i >= len(words):
            break
        v = words[base + i]
        if v > 512:
            break
        out.append(v)
    return out


def classify_draw_index(index: int, mesh_by_index: dict[int, dict[str, object]] | None = None) -> str:
    if index in BODY_SHELL_INDICES:
        return "body_shell"
    if index in WHEEL_INDICES:
        return "wheel_or_trim"
    if index in TRIM_INDICES:
        return "trim"
    if mesh_by_index and index in mesh_by_index:
        return str(mesh_by_index[index].get("role", "other"))
    if 78 <= index <= 107:
        return "body_panel"
    return "other"


def parse_race_draw_blocks(
    indices: list[int],
    *,
    mesh_by_index: dict[int, dict[str, object]] | None = None,
) -> list[VehicleDrawBlock]:
    """
    Split ``race_draw_list`` @ ROM 0x34E88 into logical draw blocks.

    Observed layout: bodies 96–107, trim 78–79, wheel sets 132–143 (repeated).
    """
    if not indices:
        return []

    blocks: list[VehicleDrawBlock] = []
    i = 0
    n = len(indices)

    def take_until(pred_stop) -> list[int]:
        nonlocal i
        chunk: list[int] = []
        while i < n and not pred_stop(indices[i], i):
            chunk.append(indices[i])
            i += 1
        return chunk

    body = take_until(lambda idx, _pos: idx < 96 or idx > 107)
    if body:
        blocks.append(
            VehicleDrawBlock(
                name="race_bodies",
                catalog_indices=body,
                roles=[classify_draw_index(x, mesh_by_index) for x in body],
            )
        )

    trim = take_until(lambda idx, _pos: idx not in TRIM_INDICES)
    if trim:
        blocks.append(
            VehicleDrawBlock(
                name="race_trim",
                catalog_indices=trim,
                roles=[classify_draw_index(x, mesh_by_index) for x in trim],
            )
        )

    wheel_set = 0
    while i < n:
        while i < n and not (132 <= indices[i] <= 143):
            i += 1
        if i >= n:
            break
        start = i
        while i < n and 132 <= indices[i] <= 143:
            i += 1
        chunk = indices[start:i]
        blocks.append(
            VehicleDrawBlock(
                name=f"wheel_set_{wheel_set}",
                catalog_indices=chunk,
                roles=[classify_draw_index(x, mesh_by_index) for x in chunk],
            )
        )
        wheel_set += 1
    return blocks


def build_vehicle_geo_chain(rom_dir: Path | None = None) -> dict[str, object]:
    """Static ROM chain: descriptors / tables → geo feed fns → catalog indices."""
    rom_dir = resolve_rom_dir(rom_dir)
    tables = parse_vehicle_catalog_tables(rom_dir)
    descriptors = parse_rom_vehicle_descriptors(rom_dir)
    meshes = catalog_mesh_report(rom_dir)
    mesh_by = {int(m["catalog_index"]): m for m in meshes if "catalog_index" in m}

    race_table = next((t for t in tables if t.name == "race_draw_list"), None)
    race_blocks = (
        parse_race_draw_blocks(race_table.catalog_indices, mesh_by_index=mesh_by)
        if race_table
        else []
    )

    body_cars = []
    for cat in BODY_SHELL_INDICES:
        meta = mesh_by.get(cat, {})
        body_cars.append(
            {
                "catalog_index": cat,
                "rom_offset": meta.get("rom_offset"),
                "vertices": meta.get("vertices"),
                "span_max": meta.get("span_max"),
                "draw_sequence": {
                    "body": [cat],
                    "trim": list(TRIM_INDICES),
                    "wheels": list(WHEEL_INDICES),
                },
                "geo_feed_path": [
                    f"ROM descriptor / 0x34E88 → copy_catalog @ 0x{COPY_CATALOG_INDEX_TABLE_FN:06x}",
                    f"vehicle_object_setup @ 0x{VEHICLE_OBJECT_SETUP_FN:06x} → draw_catalog_sequence @ 0x{DRAW_CATALOG_SEQUENCE_FN:06x}",
                    f"race: draw_car_primary @ 0x{VEHICLE_DRAW_CATALOG_FN:06x} (ld 0x5E3DF0[slot] → ldq 0x2864B40 → stq 0x804000)",
                ],
            }
        )

    return {
        "feed_pipelines": [
            {
                "stage": "init",
                "rom": "0x043830",
                "fn": f"0x{COPY_CATALOG_INDEX_TABLE_FN:06x}",
                "action": "Copy descriptor index runs → workram 0x5E37D0 band; geo-push tail @ 0x28528",
            },
            {
                "stage": "car_setup",
                "rom": f"0x{VEHICLE_OBJECT_SETUP_FN:06x}",
                "fn": f"0x{DRAW_CATALOG_SEQUENCE_FN:06x}",
                "action": "Staging 0x5E2890/0x5E2900 → ldq catalog → copro + prg FIFO",
            },
            {
                "stage": "car_select",
                "rom": "0x034D80",
                "fn": f"0x{VEHICLE_CAR_REGISTER_FN:06x}",
                "action": "car_register → 0x33E90 texture/geo + 0x2B0B0 lookup",
            },
            {
                "stage": "race_draw",
                "rom": f"0x{VEHICLE_DRAW_CATALOG_FN:06x}",
                "fn": "0x0451E0 dispatch",
                "action": "Jump table @ 0x45220 → draw_car_primary / draw_car_batch / draw_car_parts",
            },
        ],
        "rom_descriptors": [
            {
                "rom": f"0x{d.rom_offset:06x}",
                "kind": d.kind,
                "main_data_vaddr": f"0x{d.main_data_vaddr:08x}",
                "catalog_indices": d.catalog_indices,
                "body_shells": [i for i in d.catalog_indices if i in BODY_SHELL_INDICES],
            }
            for d in descriptors
        ],
        "static_tables": [
            {
                "rom": f"0x{t.rom_offset:06x}",
                "name": t.name,
                "catalog_indices": t.catalog_indices,
            }
            for t in tables
        ],
        "race_draw_blocks": [
            {
                "name": b.name,
                "catalog_indices": b.catalog_indices,
                "roles": b.roles,
            }
            for b in race_blocks
        ],
        "body_cars": body_cars,
        "dispatch_jump_table": {
            "rom": "0x045220",
            "entries_hex": ["0x310", "0x30F", "0x312", "0x311", "0x314", "0x313"],
            "resolved_fns": {
                "0x310": "0x045310 draw_car_batch area",
                "0x380": "0x045380 draw_car_mode_gate",
                "0x460": "0x045460 draw_car_parts",
            },
        },
        "geo_push_helper": {
            "fn": "0x03EF70",
            "role": "Scene/catalog row pusher via 0x5DDB70 table → stq 0x804000",
        },
    }


def parse_vehicle_catalog_tables(rom_dir: Path | None = None) -> list[VehicleCatalogTable]:
    """
    Static draw-order tables embedded after ``vehicle_select_step`` @ ROM 0x34D80.

    Confirmed by ROM layout (not heuristics):
    - 0x34E40: body + trim parts (catalog 78–107)
    - 0x34E88: race draw list (catalog 96–107, wheels 132–143, repeated livery blocks)
  """
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    assembly = _read_catalog_index_run(words, VEHICLE_ASSEMBLY_CATALOG_ROM)
    draw_list = _read_catalog_index_run(words, VEHICLE_DRAW_LIST_ROM)
    tables = [
        VehicleCatalogTable(VEHICLE_ASSEMBLY_CATALOG_ROM, "assembly_parts", assembly),
        VehicleCatalogTable(VEHICLE_DRAW_LIST_ROM, "race_draw_list", draw_list),
    ]
    return tables


def parse_rom_vehicle_descriptors(rom_dir: Path | None = None) -> list[VehicleRomDescriptor]:
    """
  Typed ROM records @ 0x43830–0x43A00 (maincpu).

  Layout (per record):
    +0x00 kind
    +0x04 n_indices
    +0x08 main_data_vaddr (transform / material blob)
    +0x0C catalog_index[n]  (bias 0x400 when encoded)
  """
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)
    start = VEHICLE_DESCRIPTOR_ROM_START // 4
    end = VEHICLE_DESCRIPTOR_ROM_END // 4
    out: list[VehicleRomDescriptor] = []
    i = start
    while i + 3 < end:
        kind = words[i]
        count = words[i + 1]
        main_data = words[i + 2]
        if not (0x0200_0000 <= main_data <= 0x0300_0000):
            i += 1
            continue
        if count == 0 or count > 64:
            i += 1
            continue
        if i + 3 + count > end:
            break
        raw = words[i + 3 : i + 3 + count]
        indices = [decode_catalog_index_word(v) for v in raw]
        if not all(0 <= idx < 782 for idx in indices):
            i += 1
            continue
        out.append(
            VehicleRomDescriptor(
                rom_offset=i * 4,
                kind=kind,
                main_data_vaddr=main_data,
                catalog_indices=indices,
            )
        )
        i += 3 + count
    return out


def mesh_geometry_fingerprint(parsed) -> str:
    """Stable id for comparing catalog meshes (verts + primitive indices)."""
    payload = repr(
        (
            len(parsed.vertices),
            parsed.vertices[0],
            parsed.vertices[-1],
            tuple(p.indices for p in parsed.primitives),
        )
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:12]


def _mesh_stats(vertices: list[tuple[float, float, float]]) -> dict[str, float | int]:
    xs = [v[0] for v in vertices]
    ys = [v[1] for v in vertices]
    zs = [v[2] for v in vertices]
    span_x = max(xs) - min(xs)
    span_y = max(ys) - min(ys)
    span_z = max(zs) - min(zs)
    peak = max(max(abs(x) for x in xs), max(abs(y) for y in ys), max(abs(z) for z in zs))
    return {
        "vertices": len(vertices),
        "span_x": round(span_x, 2),
        "span_y": round(span_y, 2),
        "span_z": round(span_z, 2),
        "span_max": round(max(span_x, span_y, span_z), 2),
        "peak_abs": round(peak, 2),
    }


VEHICLE_DRAW_FUNCTIONS: list[dict[str, str]] = [
    {
        "fn": "0x00044f00",
        "role": "draw_car_primary",
        "catalog_table": "0x005e3df0 / 0x005e3df8",
        "matrix": "0x005e3e00[player×16]",
        "geo_fifo": "0x00884000",
    },
    {
        "fn": "0x000451e0",
        "role": "vehicle_state_dispatch",
        "note": "bx via workram 0x005e421c; ROM literals @ 0x45220",
    },
    {
        "fn": "0x00045240",
        "role": "draw_car_batch",
        "catalog_table": "0x005e4220[slot×4]",
        "geo_fifo": "0x00884000 (stq → 0x00804000)",
    },
    {
        "fn": "0x00045380",
        "role": "draw_car_mode_gate",
        "note": "checks 0x00202230, 0x00217184, 0x00202098",
    },
    {
        "fn": "0x00045460",
        "role": "draw_car_parts",
        "catalog_table": "0x005e3b90 / 0x005e3cc0",
    },
    {
        "fn": "0x00045580",
        "role": "draw_car_race_fx",
        "note": "ldq fixed main_data @ 0x2867dc0 / 0x2867e00 (614-vert FX, not body)",
    },
    {
        "fn": "0x0002b420",
        "role": "catalog_single_dispatch",
        "note": "car parts path @ 0x2bb74; fifo 0x884000",
    },
    {
        "fn": "0x00034f40",
        "role": "car_register",
        "note": "calls 0x33e90 + 0x2b0b0; stores handle @ 0x2140c8",
    },
    {
        "fn": f"0x{DRAW_CATALOG_SEQUENCE_FN:08x}",
        "role": "draw_catalog_sequence",
        "note": "walks workram staging struct; ldq 0x2864b40[index]; fifo 0x884000",
    },
    {
        "fn": f"0x{COPY_CATALOG_INDEX_TABLE_FN:08x}",
        "role": "copy_catalog_index_table",
        "note": "copies catalog index arrays from ROM/main_data into workram (5E3DF0 band)",
    },
    {
        "fn": f"0x{VEHICLE_OBJECT_SETUP_FN:08x}",
        "role": "vehicle_object_setup",
        "note": f"calls 0x280D0 with staging @ 0x{VEHICLE_STAGING_WORKRAM_A:08x}/0x{VEHICLE_STAGING_WORKRAM_B:08x}",
    },
]

VEHICLE_INIT_CHAIN: list[dict[str, str]] = [
    {
        "step": "1",
        "where": f"ROM 0x{VEHICLE_DESCRIPTOR_ROM_START:06x}",
        "what": "Typed vehicle descriptors (kind, n, main_data ptr, catalog index list)",
    },
    {
        "step": "2",
        "where": f"0x{COPY_CATALOG_INDEX_TABLE_FN:08x}",
        "what": "Runtime copy of catalog index arrays into workram blob rooted @ 0x5E37D0",
    },
    {
        "step": "3",
        "where": "0x005e3df0 (+0x2e0 from 0x5e3b10)",
        "what": "Per-slot catalog index table consumed by draw_car_primary @ 0x44F00",
    },
    {
        "step": "4",
        "where": f"0x{DRAW_CATALOG_SEQUENCE_FN:08x}",
        "what": "Optional batch draw via staging buffers 0x5E2890 / 0x5E2900 during car setup",
    },
    {
        "step": "5",
        "where": f"0x{VEHICLE_DRAW_CATALOG_FN:08x}",
        "what": "Per-frame draw: matrix from 0x5E3E00, catalog row from 0x5E3DF0[slot]",
    },
]

VEHICLE_WORKRAM_LAYOUT: list[dict[str, str]] = [
    {"vaddr": "0x005e37d0", "offset_from_root": "+0x0000", "note": "workram blob root (ROM ptr @ 0x3efe4)"},
    {"vaddr": "0x005e3b10", "offset_from_root": "+0x0340", "note": "secondary blob (ROM ptr @ 0x3efe8)"},
    {"vaddr": "0x005e3b90", "offset_from_3b10": "+0x0080", "note": "catalog index table (ld @ 0x4547c)"},
    {"vaddr": "0x005e3cc0", "offset_from_3b10": "+0x01b0", "note": "alt catalog index table (ld @ 0x454d0)"},
    {"vaddr": "0x005e3df0", "offset_from_3b10": "+0x02e0", "note": "per-slot catalog index A (ld @ 0x4509c)"},
    {"vaddr": "0x005e3df8", "offset_from_3b10": "+0x02e8", "note": "per-slot catalog index B (ld @ 0x45110)"},
    {"vaddr": "0x005e3e00", "offset_from_3b10": "+0x02f0", "note": "per-player 4×4 matrix table"},
    {"vaddr": "0x005e421c", "offset_from_3b10": "+0x050c", "note": "indirect dispatch pointer (bx @ 0x451e4)"},
    {"vaddr": "0x005e4220", "offset_from_3b10": "+0x0510", "note": "batch catalog index table"},
    {"vaddr": "0x002142c8", "offset_from_root": "car_select", "note": "car select slot counter"},
    {"vaddr": "0x002140c8", "offset_from_root": "car_select", "note": "active car object handle"},
]

WORKRAM_CAPTURE_SPECS: list[dict[str, str | int]] = [
    {"file": "workram_5e3df0.bin", "vaddr": "0x005e3df0", "words": 16},
    {"file": "workram_5e3df8.bin", "vaddr": "0x005e3df8", "words": 16},
    {"file": "workram_5e4220.bin", "vaddr": "0x005e4220", "words": 16},
    {"file": "workram_5e3b90.bin", "vaddr": "0x005e3b90", "words": 32},
    {"file": "workram_5e3e00.bin", "vaddr": "0x005e3e00", "words": 64},
    {"file": "workram_2140c8.bin", "vaddr": "0x002140c8", "words": 8},
    {"file": "workram_2142c8.bin", "vaddr": "0x002142c8", "words": 8},
]


def parse_vehicle_workram_ptr_tables(rom_dir: Path | None = None) -> dict[str, list[str]]:
    """Workram destination roots from ROM template tables @ 0x3EFC4 / 0x3F000."""
    rom_dir = resolve_rom_dir(rom_dir)
    _, words = load_maincpu_words(rom_dir)

    def read_ptr_run(rom_offset: int, max_len: int = 16) -> list[str]:
        base = rom_offset // 4
        out: list[str] = []
        for i in range(max_len):
            w = words[base + i]
            if w == 0:
                break
            if 0x0050_0000 <= w <= 0x0060_0000:
                out.append(f"0x{w:08x}")
        return out

    return {
        "roots_rom": f"0x{VEHICLE_WORKRAM_ROOTS_ROM:06x}",
        "ext_rom": f"0x{VEHICLE_WORKRAM_EXT_ROM:06x}",
        "roots": read_ptr_run(VEHICLE_WORKRAM_ROOTS_ROM),
        "extended": read_ptr_run(VEHICLE_WORKRAM_EXT_ROM),
    }


def load_workram_capture(capture_dir: Path | None) -> dict[str, object]:
    if capture_dir is None:
        return {"present": False, "missing": [s["file"] for s in WORKRAM_CAPTURE_SPECS]}
    capture_dir = Path(capture_dir)
    out: dict[str, object] = {"present": True, "dir": str(capture_dir), "tables": {}}
    missing: list[str] = []
    for spec in WORKRAM_CAPTURE_SPECS:
        path = capture_dir / str(spec["file"])
        if not path.is_file():
            missing.append(str(spec["file"]))
            continue
        words = list(struct.unpack(f"<{path.stat().st_size // 4}I", path.read_bytes()))
        out["tables"][str(spec["file"])] = {
            "vaddr": spec["vaddr"],
            "values": words,
            "catalog_indices": [w for w in words if w < 512],
        }
    out["missing"] = missing
    return out


def classify_catalog_role(index: int, stats: dict[str, float | int]) -> str:
    verts = int(stats["vertices"])
    span = float(stats["span_max"])
    if verts >= 1000 and span < 10:
        return "body_shell"
    if 200 <= verts < 400 and span < 8:
        return "body_panel"
    if verts < 60 and span < 6:
        return "small_part"
    if 132 <= index <= 143:
        return "wheel_or_trim"
    return "other"


def catalog_mesh_report(rom_dir: Path | None = None) -> list[dict[str, object]]:
    rom_dir = resolve_rom_dir(rom_dir)
    poly_raw = load32_word_region(rom_dir, SRALLY_DATA_ROMS["polygons"])
    polygon_rom = list(struct.unpack(f"<{len(poly_raw) // 4}I", poly_raw))
    mask = len(polygon_rom) - 1
    main_data = list(
        struct.unpack(
            f"<{len(load32_word_region(rom_dir, SRALLY_DATA_ROMS['main_data'])) // 4}I",
            load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"]),
        )
    )
    catalog = parse_catalog(main_data, mask=mask)
    tables = parse_vehicle_catalog_tables(rom_dir)
    referenced = sorted({idx for t in tables for idx in t.catalog_indices})

    rows: list[dict[str, object]] = []
    canonical_by_fingerprint: dict[str, int] = {}
    for index in referenced:
        entry = catalog[index]
        parsed = try_parse_polygon_object(polygon_rom, entry.rom_offset)
        if parsed is None:
            rows.append(
                {
                    "catalog_index": index,
                    "rom_offset": entry.rom_offset,
                    "error": "parse_failed",
                    "obc": entry.obc,
                }
            )
            continue
        stats = _mesh_stats(parsed.vertices)
        geometry_id = mesh_geometry_fingerprint(parsed)
        canonical = canonical_by_fingerprint.setdefault(geometry_id, index)
        row: dict[str, object] = {
            "catalog_index": index,
            "rom_offset": entry.rom_offset,
            "obc": entry.obc,
            "oba": f"0x{entry.oba:08x}",
            "role": classify_catalog_role(index, stats),
            "geometry_id": geometry_id,
            "geometry_canonical_catalog": canonical,
            **stats,
        }
        if canonical != index:
            row["geometry_note"] = (
                f"Identical mesh to catalog {canonical} — separate ROM blob; "
                "car differences are texture/trim/wheels at runtime."
            )
        rows.append(row)
    return rows


def build_vehicle_report(
    rom_dir: Path | None = None,
    *,
    capture_dir: Path | None = None,
) -> dict[str, object]:
    rom_dir = resolve_rom_dir(rom_dir)
    tables = parse_vehicle_catalog_tables(rom_dir)
    descriptors = parse_rom_vehicle_descriptors(rom_dir)
    meshes = catalog_mesh_report(rom_dir)
    workram_ptrs = parse_vehicle_workram_ptr_tables(rom_dir)
    workram_capture = load_workram_capture(capture_dir)

    slot_decode: list[dict[str, int]] = []
    cap_tables = workram_capture.get("tables", {})
    if isinstance(cap_tables, dict):
        cap_table = cap_tables.get("workram_5e3df0.bin")
        if isinstance(cap_table, dict) and isinstance(cap_table.get("values"), list):
            for slot, raw in enumerate(cap_table["values"]):
                idx = decode_catalog_index_word(int(raw))
                if 0 <= idx < 782:
                    slot_decode.append({"slot": slot, "catalog_index": idx})

    draw_fn = {
        "fn": f"0x{VEHICLE_DRAW_CATALOG_FN:08x}",
        "geo_fifo": f"0x{VEHICLE_GEO_FIFO:08x}",
        "catalog_base": f"0x{CATALOG_VADDR:08x}",
        "matrix_table": f"0x{VEHICLE_MATRIX_TABLE:08x}",
        "matrix_flags": f"0x{VEHICLE_MATRIX_FLAGS:08x}",
        "catalog_index_a": f"0x{VEHICLE_CATALOG_INDEX_A:08x}",
        "catalog_index_b": f"0x{VEHICLE_CATALOG_INDEX_B:08x}",
        "batch_catalog_index": f"0x{VEHICLE_BATCH_CATALOG_INDEX:08x}",
        "jump_table": f"0x{VEHICLE_JUMP_TABLE:08x}",
        "state_byte": f"0x{VEHICLE_STATE_BYTE:08x}",
        "mode_flag": f"0x{VEHICLE_MODE_FLAG:08x}",
        "per_car_struct_fields": {
            "+0x18": "texture / palette word (tpa)",
            "+0x1c": "texture header (tha)",
            "+0x20": "polygon oba",
            "+0x28": "extra geo param",
            "+0x5c": "catalog batch slot / player index",
        },
        "catalog_load_sites": {
            "primary_body": "0x0004509C ld 0x5e3df0[g13*4]",
            "alt_body": "0x00045110 ld 0x5e3df8[g13*4]",
            "batch": "0x000452F0 ld 0x5e4220[g5*4]",
            "matrix": "0x00044F84 lda 0x5e3e00[r3*16]",
        },
    }

    track_contrast = {
        "track_placement_stream": "0x02867C20",
        "track_geo_fifo": "0x00804000",
        "track_feeder_cluster": "0x00023CC8",
        "note": "Track bulk geometry uses placement stream + catalog dispatch @ 0x2B290; "
        "vehicles use per-slot catalog index tables in workram and geo FIFO 0x884000.",
    }

    car_select = {
        "step_fn": "0x00034d80",
        "register_fn": f"0x{VEHICLE_CAR_REGISTER_FN:08x}",
        "setup_fn": f"0x{VEHICLE_CAR_SETUP_FN:08x}",
        "lookup_fn": f"0x{VEHICLE_CAR_LOOKUP_FN:08x}",
        "slot_counter": f"0x{VEHICLE_SELECT_SLOT:08x}",
        "mode": f"0x{VEHICLE_SELECT_MODE:08x}",
        "param": f"0x{VEHICLE_SELECT_PARAM:08x}",
        "object_handle": "0x002140c8",
    }

    return {
        "draw_path": draw_fn,
        "draw_functions": VEHICLE_DRAW_FUNCTIONS,
        "init_chain": VEHICLE_INIT_CHAIN,
        "rom_descriptors": [
            {
                "rom_offset": f"0x{d.rom_offset:06x}",
                "kind": d.kind,
                "main_data_vaddr": f"0x{d.main_data_vaddr:08x}",
                "catalog_indices": d.catalog_indices,
            }
            for d in descriptors
        ],
        "workram_layout": VEHICLE_WORKRAM_LAYOUT,
        "workram_slot_catalog": slot_decode,
        "workram_ptr_tables": workram_ptrs,
        "workram_capture": workram_capture,
        "track_contrast": track_contrast,
        "car_select_workram": car_select,
        "race_fx_catalog_refs": {
            "a": f"0x{VEHICLE_RACE_FX_CATALOG_A:08x}",
            "b": f"0x{VEHICLE_RACE_FX_CATALOG_B:08x}",
            "note": "Fixed main_data catalog-style records used @ 0x456a8 — race FX geometry, not car bodies.",
        },
        "static_catalog_tables": [
            {
                "name": t.name,
                "rom_offset": f"0x{t.rom_offset:06x}",
                "count": len(t.catalog_indices),
                "catalog_indices": t.catalog_indices,
            }
            for t in tables
        ],
        "catalog_meshes": meshes,
        "recommended_exports": {
            "body_shells": [m["catalog_index"] for m in meshes if m.get("role") == "body_shell"],
            "default_catalog_index": 96,
        },
        "notes": [
            "No maincpu ROM stores to 0x5E3DF0 — copy_catalog_index_table @ 0x282D0 fills workram at runtime.",
            "Static compact lists @ 0x34E40 / 0x34E88 mirror descriptor catalog sequences.",
            "Structured descriptors @ 0x43830 encode catalog indices with +0x400 bias when ≥ 1024.",
            "draw_catalog_sequence @ 0x280D0 pushes catalog rows during vehicle_object_setup @ 0x439D0.",
            "ROM workram pointer templates @ 0x3EFC4 / 0x3F000 list destination blobs (0x5E37D0 … 0x5E4FD0).",
            "Runtime workram tables (0x5E3DF0 etc.) — infer from disasm trace or lifted harness.",
            "Do not use polygon-ROM span heuristics for vehicles; use catalog indices from this report.",
            "Part transforms: 20-word main_data records (tags @ words 4/9/14/19); copy_catalog @ 0x28530 blends four lanes; static export uses translation @ words 10–11 (see tools/model2_vehicle_transforms.py).",
            "Master catalog field_a/field_b are polygon-ROM byte offsets — not a separate instance table @ 0x2864F00.",
            "Body shells 96–99 and 106–107 share one identical polygon mesh (6337-word ROM blobs spaced 0x18c1 apart); catalog 100–105 are panels/small parts, not alternate bodies.",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Build vehicle geometry RE report for srallyc")
    ap.add_argument("--rom-dir", type=Path, default=None)
    ap.add_argument("--capture-dir", type=Path, default=Path("out/i960"))
    ap.add_argument("--out", type=Path, default=Path("out/i960/vehicle_report.json"))
    args = ap.parse_args()

    report = build_vehicle_report(rom_dir=args.rom_dir, capture_dir=args.capture_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    bodies = report["recommended_exports"]["body_shells"]
    print(f"Wrote {args.out} ({len(bodies)} body shells, {len(report['catalog_meshes'])} catalog rows)")
    if report["workram_capture"].get("missing"):
        print("Note: optional workram dump bins not present under capture-dir (static RE uses ROM tables).")


if __name__ == "__main__":
    main()
