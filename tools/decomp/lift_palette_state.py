"""Load/save segamod2_lift_palette_v1 dumps from decomp_lift."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from tools.model2_palette import COLORXLAT_WORDS, LUMARAM_BYTES, PALRAM_WORDS, PaletteState


def read_u16_le(data: bytes, index: int) -> int:
    off = index * 2
    if off + 1 >= len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]


def load_lift_palette_state(dump_dir: Path) -> tuple[PaletteState, dict]:
    manifest_path = dump_dir / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing manifest: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pal_bytes = (dump_dir / str(manifest["palram"]["file"])).read_bytes()
    cx_bytes = (dump_dir / str(manifest["colorxlat"]["file"])).read_bytes()
    lu_bytes = (dump_dir / str(manifest["lumaram"]["file"])).read_bytes()

    state = PaletteState()
    for i in range(min(len(pal_bytes) // 2, PALRAM_WORDS)):
        state.palram[i] = read_u16_le(pal_bytes, i)
    for i in range(min(len(cx_bytes) // 2, COLORXLAT_WORDS)):
        state.colorxlat[i] = read_u16_le(cx_bytes, i)
    for i in range(min(len(lu_bytes), LUMARAM_BYTES)):
        state.lumaram[i] = lu_bytes[i]
    return state, manifest


def write_lift_palette_state(dump_dir: Path, state: PaletteState, manifest: dict | None = None) -> None:
    dump_dir.mkdir(parents=True, exist_ok=True)
    if manifest is None:
        manifest = {
            "format": "segamod2_lift_palette_v1",
            "palram": {"vaddr": "0x01800000", "size": PALRAM_WORDS * 2, "file": "palram.bin"},
            "colorxlat": {"vaddr": "0x01810000", "size": COLORXLAT_WORDS * 2, "file": "colorxlat.bin"},
            "lumaram": {"vaddr": "0x12800000", "size": LUMARAM_BYTES, "file": "lumaram.bin"},
        }

    pal_bytes = bytearray(PALRAM_WORDS * 2)
    for i, word in enumerate(state.palram[:PALRAM_WORDS]):
        struct.pack_into("<H", pal_bytes, i * 2, word & 0xFFFF)

    cx_bytes = bytearray(COLORXLAT_WORDS * 2)
    for i, word in enumerate(state.colorxlat[:COLORXLAT_WORDS]):
        struct.pack_into("<H", cx_bytes, i * 2, word & 0xFFFF)

    lu_bytes = bytes(state.lumaram[:LUMARAM_BYTES].ljust(LUMARAM_BYTES, b"\x00"))
    # Always compact 0x8000 (MAME umask pack); do not re-pad to legacy 0x20000 map size.
    if "lumaram" in manifest:
        manifest["lumaram"]["size"] = LUMARAM_BYTES

    (dump_dir / str(manifest["palram"]["file"])).write_bytes(pal_bytes)
    (dump_dir / str(manifest["colorxlat"]["file"])).write_bytes(cx_bytes)
    (dump_dir / str(manifest["lumaram"]["file"])).write_bytes(lu_bytes)
    (dump_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
