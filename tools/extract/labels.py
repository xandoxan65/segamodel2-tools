"""Extract meaningful ASCII labels from main_data for asset naming."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

KEYWORDS = (
    "FOREST",
    "MOUNTAIN",
    "LAKESIDE",
    "DESERT",
    "CELICA",
    "LANCIA",
    "DELTA",
    "STRATOS",
    "RALLY",
    "TRACK",
    "CAR",
    "SAS_",
    "OBJ_",
    "TEX_",
    "MAP_",
    "SKY",
    "TREE",
    "ROAD",
)


def extract_labels(rom_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])

    pattern = re.compile(rb"[\x20-\x7e]{4,64}")
    all_strings: list[str] = []
    for match in pattern.finditer(data):
        all_strings.append(match.group().decode("ascii"))

    TRACK_SUFFIX = re.compile(r"_(P16|CLEAR|TOP8|P|16)$|16$")

    def is_interesting(s: str) -> bool:
        if not any(c.isalpha() for c in s):
            return False
        upper = s.upper()
        if any(k in upper for k in KEYWORDS):
            return True
        # Named identifiers with structure (e.g. FOREST_P16, obj_tree_01)
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,63}", s) and "_" in s:
            if TRACK_SUFFIX.search(upper):
                return True
            if any(c.islower() for c in s) and any(c.isupper() for c in s):
                return True
        return False

    interesting = sorted({s for s in all_strings if is_interesting(s)}, key=str.lower)
    out_path = out_dir / "labels.json"
    out_path.write_text(json.dumps(interesting, indent=2) + "\n", encoding="utf-8")
    return out_path
