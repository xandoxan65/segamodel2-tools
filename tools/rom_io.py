"""Load and de-interleave Sega Model 2 / srallyc ROM images (MAME layouts)."""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Iterable

# Socket label variants seen in dumps (PCB silkscreen vs MAME names).
ROM_ALIASES: dict[str, list[str]] = {
    "mpr-17754.28": ["mpr-17754.29"],
    "mpr-17755.29": ["mpr-17755.28"],
    "epr-17890a.30": ["epr-17890.30"],
}

# srallyc / srallycb game ROMs used by extractors (shared data is identical across revisions).
SRALLY_DATA_ROMS = {
    "textures": [("mpr-17753.25", "mpr-17752.24")],
    "copro_data": [("mpr-17754.28", "mpr-17755.29")],
    "polygons": [
        ("mpr-17748.16", "mpr-17750.20"),
        ("mpr-17749.17", "mpr-17751.21"),
    ],
    "main_data": [
        ("mpr-17746.10", "mpr-17747.11"),
        ("mpr-17744.8", "mpr-17745.9"),
        ("mpr-17884.6", "mpr-17885.7"),
    ],
    "samples": [
        "mpr-17756.31",
        "mpr-17757.32",
        "mpr-17886.36",
        "mpr-17887.37",
    ],
}


def resolve_rom_dir(explicit: Path | str | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("SEGAMOD2_ROM_DIR")
    if env:
        return Path(env).expanduser().resolve()
    root = Path(__file__).resolve().parents[1]
    config = root / "config.toml"
    if config.is_file():
        rom_dir = _read_toml_rom_dir(config)
        if rom_dir:
            p = Path(rom_dir)
            if not p.is_absolute():
                p = root / p
            return p.resolve()
    for candidate in (root / "ROMS" / "srallyc-b", root / "ROMS" / "srallyc-c"):
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate.resolve()
    raise FileNotFoundError(
        "ROM directory not found. Set SEGAMOD2_ROM_DIR, config.toml rom_dir, or use --rom-dir."
    )


def _read_toml_rom_dir(path: Path) -> str | None:
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("rom_dir") and "=" in line:
            _, _, value = line.partition("=")
            return value.strip().strip('"').strip("'")
    return None


def find_rom(rom_dir: Path, name: str) -> Path:
    direct = rom_dir / name
    if direct.is_file():
        return direct
    for alt in ROM_ALIASES.get(name, []):
        p = rom_dir / alt
        if p.is_file():
            return p
    raise FileNotFoundError(f"ROM not found: {name} (in {rom_dir})")


def load_raw(rom_dir: Path, name: str) -> bytes:
    return find_rom(rom_dir, name).read_bytes()


def load32_word_interleave(rom_dir: Path, low_name: str, high_name: str) -> bytes:
    """MAME ROM_LOAD32_WORD: low 16 bits from low_name, high 16 from high_name."""
    low = load_raw(rom_dir, low_name)
    high = load_raw(rom_dir, high_name)
    if len(low) != len(high):
        raise ValueError(f"ROM size mismatch: {low_name} ({len(low)}) vs {high_name} ({len(high)})")
    out = bytearray(len(low) * 2)
    for i in range(0, len(low), 2):
        word_index = i // 2
        out[word_index * 4 : word_index * 4 + 2] = low[i : i + 2]
        out[word_index * 4 + 2 : word_index * 4 + 4] = high[i : i + 2]
    return bytes(out)


def load32_word_region(rom_dir: Path, pairs: Iterable[tuple[str, str]]) -> bytes:
    chunks: list[bytes] = []
    for low, high in pairs:
        chunks.append(load32_word_interleave(rom_dir, low, high))
    return b"".join(chunks)


def load16_word_swap(rom_dir: Path, name: str) -> bytes:
    """MAME ROM_LOAD16_WORD_SWAP: 16-bit big-endian words in ROM -> little-endian bytes."""
    raw = load_raw(rom_dir, name)
    if len(raw) % 2:
        raise ValueError(f"Odd ROM size: {name}")
    out = bytearray(len(raw))
    for i in range(0, len(raw), 2):
        out[i] = raw[i + 1]
        out[i + 1] = raw[i]
    return bytes(out)


def u32_words(data: bytes) -> list[int]:
    if len(data) % 4:
        raise ValueError("Data length must be a multiple of 4")
    return list(struct.unpack(f"<{len(data) // 4}I", data))


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
