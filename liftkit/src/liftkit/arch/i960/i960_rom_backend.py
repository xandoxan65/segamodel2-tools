"""Static maincpu ROM reads for lift-time annotation (no emulator)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from liftkit.project.workspace import resolve_in_repo


@lru_cache(maxsize=1)
def load_maincpu_image() -> bytes | None:
    candidates = [
        resolve_in_repo(Path("out/i960/maincpu_deinterleaved.bin")),
        resolve_in_repo(Path("data/maincpu_deinterleaved.bin")),
    ]
    for path in candidates:
        if path.is_file():
            return path.read_bytes()
    return None


def rom_read_u8(addr: int, *, image: bytes | None = None) -> int | None:
    blob = image if image is not None else load_maincpu_image()
    if blob is None or addr < 0 or addr >= len(blob):
        return None
    return blob[addr]


def rom_read_u32_le(addr: int, *, image: bytes | None = None) -> int | None:
    blob = image if image is not None else load_maincpu_image()
    if blob is None or addr < 0 or addr + 4 > len(blob):
        return None
    return int.from_bytes(blob[addr : addr + 4], "little")


def rom_ascii_preview(addr: int, max_len: int = 32, *, image: bytes | None = None) -> str | None:
    blob = image if image is not None else load_maincpu_image()
    if blob is None or addr < 0 or addr >= len(blob):
        return None
    end = min(len(blob), addr + max_len)
    raw = blob[addr:end]
    if not raw:
        return None
    chars: list[str] = []
    for b in raw:
        if b == 0:
            break
        if 32 <= b < 127:
            chars.append(chr(b))
        else:
            chars.append(".")
    if not chars:
        return None
    return "".join(chars)


def rom_ref_annotation(addr: int) -> str | None:
    preview = rom_ascii_preview(addr)
    if preview:
        escaped = preview.replace("\\", "\\\\").replace('"', '\\"')
        return f'/* rom @0x{addr:x}: "{escaped}" */'
    return None
