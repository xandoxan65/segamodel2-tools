"""Small ROM slice helpers (shared by compare / image stitch)."""

from __future__ import annotations

import hashlib
import re


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def count_mismatch_bytes(rebuilt: bytes, reference: bytes) -> int:
    span = min(len(rebuilt), len(reference))
    return sum(1 for i in range(span) if rebuilt[i] != reference[i]) + abs(
        len(rebuilt) - len(reference)
    )


_ROM_SPEC = re.compile(r"^0x([0-9a-fA-F]+):(?:0x([0-9a-fA-F]+)|([0-9]+))$")


def parse_rom_spec(spec: str) -> tuple[int, int]:
    m = _ROM_SPEC.match(spec.strip())
    if not m:
        raise ValueError(f"expected 0x<base>:0x<len> or 0x<base>:<decimal>, got {spec!r}")
    base = int(m.group(1), 16)
    length = int(m.group(2), 16) if m.group(2) else int(m.group(3))
    return base, length
