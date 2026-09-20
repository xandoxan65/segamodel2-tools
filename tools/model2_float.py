"""IEEE float bit reinterpretation (MAME corefloat f2u / u2f)."""

from __future__ import annotations

import struct


def u2f(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]


def f2u(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]
