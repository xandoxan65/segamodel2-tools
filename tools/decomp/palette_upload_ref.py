"""Reference simulator for geo_palette_lut_upload @ ROM 0x3C80 (disasm-backed).

Mirrors lifted C / disasm f32 round-trips (cvtir → movr → rifl). Used to tier-validate
decomp_lift colorxlat output without MAME runtime dumps.

Gamma register assignment (from disasm @ 0x3C88/0x3C80):
  r9  @ 0x5A2C70 = gamma_a — inner loop (0x3D84 mulr fp2)
  r12 @ 0x5A2C74 = gamma_b — outer bank scale (0x3D0C mulr r12)
"""

from __future__ import annotations

import math
import os
import struct
from pathlib import Path

MODEL2_PALRAM_BASE = 0x0180_0000
MODEL2_COLORXLAT_BASE = 0x0181_0000
MODEL2_COLORXLAT_SIZE = 0xC000

WORKRAM_GAMMA_A = 0x005A_2C70
WORKRAM_GAMMA_B = 0x005A_2C74
WORKRAM_ROM_MIRROR = 0x0059_F000

F64_255 = 255.0
F64_63 = 63.0
INNER_WORDS = 64
TAIL_WORDS = 191
BANK_WORDS = INNER_WORDS + TAIL_WORDS  # 255 per channel per bank


def u32_to_f32(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]


def f32_to_u32(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _f32_roundtrip(value: float) -> float:
    return u32_to_f32(f32_to_u32(value))


def gamma_u32_from_maincpu(maincpu: bytes, workram_vaddr: int) -> int:
    rom_off = workram_vaddr - WORKRAM_ROM_MIRROR
    return struct.unpack_from("<I", maincpu, rom_off)[0]


def _clamp_u8_from_unit_float(value: float) -> int:
    """cvtzril after mulrl by 255.0 @ 0x3DBC / 0x3E1C."""
    scaled = _f32_roundtrip(value) * F64_255
    iv = int(scaled)
    iv &= 0xFFFF
    if iv > 0xFF:
        return 0xFF
    return iv


def _store_u16(buf: bytearray, vaddr: int, value: int) -> None:
    if vaddr < MODEL2_COLORXLAT_BASE:
        return
    off = vaddr - MODEL2_COLORXLAT_BASE
    if off < 0 or off + 1 >= len(buf):
        return
    struct.pack_into("<H", buf, off, value & 0xFFFF)


def _outer_g6_u32(g4_bank: int, gamma_b_u32: int) -> int:
    """0x3CBC..0x3D44 — r12=gamma_b, r6=(1-gb); sqrt*gb + (1-gb)*frac^2."""
    gb = u32_to_f32(gamma_b_u32)
    one_m_gb = _f32_roundtrip(1.0 - gb)

    fp0 = _f32_roundtrip(float(int(g4_bank & 0xFFFF)))
    g6_frac = _f32_roundtrip(fp0 / F64_255)

    term1 = _f32_roundtrip(g6_frac * one_m_gb)
    sqrt_term = _f32_roundtrip(math.sqrt(g6_frac) * gb)
    t10 = _f32_roundtrip(g6_frac * term1)
    result = _f32_roundtrip(sqrt_term + t10)
    return f32_to_u32(result)


def _inner_sample_u8(g1: int, g6_u32: int, gamma_a_u32: int) -> int:
    """0x3D48 inner — r4=(1-ga), fp2=gamma_a; sqrt*ga + (1-ga)*a^2."""
    ga = u32_to_f32(gamma_a_u32)
    one_m_ga = _f32_roundtrip(1.0 - ga)
    g6_f = u32_to_f32(g6_u32)

    a = _f32_roundtrip(g6_f * _f32_roundtrip(float(int(g1 & 0xFFFF)) / F64_63))
    sqrt_ga = _f32_roundtrip(math.sqrt(a) * ga)
    b = _f32_roundtrip(one_m_ga * a)
    c = _f32_roundtrip(b * a)
    result = _f32_roundtrip(sqrt_ga + c)
    return _clamp_u8_from_unit_float(result)


def simulate_geo_palette_lut_upload(
    *,
    gamma_a_u32: int,
    gamma_b_u32: int,
) -> bytearray:
    """Replay 0x3C80 colorxlat fill into a MODEL2_COLORXLAT-sized buffer."""
    cx = bytearray(MODEL2_COLORXLAT_SIZE)
    g2 = MODEL2_PALRAM_BASE
    r13_mask = 0xFFFF

    g13 = 0
    while True:
        g4_bank = ((g13 & r13_mask) << 3) + ((g13 & r13_mask) >> 2)
        g4_bank &= r13_mask
        g6_u32 = _outer_g6_u32(g4_bank, gamma_b_u32)

        g3 = g2 + 0x18000
        g0_ptr = g2 + 0x14000
        g7_ptr = g2 + 0x10000
        g1 = 0

        while True:
            val = _inner_sample_u8(g1, g6_u32, gamma_a_u32)
            _store_u16(cx, g3, val)
            g3 += 2
            g1 += 1
            _store_u16(cx, g0_ptr, val)
            _store_u16(cx, g7_ptr, val)
            g0_ptr += 2
            g7_ptr += 2
            g2 += 2
            if (g1 & r13_mask) > 0x3F:
                break

        tail = _clamp_u8_from_unit_float(u32_to_f32(g6_u32))
        g0_ptr = g2 + 0x18000
        g7_ptr = g2 + 0x14000
        g6_ptr = g2 + 0x10000
        g1 = 0xBF
        while True:
            _store_u16(cx, g0_ptr, tail)
            g0_ptr += 2
            g1 -= 1
            g4 = g1 & r13_mask
            _store_u16(cx, g7_ptr, tail)
            _store_u16(cx, g6_ptr, tail)
            g7_ptr += 2
            g6_ptr += 2
            g2 += 2
            if g4 == r13_mask:
                break

        g13 += 1
        if (g13 & r13_mask) > 31:
            break

    return cx


def colorxlat_nonzero_words(cx: bytes) -> int:
    n = len(cx) // 2
    return sum(1 for i in range(n) if struct.unpack_from("<H", cx, i * 2)[0])


COLORXLAT_G_WORD = 0x2000
COLORXLAT_B_WORD = 0x4000
BANK_COUNT = 32


def _channel_bank_match(lift: bytes, ref: bytes, base_word: int, *, banks: int) -> dict:
    words = banks * BANK_WORDS
    matches = 0
    mismatches: list[dict] = []
    for i in range(words):
        got = struct.unpack_from("<H", lift, (base_word + i) * 2)[0]
        exp = struct.unpack_from("<H", ref, (base_word + i) * 2)[0]
        if got == exp:
            matches += 1
        elif len(mismatches) < 4:
            mismatches.append({"word": base_word + i, "expected": exp, "got": got})
    return {
        "words": words,
        "banks": banks,
        "matches": matches,
        "ok": matches == words,
        "mismatches": mismatches,
    }


def compare_colorxlat(lift: bytes, ref: bytes, *, banks: int = BANK_COUNT) -> dict:
    """Byte-compare lift dump vs reference."""
    span = min(len(lift), len(ref))
    channels = {
        "r": _channel_bank_match(lift, ref, 0, banks=banks),
        "g": _channel_bank_match(lift, ref, COLORXLAT_G_WORD, banks=banks),
        "b": _channel_bank_match(lift, ref, COLORXLAT_B_WORD, banks=banks),
    }
    all_ok = all(channels[c]["ok"] for c in ("r", "g", "b"))
    bank0_ok = all(
        channels[c]["matches"] >= BANK_WORDS and channels[c]["ok"] or channels[c]["matches"] == BANK_WORDS
        for c in ("r", "g", "b")
    )
    # bank0-only shortcut
    bank0_only = all(
        _channel_bank_match(lift, ref, base, banks=1)["ok"] for base in (0, COLORXLAT_G_WORD, COLORXLAT_B_WORD)
    )

    mismatches: list[dict] = []
    if not all_ok:
        for off in range(span // 2):
            got = struct.unpack_from("<H", lift, off * 2)[0]
            exp = struct.unpack_from("<H", ref, off * 2)[0]
            if got != exp:
                mismatches.append(
                    {
                        "word_index": off,
                        "vaddr": f"0x{MODEL2_COLORXLAT_BASE + off * 2:08X}",
                        "expected": exp,
                        "got": got,
                    }
                )
                if len(mismatches) >= 8:
                    break

    match_bytes = sum(1 for i in range(span) if lift[i] == ref[i])
    return {
        "size": span,
        "match_bytes": match_bytes,
        "mismatch_bytes": span - match_bytes,
        "match_ratio": round(match_bytes / span, 6) if span else 0.0,
        "lift_nz_words": colorxlat_nonzero_words(lift),
        "ref_nz_words": colorxlat_nonzero_words(ref),
        "channels": channels,
        "bank0_ok": bank0_only,
        "all_banks_ok": all_ok,
        "first_mismatches": mismatches,
        "ok": all_ok,
        "tier_note": (
            f"effect_match all {banks} banks R/G/B"
            if all_ok
            else (
                "effect_match bank0 only"
                if bank0_only
                else "upload mismatch — see first_mismatches"
            )
        ),
    }


def load_maincpu_deinterleaved(repo_root: Path | None = None) -> bytes:
    root = repo_root or Path(__file__).resolve().parents[2]
    for path in (
        root / "out" / "i960" / "maincpu_deinterleaved.bin",
        root / "decomp" / "out" / "i960" / "maincpu_deinterleaved.bin",
    ):
        if path.is_file():
            return path.read_bytes()
    raise FileNotFoundError(f"maincpu ROM not found under {root}/out/i960/")


def colorxlat_bytes_to_state_words(cx: bytes, state) -> None:
    """Copy raw colorxlat.bin bytes into PaletteState.colorxlat words."""
    from tools.model2_palette import COLORXLAT_WORDS

    n = min(len(cx) // 2, COLORXLAT_WORDS)
    for i in range(n):
        state.colorxlat[i] = struct.unpack_from("<H", cx, i * 2)[0]


def apply_validated_upload_colorxlat(state, maincpu: bytes, lift_cx_bytes: bytes) -> dict:
    """Use lift upload colorxlat when validated; else fill from disasm ref sim.

    geo_renderer_init @ 0x4350 overwrites upload output — full palette dumps need
    replacement with the validated upload table (same bytes as geo_palette_lut_upload).
    """
    gamma_a = gamma_u32_from_maincpu(maincpu, WORKRAM_GAMMA_A)
    gamma_b = gamma_u32_from_maincpu(maincpu, WORKRAM_GAMMA_B)
    ref = simulate_geo_palette_lut_upload(gamma_a_u32=gamma_a, gamma_b_u32=gamma_b)
    span = min(len(lift_cx_bytes), len(ref))
    cmp = compare_colorxlat(lift_cx_bytes[:span], ref[:span])

    if cmp["all_banks_ok"]:
        return {
            "colorxlat_source": "validated_upload",
            "match_ratio": cmp["match_ratio"],
            "replaced": False,
        }

    colorxlat_bytes_to_state_words(ref, state)
    return {
        "colorxlat_source": "upload_ref",
        "match_ratio": cmp["match_ratio"],
        "replaced": True,
        "note": "dump colorxlat differed from 0x3C80 ref (e.g. lumaram_init clobber)",
    }
