"""Texture RAM against MAME: python -m pytest tools/extract/tests

The ROM checks need ``SEGAMOD2_ROM_DIR`` (or config.toml) pointing at srallyc and
skip without it. The references are SHA-256 over MAME's ``textureram0`` and
``textureram1`` (first 1 MiB each), captured by ``tools/mame/srally_texram.lua``
during the attract loop, so no texture data is carried here.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from tools.extract.texture_ram import (
    SHEET_BYTES,
    SRALLY_TABLES,
    build_texture_ram,
    find_upload_tables,
    upload_bank,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, load_maincpu, resolve_rom_dir

# Course variant -> (sheet 0, sheet 1), MAME srallyc, attract loop.
MAME_SHA256 = {
    0: (
        "0b496d0178ae14ae61abe2cea5db097bdffafea4fb5081cdc68f7db416ac84bb",
        "b66e4bed7079b99ba182a8e60e19a90fa77e41efd3bd0f7d202b9994922bc975",
    ),
    1: (
        "92746120a8c294111f370665e6a0a9023f66a3830430bcc48c24d5152afa6503",
        "5d4b301672c36da82e902a15774bc7ef56d7591fce6cf1cbf44e2659c66c08ca",
    ),
}


@pytest.fixture(scope="module")
def roms():
    try:
        rom_dir = resolve_rom_dir()
        main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
        maincpu = load_maincpu(rom_dir)
    except FileNotFoundError as exc:
        pytest.skip(str(exc))
    return main_data, maincpu


def test_tables_found_in_rom_match_defaults(roms):
    _, maincpu = roms
    assert find_upload_tables(maincpu) == SRALLY_TABLES


@pytest.mark.parametrize("variant", sorted(MAME_SHA256))
def test_sheets_match_mame(roms, variant):
    main_data, maincpu = roms
    built = build_texture_ram(main_data, maincpu, variant)
    got = tuple(hashlib.sha256(sheet).hexdigest() for sheet in built)
    assert got == MAME_SHA256[variant]


def _numbered_banks() -> bytes:
    """main_data whose every halfword is its own index within its bank, plus the bank in bit 15."""
    out = bytearray(SRALLY_TABLES.bank_base)
    for bank in range(2):
        out += struct.pack("<524288H", *(((bank << 15) | (i & 0x7FFF)) for i in range(0x80000)))
    return bytes(out)


def test_full_size_area_is_a_flat_copy_and_mips_are_dealt():
    main_data = _numbered_banks()
    tex = bytearray(2 * SHEET_BYTES)
    upload_bank(tex, main_data, SRALLY_TABLES, 0, False)
    upload_bank(tex, main_data, SRALLY_TABLES, 1, True)
    sheet0, sheet1 = tex[:SHEET_BYTES], tex[SHEET_BYTES:]
    bank = SRALLY_TABLES.bank_base
    # Rows 0..0x2ff of each sheet are the start of its own bank.
    assert sheet0[: 0x300 * 0x400] == main_data[bank : bank + 0x300 * 0x400]
    assert sheet1[: 0x300 * 0x400] == main_data[bank + 0x100000 : bank + 0x100000 + 0x300 * 0x400]
    # Mip level 0 (rows 0x300..0x37f) goes whole to the other sheet.
    level0 = slice(0x300 * 0x400, 0x380 * 0x400)
    assert sheet1[level0] == main_data[bank + 0x300 * 0x400 : bank + 0x380 * 0x400]
    # Level 1's first row: 0x100 halfwords of each sheet from each bank, swapped halves.
    row = 0x380 * 0x400
    half = struct.unpack_from("<H", sheet0, row)[0], struct.unpack_from("<H", sheet0, row + 0x200)[0]
    assert half[0] >> 15 == 1 and half[1] >> 15 == 0
