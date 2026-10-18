"""Texture RAM as Sega Rally's own upload routine (maincpu ``0x3940``) builds it.

A bank is 1 MiB of ``main_data`` at ``0x02200000 + (index << 20)``, and a sheet
is 1 MiB of texture RAM: 1024 rows of 0x200 halfwords. The routine does not copy
a bank flat. It walks a table of records (``0x5A2880`` in work RAM, the ROM
mirror at ``maincpu + (vaddr - 0x59F000)``), each record a row count followed by
a list of runs in halfwords, ended by 0 or -1:

    count 1      0x60000 0x10000 -1           full-size area, then mip level 0
    count 0x40   0x100 0x100 0                mip level 1
    count 0x20   0x100 0x80 0x80 -1           mip level 2
    count 0x10   0x100 0x80 0x40 0x40 0       mip level 3
    count 8      0x100 0x80 0x40 0x20 0x20 -1 mip level 4
    count 4      0x100 0x80 0x40 0x20 0x10 -1 mip level 5

Both sheet pointers advance on every run and only one is written, so the sheets
swap after each run: what one sheet does not take, the other does. A -1 swaps
once more, and a 0 does not. The routine stops after the sixth record. Level 5
adds up to 0x1F0 halfwords a row, not 0x200, so its rows drift, and levels 6-8
are never uploaded. That is what the board holds too.

The game uploads bank 0 onto sheet 0 at boot (``0x3740``), then the course's
bank onto sheet 1. The course's bank comes from a table indexed by the course
variant (``0x214354``). Every call site reads that table with the same
``ld table[g4*4], g0``.

The routine, its record table and the course's bank table are found in the
program ROM by the instructions that use them, so any revision whose code has
the same shape works. ``SRALLY_TABLES`` holds what that search finds in
srallyc, for callers that have main_data but no program ROM. Checked byte for
byte against MAME's ``textureram0``/``textureram1`` for srallyc:
``tools/mame/srally_texram.lua`` takes the capture, and
``python -m tools.extract.texture_ram --check`` compares against it.
"""

from __future__ import annotations

import argparse
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, load_maincpu, resolve_rom_dir

SHEET_BYTES = 0x10_0000
MAIN_DATA_VADDR = 0x0200_0000
WORKRAM_ROM_MIRROR = 0x59_F000  # workram vaddr - this = maincpu offset
RECORD_STRIDE = 8  # words; the routine steps the record index by 8
RECORD_LAST = 47  # ... while it is <= 31 + 16

# Instruction words the tables are found by.
LDA_DISP_G0_G0 = 0x8C84_3400  # lda disp(g0), g0 — the bank base
LD_TABLE_G4_G4 = 0x90A0_3914  # ld disp[g4*4], g4 — the record table
LD_TABLE_G4_G0 = 0x9080_3914  # ld disp[g4*4], g0 — the course's bank table
MOV_1_G1 = 0x5C88_1E01  # mov 1, g1 — upload onto sheet 1
CALL = 0x09

# Course names to the variant index at 0x214354. MAME's attract loop runs
# variants 0 and 1; the rest are named by their banks' art (3 carries the
# LAKESIDE signs). Championship is a mode, not a course, and opens on desert.
COURSE_VARIANTS = {"desert": 0, "forest": 1, "mountain": 2, "lakeside": 3, "championship": 0}


@dataclass(frozen=True)
class UploadTables:
    routine: int  # maincpu offset of the upload routine
    bank_base: int  # main_data offset of bank 0
    records: tuple[int, ...]  # the record table, as signed words
    course_banks: tuple[int, ...]  # bank index by course variant


# What find_upload_tables() reads out of srallyc's program ROM.
SRALLY_TABLES = UploadTables(
    routine=0x3940,
    bank_base=0x20_0000,
    records=(
        1, 0x60000, 0x10000, -1, 0, 0, 0, 0,
        0x40, 0x100, 0x100, 0, 0, 0, 0, 0,
        0x20, 0x100, 0x80, 0x80, -1, 0, 0, 0,
        0x10, 0x100, 0x80, 0x40, 0x40, 0, 0, 0,
        8, 0x100, 0x80, 0x40, 0x20, 0x20, -1, 0,
        4, 0x100, 0x80, 0x40, 0x20, 0x10, -1, 0,
    ),
    course_banks=(2, 3, 4, 5, 2, 1, 1, 1),
)


def _u32(rom: bytes, offset: int) -> int:
    return struct.unpack_from("<I", rom, offset)[0]


def _s32(rom: bytes, offset: int) -> int:
    return struct.unpack_from("<i", rom, offset)[0]


def _call_target(rom: bytes, at: int) -> int | None:
    word = _u32(rom, at)
    if word >> 24 != CALL:
        return None
    disp = (word >> 2) & 0x3F_FFFF
    if disp & 0x20_0000:
        disp -= 0x40_0000
    return at + disp * 4


def find_upload_tables(maincpu: bytes) -> UploadTables:
    """Find the upload routine and its two tables in a program ROM image."""
    routine = bank_base = None
    for at in range(0, len(maincpu) - 8, 4):
        if _u32(maincpu, at) == LDA_DISP_G0_G0 and _u32(maincpu, at + 4) == 0x0220_0000:
            routine, bank_base = at - 8, _u32(maincpu, at + 4) - MAIN_DATA_VADDR
            break
    if routine is None:
        raise ValueError("texture upload routine not found (no lda 0x2200000(g0), g0)")

    record_vaddr = None
    for at in range(routine, routine + 0x100, 4):
        if _u32(maincpu, at) == LD_TABLE_G4_G4:
            record_vaddr = _u32(maincpu, at + 4)
            break
    if record_vaddr is None:
        raise ValueError(f"record table load not found in the routine at 0x{routine:x}")
    record_at = record_vaddr - WORKRAM_ROM_MIRROR
    records = tuple(_s32(maincpu, record_at + 4 * i) for i in range(RECORD_LAST + 1))

    # Every call onto sheet 1 loads its bank index from the same table.
    tables: Counter[int] = Counter()
    for at in range(0, len(maincpu) - 4, 4):
        if _call_target(maincpu, at) != routine:
            continue
        window = range(max(0, at - 0x20), at, 4)
        if not any(_u32(maincpu, a) == MOV_1_G1 for a in window):
            continue
        for a in window:
            if _u32(maincpu, a) == LD_TABLE_G4_G0:
                tables[_u32(maincpu, a + 4)] += 1
    if not tables:
        raise ValueError(f"no call loads a course bank for the routine at 0x{routine:x}")
    course_at = tables.most_common(1)[0][0] - WORKRAM_ROM_MIRROR
    course_banks = tuple(_s32(maincpu, course_at + 4 * i) for i in range(8))
    return UploadTables(routine, bank_base, records, course_banks)


def upload_bank(tex: bytearray, main_data: bytes, tables: UploadTables, index: int, to_sheet1: bool) -> None:
    """Port of the routine: deal bank ``index`` out between the two sheets.

    ``tex`` is both sheets, sheet 0 then sheet 1, as texture RAM bytes.
    """
    src = tables.bank_base + (index << 20)
    near, far = (SHEET_BYTES, 0) if to_sheet1 else (0, SHEET_BYTES)
    records = tables.records
    for rec in range(0, RECORD_LAST + 1, RECORD_STRIDE):
        for _ in range(records[rec]):
            k = rec + 1
            while True:
                n = records[k]
                k += 1
                if n <= 0:
                    if n < 0:
                        near, far = far, near
                    break
                tex[near : near + 2 * n] = main_data[src : src + 2 * n]
                src += 2 * n
                near += 2 * n
                far += 2 * n
                near, far = far, near


def build_texture_ram(
    main_data: bytes, maincpu: bytes | None = None, course: str | int | None = "desert"
) -> tuple[bytes, bytes]:
    """Both sheets as the board holds them once ``course`` is loaded.

    ``course`` is a name from ``COURSE_VARIANTS`` or a variant index, or None
    for the boot bank alone. Without ``maincpu`` the tables are srallyc's.
    """
    tables = find_upload_tables(maincpu) if maincpu is not None else SRALLY_TABLES
    tex = bytearray(2 * SHEET_BYTES)
    upload_bank(tex, main_data, tables, 0, False)
    if course is not None:
        if isinstance(course, str) and course not in COURSE_VARIANTS:
            raise ValueError(f"unknown course {course!r}; known: {', '.join(COURSE_VARIANTS)}")
        variant = COURSE_VARIANTS[course] if isinstance(course, str) else course
        upload_bank(tex, main_data, tables, tables.course_banks[variant], True)
    return bytes(tex[:SHEET_BYTES]), bytes(tex[SHEET_BYTES:])


def sheet_words(sheet: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(sheet) // 4}I", sheet))


def load_texture_sheets(rom_dir: Path, course: str | int | None = "desert") -> tuple[list[int], list[int]]:
    """Both sheets as u32 word lists, the form ``textures.get_texel`` reads."""
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    sheet0, sheet1 = build_texture_ram(main_data, load_maincpu(rom_dir), course)
    return sheet_words(sheet0), sheet_words(sheet1)


def check_capture(rom_dir: Path, sheet0: Path, sheet1: Path, variant: int) -> bool:
    """Compare against a MAME capture; prints the first differing halfword."""
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    ours = build_texture_ram(main_data, load_maincpu(rom_dir), variant)
    ok = True
    for index, (built, path) in enumerate(zip(ours, (sheet0, sheet1))):
        captured = path.read_bytes()[:SHEET_BYTES]
        bad = [k for k in range(0, SHEET_BYTES, 2) if built[k : k + 2] != captured[k : k + 2]]
        if bad:
            ok = False
            k = bad[0]
            print(f"sheet {index}: {len(bad)} halfwords differ, first at row 0x{k // 0x400:x} halfword 0x{(k % 0x400) // 2:x}")
        else:
            print(f"sheet {index}: identical")
    return ok


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--check", nargs=2, type=Path, metavar=("SHEET0", "SHEET1"), help="MAME capture to compare with")
    parser.add_argument("--variant", type=int, default=0, help="course variant the capture was taken on")
    args = parser.parse_args()
    rom_dir = resolve_rom_dir(args.rom_dir)
    tables = find_upload_tables(load_maincpu(rom_dir))
    print(f"upload routine 0x{tables.routine:x}, bank 0 at main_data 0x{tables.bank_base:x}")
    print(f"course banks by variant: {list(tables.course_banks)}")
    if args.check and not check_capture(rom_dir, args.check[0], args.check[1], args.variant):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
