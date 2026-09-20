"""Model 2 palette / CGM static extraction (RE-backed, no MAME runtime).

Textured polygon color path (i960 / ``geo_palette_lut_upload`` @ ``0x3C80``,
``geo_lumaram_init`` @ ``0x4350``):

  texel → lumaram[lumabase + (texel<<4)>>1] scaled by draw luma → luma_idx (0..63)
        → colorxlat R/G/B banks selected by palram[colorbase+0x1000] color15
        → 8-bit RGB (gamma baked into colorxlat build via workram ``0x5A2C70``/``0x5A2C74``)

Do **not** apply MAME ``gamma_table`` to colorxlat outputs — that is CRT/display
emulation layered on top of values that already include upload gamma math.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from tools.i960_memory import MAIN_DATA_A, MAIN_DATA_SIZE, WORKRAM_BASE

CGM_MAGIC = b"CGM 1.0 "

# CPU mirrors of main_data / workram init images (disasm omits high nibbles).
LOW_DATA_MIRROR = 0x0020_0000
# Runtime staging @ 0x210830 is filled by 0x33454 from these DEF tables (not ROM-static).
COLORXLAT_DEF_R_VADDR = 0x0020_D830
COLORXLAT_DEF_G_VADDR = 0x0020_E830
COLORXLAT_DEF_B_VADDR = 0x0020_F830
# colorxlat_copy @ 0x330A0 reads staging after build (0x210830 family).
COLORXLAT_STAGING_R_VADDR = 0x0021_0830
COLORXLAT_STAGING_G_VADDR = 0x0021_1830
COLORXLAT_STAGING_B_VADDR = 0x0021_2830
COLORXLAT_SCALE_VADDR = 0x0021_3854  # workram: ld @ 0x33464
COLORXLAT_DEF_SCALE = 0x100  # i960 mulo scale (RE: 0x33454); not the float at 0x213854 mirror
PALRAM_FILL_SRC_VADDR = 0x005C_5670

# i960 / MAME Model 2 video RAM sizes
PALRAM_WORDS = 0x4000 // 2
COLORXLAT_WORDS = 0xC000 // 2
LUMARAM_BYTES = 0x8000

PALRAM_COLORBASE_WORD = 0x1000

COLORXLAT_R_WORD = 0x0000 // 2
COLORXLAT_G_WORD = 0x4000 // 2
COLORXLAT_B_WORD = 0x8000 // 2

# Course palette CGM blocks referenced from ROM 0x12D00 (desert scene init path).
COURSE_CGM_VADDRS = (
    0x028AF104,
    0x028CCAF8,
)

# Per-course CGM chains (extend as maincpu course-init paths are disassembled).
COURSE_CGM_VADDRS_BY_ID: dict[str, tuple[int, ...]] = {
    "desert": COURSE_CGM_VADDRS,
}

# ROM functions that touch palette RAM (maincpu).
PALETTE_ROM_FUNCTIONS = (
    {"addr": 0x00026750, "role": "palram_fill", "src_workram": 0x005C5670, "dst": 0x01800000},
    {"addr": 0x000267B0, "role": "palram_colorbase_fill", "src_workram": 0x005FB89E, "dst": 0x01802000},
    {"addr": 0x000272C4, "role": "colorxlat_dispatch", "calls": 0x00033018},
    {
        "addr": 0x000330A0,
        "role": "colorxlat_copy",
        "src_tables": (COLORXLAT_STAGING_R_VADDR, 0x0021_1830, 0x0021_2830),
        "dst": 0x01810000,
    },
    {
        "addr": 0x00033454,
        "role": "colorxlat_build",
        "def_tables": (COLORXLAT_DEF_R_VADDR, COLORXLAT_DEF_G_VADDR, COLORXLAT_DEF_B_VADDR),
        "scale_vaddr": COLORXLAT_SCALE_VADDR,
    },
    {"addr": 0x00033300, "role": "palram_upload_dispatch"},
    {"addr": 0x000333C8, "role": "palram_colorbase_copy", "src_workram": 0x005FB89E, "dst": 0x01802000},
    {"addr": 0x00029EB0, "role": "cgm_parse", "calls": 0x00029C10},
    {"addr": 0x00029C10, "role": "cgm_upload", "staging": (0x01000000, 0x01004000)},
    {"addr": 0x00012D00, "role": "course_palette_init", "cgm": COURSE_CGM_VADDRS},
)


def vaddr_to_rom_offset(vaddr: int) -> int:
    """Map CPU vaddr to byte offset in deinterleaved main_data ROM."""
    if MAIN_DATA_A <= vaddr < MAIN_DATA_A + MAIN_DATA_SIZE:
        return vaddr - MAIN_DATA_A
    if LOW_DATA_MIRROR <= vaddr < LOW_DATA_MIRROR + MAIN_DATA_SIZE:
        return vaddr - LOW_DATA_MIRROR
    if WORKRAM_BASE <= vaddr < WORKRAM_BASE + MAIN_DATA_SIZE:
        return vaddr - WORKRAM_BASE
    raise ValueError(f"Address not in static ROM mirror: 0x{vaddr:08X}")


def gamma_correct(value: int) -> int:
    """MAME model2 CRT ``gamma_table`` only — not used on i960 texel lookup."""
    raw = max((int(value) - 64) * 255 / 191.0, 0.0)
    return int(raw) & 0xFF


def rgb15(value: int) -> tuple[int, int, int]:
    """Unpack Model 2 15-bit xGGGGGRRRRRBBBBB to 8-bit channels (pre-gamma)."""
    v = value & 0x7FFF
    r = ((v >> 0) & 0x1F) << 3
    g = ((v >> 5) & 0x1F) << 3
    b = ((v >> 10) & 0x1F) << 3
    return r, g, b


@dataclass(frozen=True)
class CgmBlock:
    vaddr: int
    rom_offset: int
    version: int
    data_offset: int


@dataclass
class PaletteState:
    palram: list[int] = field(default_factory=lambda: [0] * PALRAM_WORDS)
    colorxlat: list[int] = field(default_factory=lambda: [0] * COLORXLAT_WORDS)
    lumaram: bytearray = field(default_factory=lambda: bytearray(LUMARAM_BYTES))
    cgm_blocks_loaded: list[int] = field(default_factory=list)
    cgm_pending_1111_bytes: int = 0
    cgm_1111_slots: dict[int, int] = field(default_factory=dict)

    @classmethod
    def with_defaults(cls) -> PaletteState:
        state = cls()
        state._install_default_colorxlat()
        state._install_default_lumaram()
        return state

    def _install_default_colorxlat(self) -> None:
        """Synthetic per-bank channel ramps when hardware colorxlat is unavailable.

        MAME indexes separate R/G/B colorxlat banks from palram color15 bits.
        Identical gray ramps in all banks collapse every material to monochrome;
        scale each channel table by bank index so color15 selectors produce hue.
        """
        for bank in range(32):
            for luma in range(64):
                v = 64 + (luma * 191) // 63
                base = bank * 256 + luma
                if bank == 0:
                    floor = v >> 2
                    self.colorxlat[COLORXLAT_R_WORD + base] = floor
                    self.colorxlat[COLORXLAT_G_WORD + base] = floor
                    self.colorxlat[COLORXLAT_B_WORD + base] = floor
                else:
                    self.colorxlat[COLORXLAT_R_WORD + base] = min(255, v * bank // 31)
                    self.colorxlat[COLORXLAT_G_WORD + base] = min(255, v * bank // 31)
                    self.colorxlat[COLORXLAT_B_WORD + base] = min(255, v * bank // 31)

    def _install_default_lumaram(self) -> None:
        # MAME: lumaram[lumabase + (filtered_texel >> 1)]; 4-bit index n → offset n*8.
        for i in range(LUMARAM_BYTES):
            slot = (i % 128) // 8
            self.lumaram[i] = min(0x3F, 8 + slot * 3)

    def pal_colorbase_entry(self, colorbase: int) -> int:
        """MAME: palram[(colorbase + 0x1000)] & 0x7fff — no slot aliasing."""
        slot = colorbase & 0x3FF
        idx = PALRAM_COLORBASE_WORD + slot
        if idx < len(self.palram):
            return self.palram[idx] & 0x7FFF
        return 0

    def lookup_texel(
        self,
        texel: int,
        colorbase: int,
        lumabase: int,
        *,
        luma: int = 255,
    ) -> tuple[int, int, int]:
        """Texel color: lumaram row index → colorxlat banks (upload gamma already baked)."""
        texel &= 0x0F
        color15 = self.pal_colorbase_entry(colorbase)
        r_bank = ((color15 >> 0) & 0x1F) * 256
        g_bank = ((color15 >> 5) & 0x1F) * 256
        b_bank = ((color15 >> 10) & 0x1F) * 256

        luma_idx = self.lumaram[lumabase + ((texel << 4) >> 1)]
        luma_idx = (int(luma_idx) * int(luma)) // 256
        luma_idx = min(luma_idx, 0x3F)

        tr = self.colorxlat[COLORXLAT_R_WORD + r_bank + luma_idx] & 0xFF
        tg = self.colorxlat[COLORXLAT_G_WORD + g_bank + luma_idx] & 0xFF
        tb = self.colorxlat[COLORXLAT_B_WORD + b_bank + luma_idx] & 0xFF
        return (tr, tg, tb)

    def lookup_rgb15(self, color15: int, *, luma: int = 0x3F) -> tuple[int, int, int]:
        """Solid-polygon path using a direct 15-bit palette entry."""
        color15 &= 0x7FFF
        r_bank = ((color15 >> 0) & 0x1F) * 256
        g_bank = ((color15 >> 5) & 0x1F) * 256
        b_bank = ((color15 >> 10) & 0x1F) * 256
        luma_idx = min(int(luma) >> 2, 0x3F)
        tr = self.colorxlat[COLORXLAT_R_WORD + r_bank + luma_idx] & 0xFF
        tg = self.colorxlat[COLORXLAT_G_WORD + g_bank + luma_idx] & 0xFF
        tb = self.colorxlat[COLORXLAT_B_WORD + b_bank + luma_idx] & 0xFF
        return (tr, tg, tb)


def find_cgm_blocks(main_data: bytes, *, base_vaddr: int = MAIN_DATA_A) -> list[CgmBlock]:
    blocks: list[CgmBlock] = []
    start = 0
    while True:
        off = main_data.find(CGM_MAGIC, start)
        if off < 0:
            break
        version = main_data[off + 8] if off + 8 < len(main_data) else 0
        data_offset = off + 10
        if data_offset & 1:
            data_offset += 1
        blocks.append(
            CgmBlock(
                vaddr=base_vaddr + off,
                rom_offset=off,
                version=version,
                data_offset=data_offset,
            )
        )
        start = off + 1
    return blocks


def _read_u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _is_palette15(word: int) -> bool:
    if word == 0:
        return False
    if word == 0xFFFF:
        return False
    # Model 2 palette entries use 15-bit color space (high bit often set).
    return (word & 0x7FFF) >= 0x0800 or (word & 0x7C00) != 0


def parse_cgm_palette_colors(data: bytes, block: CgmBlock) -> list[int]:
    """Course CGM blocks: leading run of 15-bit palette colors before record tags."""
    colors: list[int] = []
    off = block.data_offset
    limit = min(len(data), off + 4096)
    while off + 1 < limit:
        word = _read_u16(data, off)
        if word == 0xFFFF:
            if colors:
                break
            off += 2
            continue
        if word == 0 and off + 3 < limit:
            nxt = _read_u16(data, off + 2)
            if 0 < nxt < 0x80:
                break
        if word <= 0x7FFF:
            colors.append(word & 0x7FFF)
            off += 2
            continue
        break
    return colors


def _write_colorbase(state: PaletteState, slot: int, color15: int) -> None:
    """Write one colorbase word @ palram[0x1000 + slot] (10-bit slot index, no wrap)."""
    if slot < 0 or slot > 0x3FF:
        return
    idx = PALRAM_COLORBASE_WORD + slot
    if idx < len(state.palram) and color15 & 0x7FFF:
        state.palram[idx] = color15 & 0x7FFF


def parse_cgm_colorbase_block(data: bytes, block: CgmBlock) -> list[tuple[int, int]]:
    """Parse course CGM palette blocks (v9/v16) per ROM 0x12D00 / 0x29EB0 uploads."""
    off = block.data_offset
    if off + 2 > len(data):
        return []

    if block.version == 9:
        color15 = _read_u16(data, off) & 0x7FFF
        return [(0, color15)] if color15 else []

    if block.version == 16:
        w0 = _read_u16(data, off)
        off += 2
        if w0 == 0xFFFF and off + 1 < len(data):
            off += 0  # colors follow immediately after 0xffff
        entries: list[tuple[int, int]] = []
        slot = 1
        while off + 1 < len(data) and slot < 0x400:
            word = _read_u16(data, off)
            if word == 0xFFFF or word == 0:
                break
            if word <= 0x7FFF:
                entries.append((slot, word))
                slot += 1
                off += 2
                continue
            break
        return entries

    colors = parse_cgm_palette_colors(data, block)
    return [(i, c) for i, c in enumerate(colors)]


def load_course_cgm_palram(state: PaletteState, main_data: bytes) -> None:
    """Apply course-init CGM blocks referenced from ROM 0x12D00."""
    blocks = find_cgm_blocks(main_data)
    by_vaddr = {b.vaddr: b for b in blocks}
    ordered = [by_vaddr[v] for v in COURSE_CGM_VADDRS if v in by_vaddr]
    for block in ordered:
        for slot, color15 in parse_cgm_colorbase_block(main_data, block):
            _write_colorbase(state, slot, color15)
        state.cgm_blocks_loaded.append(block.vaddr)


def parse_cgm_v1_colorxlat(data: bytes, block: CgmBlock) -> list[int] | None:
    """Version 1 blocks: type-2 record holds colorxlat u16 stream."""
    off = block.data_offset
    if off + 8 > len(data):
        return None
    if _read_u16(data, off) != 2:
        return None
    count = _read_u16(data, off + 6)
    if count <= 0 or count > 512:
        return None
    values: list[int] = []
    data_off = off + 8
    for i in range(count):
        if data_off + 1 >= len(data):
            break
        values.append(_read_u16(data, data_off) & 0xFF)
        data_off += 2
    return values if len(values) >= 64 else None


def _install_colorxlat_bytes(state: PaletteState, ramp: list[int]) -> None:
    """Map a flat u8 ramp into all 32 banks (fallback when ROM tables are absent)."""
    for bank in range(32):
        for luma in range(64):
            src = ramp[min(luma, len(ramp) - 1)] if ramp else min(255, luma * 4)
            base = bank * 256 + luma
            state.colorxlat[COLORXLAT_R_WORD + base] = src
            state.colorxlat[COLORXLAT_G_WORD + base] = src
            state.colorxlat[COLORXLAT_B_WORD + base] = src


_COLORXLAT_BYTE_MASK = 0x00FF00FF


def _scaled_colorxlat_byte(byte: int, scale: int) -> int:
    """One byte lane after mulo by scale @ ROM 0x33454 (all channels >>8)."""
    return ((byte * scale) >> 8) & 0xFF


def _def_word_to_lane_bytes(word: int, scale: int) -> tuple[int, int]:
    """Each DEF-table u32 yields two u8 entries (mask 0x00ff00ff @ 0x334D4)."""
    masked = word & _COLORXLAT_BYTE_MASK
    low = _scaled_colorxlat_byte(masked & 0xFF, scale)
    high = _scaled_colorxlat_byte((masked >> 16) & 0xFF, scale)
    return low, high


def _build_colorxlat_bank_from_def(
    main_data: bytes,
    bank_index: int,
    *,
    scale: int,
) -> tuple[list[int], list[int], list[int]]:
    """Replicate colorxlat build @ ROM 0x33454 (16×u32 → 32 bytes / channel / bank)."""
    base_off = bank_index << 7
    src_r = vaddr_to_rom_offset(COLORXLAT_DEF_R_VADDR) + base_off
    src_g = vaddr_to_rom_offset(COLORXLAT_DEF_G_VADDR) + base_off
    src_b = vaddr_to_rom_offset(COLORXLAT_DEF_B_VADDR) + base_off
    r_vals: list[int] = []
    g_vals: list[int] = []
    b_vals: list[int] = []
    # ROM 0x33454: 32 DEF dwords per bank per channel (g1 = 0..31).
    for _ in range(32):
        if src_r + 3 >= len(main_data) or src_g + 3 >= len(main_data) or src_b + 3 >= len(main_data):
            break
        d_word = struct.unpack_from("<I", main_data, src_r)[0]
        e_word = struct.unpack_from("<I", main_data, src_g)[0]
        f_word = struct.unpack_from("<I", main_data, src_b)[0]
        src_r += 4
        src_g += 4
        src_b += 4
        r0, r1 = _def_word_to_lane_bytes(d_word, scale)
        g0, g1 = _def_word_to_lane_bytes(e_word, scale)
        b0, b1 = _def_word_to_lane_bytes(f_word, scale)
        r_vals.extend((r0, r1))
        g_vals.extend((g0, g1))
        b_vals.extend((b0, b1))
    if r_vals and len(r_vals) < 32:
        pad_r, pad_g, pad_b = r_vals[-1], g_vals[-1], b_vals[-1]
        while len(r_vals) < 32:
            r_vals.append(pad_r)
            g_vals.append(pad_g)
            b_vals.append(pad_b)
    return r_vals, g_vals, b_vals


def _expand_colorxlat_lane(values: list[int]) -> list[int]:
    """Expand DEF-table bytes to 64 luma slots (MAME indexes 0..0x3f)."""
    if not values:
        return [0] * 64
    if len(values) >= 64:
        return values[:64]
    if len(values) == 1:
        return values * 64
    out: list[int] = []
    for i in range(len(values) - 1):
        out.append(values[i])
        out.append((values[i] + values[i + 1]) // 2)
    out.append(values[-1])
    while len(out) < 64:
        out.append(values[-1])
    return out[:64]


def _colorxlat_lane_looks_like_ramp(values: list[int]) -> bool:
    """Monotone-ish ramps in staging mirror or post-build tables."""
    if len(values) < 16:
        return False
    sample = values[:32]
    if max(sample) < 8:
        return False
    nondecreasing = sum(1 for i in range(len(sample) - 1) if sample[i + 1] >= sample[i] - 1)
    return nondecreasing >= (len(sample) - 1) * 3 // 5


def _def_colorxlat_build_looks_valid(r: list[int], g: list[int], b: list[int]) -> bool:
    """Accept ROM DEF tables @ 0x20d830 (0x33454 mask 0x00ff00ff lanes).

    Packed dwords yield paired high bytes with occasional 0x04/0x08 fillers — not
    monotone in file order, but peaks sit in the gamma-active range (>= 64).
    """
    if len(r) < 32 or len(g) < 32 or len(b) < 32:
        return False
    combined = r + g + b
    if max(combined) < 64:
        return False
    strong = [v for v in combined if v >= 32]
    return len(set(strong)) >= 8


def _colorxlat_build_looks_valid(r: list[int], g: list[int], b: list[int]) -> bool:
    """Reject empty tables; accept DEF builds or monotone staging ramps."""
    if len(r) < 32 or len(g) < 32 or len(b) < 32:
        return False
    combined = r + g + b
    if max(combined) < 8:
        return False
    if len(set(combined)) < 8:
        return False
    if _def_colorxlat_build_looks_valid(r, g, b):
        return True
    return (
        _colorxlat_lane_looks_like_ramp(r)
        and _colorxlat_lane_looks_like_ramp(g)
        and _colorxlat_lane_looks_like_ramp(b)
    )


def _staging_mirror_looks_valid(main_data: bytes) -> bool:
    """Reject static ROM mirrors that are uninitialized (not monotone ramps)."""
    try:
        src_r = vaddr_to_rom_offset(COLORXLAT_STAGING_R_VADDR)
        src_g = vaddr_to_rom_offset(COLORXLAT_STAGING_G_VADDR)
        src_b = vaddr_to_rom_offset(COLORXLAT_STAGING_B_VADDR)
    except ValueError:
        return False
    bank_off = 0
    if src_r + 63 >= len(main_data):
        return False
    r = list(main_data[src_r + bank_off : src_r + bank_off + 32])
    g = list(main_data[src_g + bank_off : src_g + bank_off + 32])
    b = list(main_data[src_b + bank_off : src_b + bank_off + 32])
    return _colorxlat_build_looks_valid(r, g, b)


def load_colorxlat_from_staging_mirror(state: PaletteState, main_data: bytes) -> bool:
    """Copy colorxlat built in workram staging @ 0x210830 (0x330A0 after 0x33454).

    Staging holds 32 bytes/channel/bank from the DEF build; 0x330A0 copies 128 bytes
    to hardware but only the first 32 are meaningful — expand to 64 luma slots.
    """
    if not _staging_mirror_looks_valid(main_data):
        return False
    try:
        src_r = vaddr_to_rom_offset(COLORXLAT_STAGING_R_VADDR)
        src_g = vaddr_to_rom_offset(COLORXLAT_STAGING_G_VADDR)
        src_b = vaddr_to_rom_offset(COLORXLAT_STAGING_B_VADDR)
    except ValueError:
        return False

    for bank in range(32):
        base = bank * 256
        bank_off = bank << 7
        for ci, src in enumerate((src_r, src_g, src_b)):
            off = src + bank_off
            if off + 31 >= len(main_data):
                return False
            lane = list(main_data[off : off + 32])
            expanded = _expand_colorxlat_lane(lane)
            word_base = (COLORXLAT_R_WORD, COLORXLAT_G_WORD, COLORXLAT_B_WORD)[ci]
            for i in range(64):
                state.colorxlat[word_base + base + i] = expanded[i]
    return True


def load_colorxlat_from_rom(state: PaletteState, main_data: bytes) -> bool:
    """Build colorxlat from ROM DEF tables @ 0x20d830 (maincpu 0x33454 → 0x330A0)."""
    scale = COLORXLAT_DEF_SCALE
    sample_r, sample_g, sample_b = _build_colorxlat_bank_from_def(main_data, 0, scale=scale)
    if not _colorxlat_build_looks_valid(sample_r, sample_g, sample_b):
        return False

    for bank in range(32):
        r_lane, g_lane, b_lane = _build_colorxlat_bank_from_def(main_data, bank, scale=scale)
        r_exp = _expand_colorxlat_lane(r_lane)
        g_exp = _expand_colorxlat_lane(g_lane)
        b_exp = _expand_colorxlat_lane(b_lane)
        base = bank * 256
        for i in range(64):
            state.colorxlat[COLORXLAT_R_WORD + base + i] = r_exp[i]
            state.colorxlat[COLORXLAT_G_WORD + base + i] = g_exp[i]
            state.colorxlat[COLORXLAT_B_WORD + base + i] = b_exp[i]
    return True


def load_colorxlat_from_main_data(state: PaletteState, main_data: bytes) -> None:
    """Build colorxlat: ROM DEF 0x33454 build, then staging mirror, then linear default."""
    if load_colorxlat_from_rom(state, main_data):
        return
    if load_colorxlat_from_staging_mirror(state, main_data):
        return
    state._install_default_colorxlat()


def load_palram_colorbase_table_from_rom(state: PaletteState, main_data: bytes) -> None:
    """Merge u16 entries from workram static image @ 0x5FB89E when count @ 0x5FB89C > 0."""
    try:
        count_off = vaddr_to_rom_offset(0x005FB89C)
        off = vaddr_to_rom_offset(0x005FB89E)
    except ValueError:
        return
    if _read_u16(main_data, count_off) == 0:
        return
    for slot in range(0x400):
        byte_off = off + slot * 2
        if byte_off + 1 >= len(main_data):
            break
        color15 = _read_u16(main_data, byte_off) & 0x7FFF
        if color15:
            _write_colorbase(state, slot, color15)


def load_palram_fill_from_rom(state: PaletteState, main_data: bytes) -> None:
    """Replay palram_fill @ ROM 0x26750 (10×16-word groups from workram 0x5C5670)."""
    src = vaddr_to_rom_offset(PALRAM_FILL_SRC_VADDR)
    dst = 0
    for _group in range(10):
        if dst < len(state.palram):
            state.palram[dst] = 0
        dst += 1
        if src + 1 < len(main_data):
            state.palram[dst] = _read_u16(main_data, src) & 0x7FFF
            src += 2
            dst += 1
        for _ in range(13):
            if dst < len(state.palram):
                state.palram[dst] = 0
            dst += 1


def _skip_cgm_color_run(data: bytes, off: int) -> int:
    """Advance past leading 0xFFFF and version-9/16 color u16 list."""
    limit = len(data)
    if off + 1 < limit and _read_u16(data, off) == 0xFFFF:
        off += 2
    while off + 1 < limit:
        word = _read_u16(data, off)
        if word in (0xFFFF, 0):
            break
        if word <= 0x7FFF:
            off += 2
            continue
        break
    while off + 1 < limit and _read_u16(data, off) == 0xFFFF:
        off += 2
    return off


def _iter_cgm_v16_records(data: bytes, block: CgmBlock) -> list[tuple[int, int, int]]:
    """Return (type, length, payload_start) for CGM v16 records after the color run."""
    if block.version != 16:
        return []
    off = _skip_cgm_color_run(data, block.data_offset)
    records: list[tuple[int, int, int]] = []
    limit = min(len(data), off + 8192)
    while off + 3 < limit:
        rec_type = _read_u16(data, off)
        rec_len = _read_u16(data, off + 2)
        off += 4
        if rec_type == 0 and rec_len == 0:
            break
        if rec_len < 0 or off + rec_len > limit:
            break
        records.append((rec_type, rec_len, off))
        off += rec_len
    return records


def apply_cgm_v16_lumaram_records(
    state: PaletteState,
    data: bytes,
    block: CgmBlock,
    *,
    lumaram_base: int = 0,
) -> int:
    """Apply CGM v16 type-0x10 lumaram byte records (course desert block)."""
    if block.version != 16:
        return 0
    off = _skip_cgm_color_run(data, block.data_offset)
    applied = 0
    limit = min(len(data), off + 4096)
    while off + 3 < limit:
        rec_type = _read_u16(data, off)
        rec_len = _read_u16(data, off + 2)
        off += 4
        if rec_type == 0 and rec_len == 0:
            break
        if rec_type == 0x0010 and 0 < rec_len <= 512 and off + rec_len <= limit:
            for i in range(rec_len):
                idx = lumaram_base + i
                if idx < len(state.lumaram):
                    state.lumaram[idx] = data[off + i]
            applied += 1
            off += rec_len
            continue
        break
    return applied


def load_cgm_colorbase_slots(state: PaletteState, main_data: bytes) -> None:
    """Merge colorbase slots from all CGM v9/v16 blocks (later blocks override)."""
    for block in find_cgm_blocks(main_data):
        if block.version not in (9, 16):
            continue
        for slot, color15 in parse_cgm_colorbase_block(main_data, block):
            _write_colorbase(state, slot, color15)


def load_palette_from_main_data(
    main_data: bytes,
    *,
    course_id: str | None = "desert",
) -> PaletteState:
    """Build palette state from ROM init (RE-backed CGM replay)."""
    from tools.model2_cgm import replay_course_cgm_blocks

    state = PaletteState()
    state._install_default_lumaram()

    load_colorxlat_from_main_data(state, main_data)

    try:
        load_palram_fill_from_rom(state, main_data)
    except (ValueError, IndexError):
        pass

    blocks = find_cgm_blocks(main_data)
    by_vaddr = {b.vaddr: b for b in blocks}
    cgm_vaddrs = COURSE_CGM_VADDRS_BY_ID.get(course_id or "desert", COURSE_CGM_VADDRS)
    course_blocks = tuple(by_vaddr[v] for v in cgm_vaddrs if v in by_vaddr)
    if course_blocks:
        replay = replay_course_cgm_blocks(state, main_data, course_blocks)
        state.cgm_blocks_loaded.extend(b.vaddr for b in course_blocks)
        state.cgm_pending_1111_bytes = replay.pending_1111_bytes
        state.cgm_1111_slots = dict(replay.replay_1111_slots)
    else:
        load_course_cgm_palram(state, main_data)

    try:
        load_palram_colorbase_table_from_rom(state, main_data)
    except (ValueError, IndexError):
        pass

    return state


def tex_header_colorbase(word3: int) -> int:
    return (word3 >> 6) & 0x3FF


def tex_header_lumabase(word1: int) -> int:
    return (word1 & 0xFF) << 7


def palette_report_dict(main_data: bytes) -> dict:
    blocks = find_cgm_blocks(main_data)
    state = load_palette_from_main_data(main_data)
    nonzero_pal = sum(1 for w in state.palram if w)
    return {
        "pipeline": {
            "texel": "lumaram[lumabase + (texel<<4)>>1] * luma / 256",
            "colorbase": "palram[0x1000 + colorbase] -> 5:5:5 bank indices",
            "colorxlat": "R/G/B @ 0x1810000 — built with gamma_a/b @ 0x5A2C70/74 in upload",
            "gamma_note": "upload/lumaram_init bake gamma into colorxlat; no second table at texel lookup",
        },
        "rom_functions": [
            {
                **{k: (f"0x{v:08X}" if k in ("addr", "dst", "src_workram", "calls") and isinstance(v, int) else v)
                   for k, v in entry.items()},
                **({"src_tables": [f"0x{v:08X}" for v in entry["src_tables"]]} if "src_tables" in entry else {}),
                **({"staging": [f"0x{v:08X}" for v in entry["staging"]]} if "staging" in entry else {}),
                **({"cgm": [f"0x{v:08X}" for v in entry["cgm"]]} if "cgm" in entry else {}),
            }
            for entry in PALETTE_ROM_FUNCTIONS
        ],
        "cgm_blocks_found": len(blocks),
        "cgm_versions": {str(b.version): sum(1 for x in blocks if x.version == b.version) for b in blocks},
        "course_cgm_loaded": [hex(v) for v in state.cgm_blocks_loaded],
        "cgm_pending_1111_bytes": state.cgm_pending_1111_bytes,
        "cgm_1111_slots_replayed": len(state.cgm_1111_slots),
        "palram_nonzero_words": nonzero_pal,
        "palram_colorbase_samples": {
            str(i): hex(state.palram[PALRAM_COLORBASE_WORD + i])
            for i in (0, 4, 6, 9, 11, 13, 27)
            if state.palram[PALRAM_COLORBASE_WORD + i]
        },
    }
