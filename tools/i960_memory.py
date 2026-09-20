"""Sega Model 2A (srallyc) i960 memory map — from MAME model2.cpp + i960.cpp."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# i960 program ROM (maincpu region, deinterleaved EPROM pair).
MAINCPU_BASE = 0x0000_0000
MAINCPU_SIZE = 0x0010_0000  # 1 MiB in srallyc-b dumps

WORKRAM_BASE = 0x0050_0000
WORKRAM_SIZE = 0x0010_0000

GEO_REGS_BASE = 0x0080_0000
GEO_REGS_SIZE = 0x0000_4000
GEO_WRITE_START = 0x0080_1008  # m_geo_write_start_address
GEO_READ_START = 0x0080_3008
GEO_PRG_FIFO = 0x0080_4000  # Model 2B+; 2A uses geo_w below 0x1000

MAIN_DATA_A = 0x0200_0000
MAIN_DATA_B = 0x0600_0000  # mirror
MAIN_DATA_SIZE = 0x0200_0000

BUFFERRAM_BASE = 0x0090_0000
BUFFERRAM_SIZE = 0x0002_0000

# Model 2A texel atlas banks (MAME model2_tgp_mem: tex0_w / tex1_w, 2 MiB each).
TEXTURERAM0_BASE = 0x1200_0000
TEXTURERAM1_BASE = 0x1240_0000
TEXTURERAM_BANK_SIZE = 0x0020_0000
TEXTURERAM0_MIRROR = 0x0020_0000  # 0x12000000–0x121fffff mirrored +0x200000

# Polygon luma table (separate from texel sheets; boot clears via stos @ 0x12800000).
# CPU window is 0x20000; MAME umask32(0x000000ff) packs to 0x8000 compact bytes.
LUMARAM_BASE = 0x1280_0000
LUMARAM_MAP_SIZE = 0x0002_0000
LUMARAM_SIZE = 0x0000_8000

# Copro FIFO (TGP program stream) — texture/geo upload sequences push here @ 0x00884000.
COPRO_FIFO = 0x0088_4000
COPRO_FN_PORT = 0x0088_0000

# Model 2A sound board UART (i8251 / uPD71051C) — MIDI into SCSP, not shared RAM.
SOUND_UART = 0x01C8_0000
SOUND_UART_STATUS = 0x01C8_0002
SOUND_CMD_TABLE = 0x005C_3CE0

# Static texel atlas banks in main_data (RE @ maincpu 0x003940 boot upload path).
TEXTURE_SHEET_BANK0_VADDR = 0x0220_0000
TEXTURE_SHEET_BANK1_VADDR = 0x0240_0000
TEXTURE_UPLOAD_FN = 0x0000_3940
TEXTURE_UPLOAD_STATE = 0x0020_227C
TEXTURE_UPLOAD_SRC_PTR = 0x0020_224C
TEXTURE_UPLOAD_DST_BASE = 0x0020_2240
TEXTURE_UPLOAD_DST_PTR = 0x0020_2244
TEXTURE_UPLOAD_JUMP_TABLE = 0x005A_2880

# Geo display-list opcodes (top bits of pushed dword).
GEO_OP_MATRIX = 0x0B << 23
GEO_OP_OBJECT = 0x01 << 23
GEO_OP_END = 0x0F << 23

# Master polygon catalog + placement stream (confirmed i960 xrefs @ ROM 0x023CC8).
CATALOG_VADDR = 0x0286_4B40
CATALOG_ENTRY_COUNT = 782
PLACEMENT_STREAM_VADDR = 0x0286_7C20
PLACEMENT_STREAM_WORD = (PLACEMENT_STREAM_VADDR - MAIN_DATA_A) // 4

# Legacy heuristic anchor (same as placement stream start).
PLACEMENT_GROUP_026_WORD = PLACEMENT_STREAM_WORD
PLACEMENT_GROUP_026_VADDR = PLACEMENT_STREAM_VADDR

# Scene / track workram (maincpu xrefs @ ROM 0x014760, 0x015694, 0x03F200).
SCENE_ROOT_TABLE_ROM = 0x0001_4760
SCENE_METADATA_TABLE = 0x005B_375C
CATALOG_INDEX_TABLE = 0x005B_4340  # ld 0x5b4340[0x20a8c4*4] @ 0x015694
SCENE_BATCH_INDEX = 0x0020_A8C4
COURSE_SELECT_INDEX = 0x0021_5380
COURSE_VARIANT_INDEX = 0x0021_4354
SCENE_MATRIX_BASE = 0x005B_42E0
PLACEMENT_CURSOR = 0x0020_B940  # advances per catalog obc @ geo_cluster 0x023CC8
GEO_WORKRAM_WRITE_PTR = 0x0020_A290  # staging pointer for 0x802008 geo context
CATALOG_DISPATCH_BY_SLOT = 0x005C_A210  # scene slot → catalog index @ ROM 0x2B538
CATALOG_DISPATCH_BY_QUAD = 0x005C_A280  # quad id → catalog index @ ROM 0x2B6A4
CATALOG_INDEX_BY_VARIANT = 0x005B_34E0  # ld @ 0x14B70 — variant & 3 → catalog row
COURSE_HANDLER_TABLE = 0x005D_E190  # ld @ 0x3F308 — indexed by 0x214354
COURSE_SCENE_ROOT_TABLE = 0x005D_DFC0  # ld @ 0x3F24C — scene root by course entry
COURSE_SCENE_POOL_PTR_ROM = 0x0003_EFD0  # seven workram pool roots for course select

# Vehicle draw path (geo_cluster_02 @ ROM 0x044F00 — separate from track placement stream).
VEHICLE_DRAW_CATALOG_FN = 0x0004_4F00
VEHICLE_GEO_FIFO = 0x0088_4000
VEHICLE_CATALOG_INDEX_A = 0x005E_3DF0  # ld @ 0x4509C, 0x45170
VEHICLE_CATALOG_INDEX_B = 0x005E_3DF8  # ld @ 0x45110
VEHICLE_MATRIX_TABLE = 0x005E_3E00  # lda [player*16] @ 0x44F84
VEHICLE_MATRIX_FLAGS = 0x005E_3E0C  # ldis [player*16] @ 0x4503C
VEHICLE_BATCH_CATALOG_INDEX = 0x005E_4220  # ld @ 0x452F0
VEHICLE_JUMP_TABLE = 0x005E_421C  # bx dispatch @ 0x451E4
VEHICLE_STATE_BYTE = 0x0021_7184
VEHICLE_MODE_FLAG = 0x0020_2098
VEHICLE_SELECT_SLOT = 0x0021_42C8
VEHICLE_SELECT_MODE = 0x0021_42D4
VEHICLE_SELECT_PARAM = 0x0021_42D0
VEHICLE_ASSEMBLY_CATALOG_ROM = 0x0003_4E40
VEHICLE_DRAW_LIST_ROM = 0x0003_4E88
VEHICLE_CATALOG_SINGLE_FN = 0x0002_B420  # car parts @ 0x2BB74
VEHICLE_CATALOG_BATCH_FN = 0x0002_B290
VEHICLE_CAR_REGISTER_FN = 0x0003_4F40  # after static catalog tables @ 0x34E40
VEHICLE_CAR_SETUP_FN = 0x0003_3E90  # texture/geo setup loop (fifo 0x884000)
TEXTURE_COPRO_CLUSTER_FN = 0x0005_04E90  # geo_cluster_03: runtime geo texture setup (fifo)
VEHICLE_CAR_LOOKUP_FN = 0x0002_B0B0  # resolves car record via 0x214354
VEHICLE_WORKRAM_ROOTS_ROM = 0x0003_EFC4  # → 0x5E2B20, 0x5E2BF0, …
VEHICLE_WORKRAM_EXT_ROM = 0x0003_F000  # → 0x5E41E0, 0x5E4350, …
VEHICLE_RACE_FX_CATALOG_A = 0x0286_7DC0  # ldq @ 0x456F4 (not car body)
VEHICLE_RACE_FX_CATALOG_B = 0x0286_7E00  # ldq @ 0x456A8
VEHICLE_DESCRIPTOR_ROM_START = 0x0004_3830
VEHICLE_DESCRIPTOR_ROM_END = 0x0004_3A00
VEHICLE_OBJECT_SETUP_FN = 0x0004_39D0  # geo_cluster near car ctor cluster
DRAW_CATALOG_SEQUENCE_FN = 0x0002_80D0  # iterates catalog rows → geo fifo
COPY_CATALOG_INDEX_TABLE_FN = 0x0002_82D0  # copies index arrays into workram
VEHICLE_STAGING_WORKRAM_A = 0x005E_2890  # arg to 0x280D0 @ 0x43A54
VEHICLE_STAGING_WORKRAM_B = 0x005E_2900  # arg @ 0x43AB0
CATALOG_INDEX_ROM_BIAS = 0x400  # descriptor words ≥ 0x400 decode as catalog_index - 0x400

RegionKind = Literal["rom", "ram", "mmio", "internal", "mmio_gap"]


@dataclass(frozen=True)
class MemoryMapEntry:
    """One row of the Model 2A i960 address map (MAME model2a_crx_mem chain)."""

    name: str
    start: int
    end: int  # inclusive
    kind: RegionKind
    access: str  # rw, r, w, rom
    handler: str  # MAME device::handler or special-case opcode
    mame_map: str  # model2_base_mem | model2_tgp_mem | model2a_crx_mem | i960.cpp
    notes: str = ""


# srallyc / srallycb: model2a_state::model2a → model2a_crx_mem
#   = model2_tgp_mem(model2_base_mem) + 2A CRX overrides.
MODEL2A_MEMORY_MAP: tuple[MemoryMapEntry, ...] = (
    # --- model2_base_mem ---
    MemoryMapEntry("maincpu_rom", 0x0000_0000, 0x001F_FFFF, "rom", "rom", "rom(maincpu)", "model2_base_mem"),
    MemoryMapEntry("workram", WORKRAM_BASE, WORKRAM_BASE + WORKRAM_SIZE - 1, "ram", "rw", "share(workram)", "model2_base_mem"),
    MemoryMapEntry("geo_regs", GEO_REGS_BASE, GEO_REGS_BASE + GEO_REGS_SIZE - 1, "mmio", "rw", "geo_r / geo_w", "model2_base_mem", "command FIFO below 0x81000; see geo_* aliases"),
    MemoryMapEntry("geo_write_start", GEO_WRITE_START, GEO_WRITE_START + 3, "mmio", "w", "geo_w", "model2_base_mem", "m_geo_write_start_address (bufferram write ptr)"),
    MemoryMapEntry("geo_write_start_read", 0x0080_2008, 0x0080_200B, "mmio", "r", "geo_r", "model2_base_mem", "read m_geo_write_start_address"),
    MemoryMapEntry("geo_read_start", GEO_READ_START, GEO_READ_START + 3, "mmio", "rw", "geo_w / geo_r", "model2_base_mem", "m_geo_read_start_address"),
    MemoryMapEntry("bufferram", BUFFERRAM_BASE, BUFFERRAM_BASE + BUFFERRAM_SIZE - 1, "ram", "rw", "share(bufferram)", "model2_base_mem", "mirror +0x60000"),
    MemoryMapEntry("fifo_control", 0x0098_0004, 0x0098_0007, "mmio", "r", "fifo_control_r", "model2_base_mem"),
    MemoryMapEntry("videoctl", 0x0098_000C, 0x0098_000F, "mmio", "rw", "videoctl_r / videoctl_w", "model2_base_mem"),
    MemoryMapEntry("tgpid", 0x0098_0030, 0x0098_003F, "mmio", "r", "tgpid_r", "model2_base_mem", "TGP id/version"),
    MemoryMapEntry("cpu_wait_states", 0x00E0_0000, 0x00E0_0037, "ram", "rw", "ram", "model2_base_mem", "CPU bus wait-state table"),
    MemoryMapEntry("irq_request", 0x00E8_0000, 0x00E8_0003, "mmio", "rw", "irq_request_r / irq_ack_w", "model2_base_mem"),
    MemoryMapEntry("irq_enable", 0x00E8_0004, 0x00E8_0007, "mmio", "rw", "irq_enable_r / irq_enable_w", "model2_base_mem"),
    MemoryMapEntry("timers", 0x00F0_0000, 0x00F0_000F, "mmio", "rw", "timers_r / timers_w", "model2_base_mem", "4× 25 MHz countdown timers → IRQ2"),
    MemoryMapEntry("tile_map", 0x0100_0000, 0x0100_FFFF, "mmio", "rw", "segas24_tile::tile_r/w", "model2_base_mem", "mirror +0x110000"),
    MemoryMapEntry("tile_absel", 0x0102_0000, 0x0102_0003, "mmio", "w", "nopw", "model2_base_mem", "ABSEL, always 0"),
    MemoryMapEntry("tile_xhout", 0x0104_0000, 0x0104_0001, "mmio", "w", "segas24_tile::xhout_w", "model2_base_mem", "H sync"),
    MemoryMapEntry("tile_xvout", 0x0106_0000, 0x0106_0001, "mmio", "w", "segas24_tile::xvout_w", "model2_base_mem", "V sync"),
    MemoryMapEntry("tile_vsync_switch", 0x0107_0000, 0x0107_0003, "mmio", "w", "nopw", "model2_base_mem"),
    MemoryMapEntry("tile_char", 0x0108_0000, 0x010F_FFFF, "mmio", "rw", "segas24_tile::char_r/w", "model2_base_mem", "mirror +0x100000"),
    MemoryMapEntry("palette", 0x0180_0000, 0x0180_3FFF, "mmio", "rw", "palette_r / palette_w", "model2_base_mem"),
    MemoryMapEntry("colorxlat", 0x0181_0000, 0x0181_BFFF, "mmio", "rw", "colorxlat_r / colorxlat_w", "model2_base_mem"),
    MemoryMapEntry("zclip", 0x0181_C000, 0x0181_C003, "mmio", "w", "model2_3d_zclip_w", "model2_base_mem"),
    MemoryMapEntry("m2comm_share", 0x01A0_0000, 0x01A0_3FFF, "mmio", "rw", "m2comm_device::share_r/w", "model2_base_mem", "mirror +0x10000"),
    MemoryMapEntry("m2comm_cn", 0x01A0_4000, 0x01A0_4000, "mmio", "rw", "m2comm_device::cn_r/w", "model2_base_mem"),
    MemoryMapEntry("m2comm_fg", 0x01A0_4002, 0x01A0_4002, "mmio", "rw", "m2comm_device::fg_r/w", "model2_base_mem"),
    MemoryMapEntry("backup_nvram", 0x01D0_0000, 0x01D0_3FFF, "ram", "rw", "share(backup1)", "model2_base_mem", "battery-backed SRAM"),
    MemoryMapEntry("main_data", MAIN_DATA_A, MAIN_DATA_A + MAIN_DATA_SIZE - 1, "rom", "rom", "region(main_data)", "model2_base_mem"),
    MemoryMapEntry("main_data_mirror", MAIN_DATA_B, MAIN_DATA_B + 0x00FF_FFFF, "rom", "rom", "region(main_data)+0x1000000", "model2_base_mem"),
    MemoryMapEntry("render_mode", 0x1000_0000, 0x101F_FFFF, "mmio", "rw", "render_mode_r / render_mode_w", "model2_base_mem"),
    MemoryMapEntry("polygon_count", 0x1040_0000, 0x105F_FFFF, "mmio", "r", "polygon_count_r", "model2_base_mem"),
    MemoryMapEntry("fbvram_a", 0x1160_0000, 0x1167_FFFF, "ram", "rw", "fbvram_bankA_r/w", "model2_base_mem"),
    MemoryMapEntry("fbvram_b", 0x1168_0000, 0x116F_FFFF, "ram", "rw", "fbvram_bankB_r/w", "model2_base_mem"),
    # --- model2_tgp_mem (Model 2 / 2A TGP) ---
    MemoryMapEntry("geo_prg_fifo", GEO_PRG_FIFO, GEO_PRG_FIFO + 0x3FFF, "mmio", "rw", "geo_prg_r / geo_prg_w", "model2_tgp_mem", "geo program stream to TGP"),
    MemoryMapEntry("copro_fn_port", COPRO_FN_PORT, COPRO_FN_PORT + 0x3FFF, "mmio", "w", "copro_function_port_w", "model2_tgp_mem", "TGP function select"),
    MemoryMapEntry("copro_fifo", COPRO_FIFO, COPRO_FIFO + 0x3FFF, "mmio", "rw", "copro_fifo_r / copro_fifo_w", "model2_tgp_mem", "matrix / geo opcode FIFO"),
    MemoryMapEntry("copro_ctl1", 0x0098_0000, 0x0098_0003, "mmio", "rw", "copro_ctl1_r / copro_ctl1_w", "model2_tgp_mem"),
    MemoryMapEntry("geo_ctl1", 0x0098_0008, 0x0098_000B, "mmio", "w", "geo_ctl1_w", "model2_tgp_mem"),
    MemoryMapEntry("polygon_count_status", 0x1080_0000, 0x1080_0003, "mmio", "r", "nopr", "model2_tgp_mem", "renderer polygon count (unimplemented read)"),
    MemoryMapEntry("textureram0", TEXTURERAM0_BASE, TEXTURERAM0_BASE + TEXTURERAM_BANK_SIZE - 1, "ram", "rw", "tex0_w", "model2_tgp_mem", "mirror +0x200000"),
    MemoryMapEntry("textureram1", TEXTURERAM1_BASE, TEXTURERAM1_BASE + TEXTURERAM_BANK_SIZE - 1, "ram", "rw", "tex1_w", "model2_tgp_mem", "mirror +0x200000"),
    MemoryMapEntry("lumaram", LUMARAM_BASE, LUMARAM_BASE + LUMARAM_MAP_SIZE - 1, "ram", "rw", "lumaram_r / lumaram_w", "model2_tgp_mem", "8-bit polygon luma table (umask32→0x8000)"),
    # --- model2a_crx_mem (Sega Rally class) ---
    MemoryMapEntry("crx_ram", 0x0020_0000, 0x0023_FFFF, "ram", "rw", "ram", "model2a_crx_mem", "256 KiB CRX expansion RAM"),
    MemoryMapEntry("io_board", 0x01C0_0000, 0x01C0_001F, "mmio", "rw", "sega_315_5649_device", "model2a_crx_mem", "inputs, lamps, eeprom bit-bang"),
    MemoryMapEntry("io_board_nop", 0x01C0_0040, 0x01C0_0043, "mmio", "w", "nopw", "model2a_crx_mem"),
    MemoryMapEntry("sound_uart", 0x01C8_0000, 0x01C8_0003, "mmio", "rw", "i8251_device", "model2a_crx_mem", "sound board UART"),
    # --- i960 core (MAME i960.cpp synmov special cases, not in board map) ---
    MemoryMapEntry("i960_icr", 0xFF00_0004, 0xFF00_0007, "internal", "w", "synmov → m_ICR", "i960.cpp", "interrupt control register"),
    MemoryMapEntry("i960_iac", 0xFF00_0010, 0xFF00_001F, "internal", "w", "synmovq → send_iac", "i960.cpp", "invalidate cache / IAC"),
    # --- RE gap: used by boot @ 0x420, absent from MAME model2.cpp ---
    MemoryMapEntry("boot_mmio_gap", 0x00F8_0000, 0x00F8_0000, "mmio_gap", "rw", "(unmapped)", "—", "boot ldob/stob RMW bit 1; not in MAME map"),
)


def lookup_region(addr: int) -> MemoryMapEntry | None:
    """Return the narrowest map entry containing addr, or None."""
    best: MemoryMapEntry | None = None
    best_span = -1
    for entry in MODEL2A_MEMORY_MAP:
        if entry.start <= addr <= entry.end:
            span = entry.end - entry.start
            if best is None or span < best_span:
                best = entry
                best_span = span
    return best


def is_mmio_addr(addr: int) -> bool:
    """True for board MMIO, i960-internal synmov targets, and known gaps."""
    entry = lookup_region(addr)
    return entry is not None and entry.kind in ("mmio", "internal", "mmio_gap")


def region_name(addr: int) -> str | None:
    entry = lookup_region(addr)
    return entry.name if entry else None


WORKRAM_SCENE_SYMBOLS: dict[str, int] = {
    "scene_metadata_table": SCENE_METADATA_TABLE,
    "catalog_index_table": CATALOG_INDEX_TABLE,
    "scene_batch_index": SCENE_BATCH_INDEX,
    "course_select_index": COURSE_SELECT_INDEX,
    "course_variant_index": COURSE_VARIANT_INDEX,
    "scene_matrix_base": SCENE_MATRIX_BASE,
    "placement_cursor": PLACEMENT_CURSOR,
    "geo_workram_write_ptr": GEO_WORKRAM_WRITE_PTR,
    "catalog_dispatch_by_slot": CATALOG_DISPATCH_BY_SLOT,
    "catalog_dispatch_by_quad": CATALOG_DISPATCH_BY_QUAD,
    "vehicle_catalog_index_a": VEHICLE_CATALOG_INDEX_A,
    "vehicle_catalog_index_b": VEHICLE_CATALOG_INDEX_B,
    "vehicle_matrix_table": VEHICLE_MATRIX_TABLE,
    "vehicle_state_byte": VEHICLE_STATE_BYTE,
}

GEO_PORT_CONSTANTS: dict[str, int] = {
    "geo_regs_base": GEO_REGS_BASE,
    "geo_write_start": GEO_WRITE_START,
    "geo_read_start": GEO_READ_START,
    "geo_prg_fifo": GEO_PRG_FIFO,
    "bufferram_base": BUFFERRAM_BASE,
    "main_data_a": MAIN_DATA_A,
    "main_data_b": MAIN_DATA_B,
    "workram_base": WORKRAM_BASE,
    "catalog_base": CATALOG_VADDR,
    "placement_stream": PLACEMENT_STREAM_VADDR,
    "placement_group_026": PLACEMENT_GROUP_026_VADDR,
    "textureram0_base": TEXTURERAM0_BASE,
    "textureram1_base": TEXTURERAM1_BASE,
    "texture_sheet_bank0": TEXTURE_SHEET_BANK0_VADDR,
    "texture_sheet_bank1": TEXTURE_SHEET_BANK1_VADDR,
    "texture_upload_fn": TEXTURE_UPLOAD_FN,
    "lumaram_base": LUMARAM_BASE,
    "copro_fifo": COPRO_FIFO,
    "sound_uart": SOUND_UART,
}
