/* Static ROM block definitions for lifted i960 C (MAME model2.cpp layout).
 *
 * Backing storage:
 *   maincpu  — fixed BSS array (1 MiB), filled from out/i960/maincpu_deinterleaved.bin
 *   main_data — heap mapping (up to 32 MiB), filled from out/i960/main_data_deinterleaved.bin
 *
 * Call model2_rom_load() once before executing lifted code that reads I960_ROM.
 */
#ifndef MODEL2_ROM_H
#define MODEL2_ROM_H

#include "i960_lift.h"
#include "model2_memory.h"

#if defined(__GNUC__) || defined(__clang__)
#define MODEL2_HOST_ALIGN __attribute__((aligned(16)))
#else
#define MODEL2_HOST_ALIGN
#endif

typedef struct {
    const char *name;
    u32 vaddr;
    u32 size;
    const char *extract_path; /* under decomp/out/i960/ after make rom-blocks */
} model2_rom_spec_t;

extern const model2_rom_spec_t model2_rom_specs[];
extern const unsigned model2_rom_spec_count;

/* maincpu program ROM @ 0x00000000 (always resident once loaded). */
extern MODEL2_HOST_ALIGN u8 model2_maincpu_rom[MAINCPU_SIZE];

/* main_data polygon/scene ROM @ 0x02000000 (heap; NULL until loaded). */
extern u8 *model2_main_data_rom;
extern u32 model2_main_data_size;

/* Host RAM windows (Model 2A map — not in maincpu EPROM file). */
extern MODEL2_HOST_ALIGN u8 model2_crx_ram[0x00040000];   /* @ 0x00200000 */
extern MODEL2_HOST_ALIGN u8 model2_workram[WORKRAM_SIZE]; /* @ 0x00500000 */
extern u8 model2_cpu_wait[0x38];                        /* @ 0x00E00000 */

/* Pointer into maincpu deinterleaved image (ROM offset 0 .. MAINCPU_SIZE-1). */
#define I960_MAINCPU_ROM(off) ((uintptr_t)(model2_maincpu_rom + (u32)(off)))

/* Map i960 virtual address → host pointer (maincpu ROM, CRX, workram, …). */
void *i960_vaddr_ptr(u32 vaddr);

/* Map i960 virtual address → bytes, or NULL if unmapped / not loaded. */
const u8 *model2_rom_at(u32 vaddr);

/* Writable host backing for RAM windows (workram, CRX, comm share); NULL if read-only. */
u8 *model2_ram_mut(u32 vaddr);

/* Load extracted blobs from paths (NULL → defaults under out/i960/). Returns 0 on success. */
int model2_rom_load(const char *maincpu_path, const char *main_data_path);

/* Convenience: load default paths and wire i960_mem ROM backend. */
int model2_rom_load_default(void);

/* Seed workram palette cells from maincpu ROM mirror (workram - 0x59F000).
 * Gamma scalars @ 0x5A2C70/0x5A2C74, lumaram row count @ 0x5A2EB0, table ptr @ 0x5A2EB4. */
void model2_workram_seed_palette_gamma(void);

/* Video RAM windows (MAME model2_base_mem layout). */
#define MODEL2_PALRAM_BASE     0x01800000u
#define MODEL2_PALRAM_SIZE     0x00004000u
#define MODEL2_COLORXLAT_BASE  0x01810000u
#define MODEL2_COLORXLAT_SIZE  0x0000C000u

/* Boot 2D: System 24 tile char RAM @ 0x01080000 and CRX I/O board @ 0x01C00000. */
#define MODEL2_TILE_MAP_BASE   0x01000000u
#define MODEL2_TILE_MAP_SIZE   0x00010000u
#define MODEL2_TILE_CHAR_BASE  0x01080000u
#define MODEL2_TILE_CHAR_SIZE  0x00080000u
#define MODEL2_IO_BOARD_BASE   0x01C00000u
#define MODEL2_IO_BOARD_SIZE   0x00000100u

/*
 * Sega 315-5649 @ 0x01C00000 (MAME model2a_crx_mem, umask 0x00ff00ff).
 * Port B is CPU byte 0x01C00002 → IN0 (srallyc):
 *   bit0 COIN1 ACTIVE_LOW, bit6 START1 ACTIVE_LOW (IPT_START1 moved from bit4).
 * Idle = 0xFF (all released).
 */
#define MODEL2_IO_IN0_OFF      0x02u
#define MODEL2_IO_IN1_OFF      0x04u
#define MODEL2_IO_IN2_OFF      0x06u
#define MODEL2_IO_ANALOG_OFF   0x1eu /* 315-5649 analog mux @ port F */

#define MODEL2_IO_IN0_COIN1    0x01u
#define MODEL2_IO_IN0_TEST     0x04u /* PORT_SERVICE — enter operator test menu */
#define MODEL2_IO_IN0_SERVICE1 0x08u /* IPT_SERVICE1 — move test-menu cursor */
#define MODEL2_IO_IN0_VR       0x20u /* IPT_BUTTON6 VR */
#define MODEL2_IO_IN0_START1   0x40u

/* Analog channels (srallyc an_port 0..2). Neutral steer=0x80, pedals rest=0. */
#define MODEL2_IO_AN_STEER     0u
#define MODEL2_IO_AN_ACCEL     1u
#define MODEL2_IO_AN_BRAKE     2u

/*
 * 4-speed H-shifter on IN1 bits 4–6 (io_poll @ 0x26B8):
 *   idx = (~IN1 >> 4) & 7 → ROM lut @ 0x5A14B0 → 0x202044 (0=N, 1..4).
 *   1st: bits 4+6, 2nd: 5+6, 3rd: 4, 4th: 5.
 */
#define MODEL2_IO_IN1_SHIFT    0x70u
#define MODEL2_IO_IN1_GEAR1    0x50u
#define MODEL2_IO_IN1_GEAR2    0x60u
#define MODEL2_IO_IN1_GEAR3    0x10u
#define MODEL2_IO_IN1_GEAR4    0x20u

/* Released-high IN0/IN1; clear bits while a control is held. */
void model2_io_board_reset(void);
void model2_io_in0_set_mask(u8 clear_bits, int pressed);
void model2_io_in1_set_mask(u8 clear_bits, int pressed);
/* Exclusive gear 0=N, 1..4. Leaves other IN1 bits alone. */
void model2_io_shifter_set(u32 gear);
void model2_io_analog_set(u32 channel, u8 value);
u8 model2_io_analog_get(u32 channel);
/* 315-5649 port F: write selects channel; read returns value and auto-increments. */
u8 model2_io_analog_port_read(void);
void model2_io_analog_port_write(u8 value);

/* Host one-shot: F2 / test hotkey latches until game_mode_apply consumes it. */
void model2_io_request_test_menu(void);
int model2_io_consume_test_menu_request(void);

/* Battery-backed SRAM @ 0x01D00000 (16 KiB). */
#define MODEL2_BACKUP_SRAM_BASE 0x01D00000u
#define MODEL2_BACKUP_SRAM_SIZE 0x00004000u
u8 *model2_backup_sram_ptr(void);

/* Read workram cell, falling back to maincpu ROM mirror @ vaddr - 0x0059F000. */
u8 model2_workram_mirror_u8(u32 workram_vaddr);
u16 model2_workram_mirror_u16(u32 workram_vaddr);
u32 model2_workram_mirror_u32(u32 workram_vaddr);

const u8 *model2_tile_char_ptr(void);
const u8 *model2_tile_map_ptr(void);

/* Writable backing for palette / colorxlat / lumaram (NULL if unmapped). */
const u8 *model2_palram_ptr(void);
const u8 *model2_colorxlat_ptr(void);
const u8 *model2_lumaram_ptr(void);

/*
 * MAME model2_tgp_mem: map(0x12800000,0x1281ffff).umask32(0x000000ff).
 * CPU stos every +4 packs into consecutive m_lumaram[0x8000] bytes.
 * Return 1 if ea is in the lumaram window (handled); 0 if not.
 */
int model2_lumaram_cpu_store(u32 ea, u32 value);
int model2_lumaram_cpu_load(u32 ea, u32 *out);

/*
 * Vertical refresh derived from tile sync (boot_tile_splash_init @ 0x26690):
 *   ROM table @ 0xFFAC → MMIO 0x01040000 (xhout), 0x01060000 (xvout)
 * Scaled to MAME model2 raster totals 656×424 @ 16 MHz pixel clock for the
 * srallyc ROM anchor xhout=64 / xvout=152. Override with I960_HOST_FRAME_HZ.
 */
double model2_tile_vsync_hz(void);

/* Dump host palette state to dir (palram.bin, colorxlat.bin, lumaram.bin, manifest.json).
 * Set I960_PALETTE_DUMP to a directory path; called from i960_host_trace_summary(). */
void model2_palette_state_dump(const char *dir);

/* Load palram/colorxlat/lumaram from a prior dump (inverse of dump). */
int model2_palette_state_load(const char *dir);

#endif
