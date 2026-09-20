#include "model2_rom.h"
#include "i960_mem.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef MODEL2_ROM_DEFAULT_MAINCPU
#define MODEL2_ROM_DEFAULT_MAINCPU "out/i960/maincpu_deinterleaved.bin"
#endif
#ifndef MODEL2_ROM_DEFAULT_MAIN_DATA
#define MODEL2_ROM_DEFAULT_MAIN_DATA "out/i960/main_data_deinterleaved.bin"
#endif

/* MAME main_data mirror: 0x06000000 maps region+0x01000000 for 16 MiB. */
#define MAIN_DATA_MIRROR_SIZE 0x01000000u
#define MAIN_DATA_MIRROR_OFFSET 0x01000000u

const model2_rom_spec_t model2_rom_specs[] = {
    {
        "maincpu",
        MAINCPU_BASE,
        MAINCPU_SIZE,
        MODEL2_ROM_DEFAULT_MAINCPU,
    },
    {
        "main_data",
        MAIN_DATA_A,
        MAIN_DATA_SIZE,
        MODEL2_ROM_DEFAULT_MAIN_DATA,
    },
    {
        "main_data_mirror",
        MAIN_DATA_B,
        MAIN_DATA_MIRROR_SIZE,
        MODEL2_ROM_DEFAULT_MAIN_DATA,
    },
};

const unsigned model2_rom_spec_count = sizeof(model2_rom_specs) / sizeof(model2_rom_specs[0]);

MODEL2_HOST_ALIGN u8 model2_maincpu_rom[MAINCPU_SIZE];
u8 *model2_main_data_rom;
u32 model2_main_data_size;

MODEL2_HOST_ALIGN u8 model2_crx_ram[0x00040000];
MODEL2_HOST_ALIGN u8 model2_workram[WORKRAM_SIZE];
u8 model2_cpu_wait[0x38];
MODEL2_HOST_ALIGN u8 model2_bufferram[BUFFERRAM_SIZE];

static MODEL2_HOST_ALIGN u8 model2_palette[MODEL2_PALRAM_SIZE];
static MODEL2_HOST_ALIGN u8 model2_colorxlat[MODEL2_COLORXLAT_SIZE];
static MODEL2_HOST_ALIGN u8 model2_lumaram[LUMARAM_SIZE];

/* M2 cabinet comm board shared RAM @ 0x01A00000 (mirror every 0x10000, 16 KiB window). */
#define M2COMM_SHARE_BASE   0x01A00000u
#define M2COMM_SHARE_SIZE   0x00004000u
#define M2COMM_SHARE_MIRROR 0x00010000u
static MODEL2_HOST_ALIGN u8 model2_m2comm_share[M2COMM_SHARE_SIZE];

#define BACKUP_SRAM_BASE MODEL2_BACKUP_SRAM_BASE
#define BACKUP_SRAM_SIZE MODEL2_BACKUP_SRAM_SIZE
static MODEL2_HOST_ALIGN u8 model2_backup_sram[BACKUP_SRAM_SIZE];

static MODEL2_HOST_ALIGN u8 model2_tile_map[MODEL2_TILE_MAP_SIZE];
static MODEL2_HOST_ALIGN u8 model2_tile_char[MODEL2_TILE_CHAR_SIZE];
static MODEL2_HOST_ALIGN u8 model2_textureram[TEXTURERAM_BANK_SIZE * 2u];
static MODEL2_HOST_ALIGN u8 model2_io_board[MODEL2_IO_BOARD_SIZE];
static u8 model2_io_analog[8];
static u8 model2_io_analog_channel;
static u16 model2_tile_xhout;
static u16 model2_tile_xvout;
static int model2_io_test_menu_req;

u8 *model2_backup_sram_ptr(void)
{
    return model2_backup_sram;
}

void model2_io_board_reset(void)
{
    /* 315-5649 inputs idle high (ACTIVE_LOW released). */
    memset(model2_io_board, 0xff, sizeof(model2_io_board));
    memset(model2_io_analog, 0xff, sizeof(model2_io_analog));
    model2_io_analog[MODEL2_IO_AN_STEER] = 0x80u;
    model2_io_analog[MODEL2_IO_AN_ACCEL] = 0x00u;
    model2_io_analog[MODEL2_IO_AN_BRAKE] = 0x00u;
    model2_io_analog_channel = 0;
    model2_io_test_menu_req = 0;
    /*
     * Do not fill backup SRAM with 0xFF: credits @ 0x01D00020 would be 0xFFFF
     * and the HUD ones digit reads as 5. Leave zero; A9D0 seeds chute masks
     * (1<<chute for COIN1/COIN2).
     */
}

void model2_io_in0_set_mask(u8 clear_bits, int pressed)
{
    /* Port B @ CPU 0x01C00002 (315-5649 offset 1, umask lane). */
    u8 *in0 = &model2_io_board[MODEL2_IO_IN0_OFF];

    if (pressed)
        *in0 = (u8)(*in0 & (u8)~clear_bits);
    else
        *in0 = (u8)(*in0 | clear_bits);
}

void model2_io_in1_set_mask(u8 clear_bits, int pressed)
{
    u8 *in1 = &model2_io_board[MODEL2_IO_IN1_OFF];

    if (pressed)
        *in1 = (u8)(*in1 & (u8)~clear_bits);
    else
        *in1 = (u8)(*in1 | clear_bits);
}

void model2_io_shifter_set(u32 gear)
{
    u8 *in1 = &model2_io_board[MODEL2_IO_IN1_OFF];
    u8 mask = 0;

    *in1 = (u8)(*in1 | MODEL2_IO_IN1_SHIFT);
    switch (gear) {
    case 1u:
        mask = MODEL2_IO_IN1_GEAR1;
        break;
    case 2u:
        mask = MODEL2_IO_IN1_GEAR2;
        break;
    case 3u:
        mask = MODEL2_IO_IN1_GEAR3;
        break;
    case 4u:
        mask = MODEL2_IO_IN1_GEAR4;
        break;
    default:
        break;
    }
    if (mask != 0)
        *in1 = (u8)(*in1 & (u8)~mask);
}

void model2_io_analog_set(u32 channel, u8 value)
{
    if (channel < 8u)
        model2_io_analog[channel] = value;
}

u8 model2_io_analog_get(u32 channel)
{
    if (channel < 8u)
        return model2_io_analog[channel];
    return 0xffu;
}

u8 model2_io_analog_port_read(void)
{
    u8 v = model2_io_analog[model2_io_analog_channel & 7u];

    model2_io_analog_channel = (u8)((model2_io_analog_channel + 1u) & 7u);
    return v;
}

void model2_io_analog_port_write(u8 value)
{
    model2_io_analog_channel = (u8)(value & 7u);
}

void model2_io_request_test_menu(void)
{
    model2_io_test_menu_req = 1;
}

int model2_io_consume_test_menu_request(void)
{
    int req = model2_io_test_menu_req;

    model2_io_test_menu_req = 0;
    return req;
}

/* boot_tile_splash_init @ 0x26690: lda 0xFFAC → 0x01040000; lda 0x52(g5) → 0x01060000 */
#define TILE_SYNC_RODATA         0x0000FFACu
#define MODEL2_TILE_PIXEL_CLOCK  16000000u
#define MODEL2_TILE_HTOTAL_REF   656u
#define MODEL2_TILE_VTOTAL_REF   424u
#define MODEL2_TILE_XHOUT_REF    64u
#define MODEL2_TILE_XVOUT_REF    152u

double model2_tile_vsync_hz(void)
{
    u16 xhout;
    u16 xvout;
    u32 htotal;
    u32 vtotal;

    xhout = model2_tile_xhout;
    if (xhout == 0) {
        const u8 *p = model2_rom_at(TILE_SYNC_RODATA);
        xhout = p ? (u16)((u16)p[0] | ((u16)p[1] << 8)) : MODEL2_TILE_XHOUT_REF;
    }
    xvout = model2_tile_xvout & 0xffu;
    if (xvout == 0) {
        const u8 *p = model2_rom_at(TILE_SYNC_RODATA + 0x52u);
        xvout = p ? (u16)p[0] : MODEL2_TILE_XVOUT_REF;
    }
    if (xhout == 0)
        xhout = MODEL2_TILE_XHOUT_REF;
    if (xvout == 0)
        xvout = MODEL2_TILE_XVOUT_REF;

    htotal = ((u32)xhout * MODEL2_TILE_HTOTAL_REF) / MODEL2_TILE_XHOUT_REF;
    vtotal = ((u32)xvout * MODEL2_TILE_VTOTAL_REF) / MODEL2_TILE_XVOUT_REF;
    if (htotal == 0 || vtotal == 0)
        return 60.0;
    return (double)MODEL2_TILE_PIXEL_CLOCK
        / ((double)htotal * (double)vtotal);
}

/* workram ``0x005Cxxxx`` cells mirror maincpu ROM @ ``vaddr - 0x0059F000`` (static RE). */
#define WORKRAM_ROM_MIRROR 0x0059F000u

/*
 * geo_lumaram_init @ 0x4350 walks the float lerp stream @ 0x5A2EB4 until the
 * post-group continue flag (cvtzri) is ≤1. Static ROM sim fills odd banks
 * 1..19 and consumes 1176 bytes — not ``count@0x5A2EB0`` (that float is only
 * the entry gate). Keep a margin past the measured end.
 */
#define LUMARAM_INIT_STREAM_BYTES 0x500u

#define CRX_RAM_BASE 0x00200000u
#define CPU_WAIT_BASE 0x00E00000u

static u8 *io_board_mut(u32 vaddr)
{
    u32 off;

    if (vaddr < MODEL2_IO_BOARD_BASE
        || vaddr >= MODEL2_IO_BOARD_BASE + MODEL2_IO_BOARD_SIZE)
        return NULL;
    off = vaddr - MODEL2_IO_BOARD_BASE;
    return model2_io_board + off;
}

static u8 *tile_map_mut(u32 vaddr)
{
    u32 off;

    if (vaddr < MODEL2_TILE_MAP_BASE
        || vaddr >= MODEL2_TILE_MAP_BASE + MODEL2_TILE_MAP_SIZE)
        return NULL;
    off = vaddr - MODEL2_TILE_MAP_BASE;
    return model2_tile_map + off;
}

static u8 *tile_char_mut(u32 vaddr)
{
    u32 off;

    if (vaddr < MODEL2_TILE_CHAR_BASE
        || vaddr >= MODEL2_TILE_CHAR_BASE + MODEL2_TILE_CHAR_SIZE)
        return NULL;
    off = vaddr - MODEL2_TILE_CHAR_BASE;
    return model2_tile_char + off;
}

u8 model2_workram_mirror_u8(u32 workram_vaddr)
{
    u32 rom_off;
    u8 *wr;

    if (workram_vaddr >= WORKRAM_ROM_MIRROR) {
        rom_off = workram_vaddr - WORKRAM_ROM_MIRROR;
        if (rom_off < MAINCPU_SIZE)
            return model2_maincpu_rom[rom_off];
    }
    wr = model2_ram_mut(workram_vaddr);
    return wr ? *wr : 0;
}

u16 model2_workram_mirror_u16(u32 workram_vaddr)
{
    u8 lo;
    u8 hi;

    lo = model2_workram_mirror_u8(workram_vaddr);
    hi = model2_workram_mirror_u8(workram_vaddr + 1u);
    return (u16)((u16)lo | ((u16)hi << 8));
}

u32 model2_workram_mirror_u32(u32 workram_vaddr)
{
    u16 lo;
    u16 hi;

    lo = model2_workram_mirror_u16(workram_vaddr);
    hi = model2_workram_mirror_u16(workram_vaddr + 2u);
    return (u32)lo | ((u32)hi << 16);
}

const u8 *model2_tile_map_ptr(void)
{
    return model2_tile_map;
}

const u8 *model2_tile_char_ptr(void)
{
    return model2_tile_char;
}

static const u8 *m2comm_share_at(u32 vaddr)
{
    u32 rel;
    u32 in_bank;

    if (vaddr < M2COMM_SHARE_BASE)
        return NULL;
    rel = vaddr - M2COMM_SHARE_BASE;
    /* MAME model2_map: 0x01A00000-0x01A03FFF, mirror(0x10000).
     * Do not alias unrelated addresses that happen to share the low 16 bits. */
    if (rel >= M2COMM_SHARE_MIRROR + M2COMM_SHARE_SIZE)
        return NULL;
    in_bank = rel % M2COMM_SHARE_MIRROR;
    if (in_bank >= M2COMM_SHARE_SIZE)
        return NULL;
    return model2_m2comm_share + in_bank;
}

static int read_file_into(const char *path, u8 *dst, u32 cap, u32 *out_len)
{
    FILE *fp;
    long n;

    if (!path || !dst)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    n = ftell(fp);
    if (n < 0) {
        fclose(fp);
        return -1;
    }
    if ((u32)n > cap) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    if (fread(dst, 1, (size_t)n, fp) != (size_t)n) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (out_len)
        *out_len = (u32)n;
    return 0;
}

static int read_file_heap(const char *path, u8 **out_ptr, u32 *out_len)
{
    FILE *fp;
    long n;
    u8 *buf;

    if (!path || !out_ptr || !out_len)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    n = ftell(fp);
    if (n <= 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    buf = (u8 *)malloc((size_t)n);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out_ptr = buf;
    *out_len = (u32)n;
    return 0;
}

const u8 *model2_rom_at(u32 vaddr)
{
    if (vaddr < MAINCPU_SIZE)
        return model2_maincpu_rom + vaddr;
    if (vaddr >= CRX_RAM_BASE && vaddr < CRX_RAM_BASE + (u32)sizeof(model2_crx_ram))
        return model2_crx_ram + (vaddr - CRX_RAM_BASE);
    if (vaddr >= WORKRAM_BASE && vaddr < WORKRAM_BASE + WORKRAM_SIZE)
        return model2_workram + (vaddr - WORKRAM_BASE);
    if (vaddr >= BUFFERRAM_BASE && vaddr < BUFFERRAM_BASE + BUFFERRAM_SIZE)
        return model2_bufferram + (vaddr - BUFFERRAM_BASE);
    if (vaddr >= MODEL2_PALRAM_BASE && vaddr < MODEL2_PALRAM_BASE + MODEL2_PALRAM_SIZE)
        return model2_palette + (vaddr - MODEL2_PALRAM_BASE);
    if (vaddr >= MODEL2_COLORXLAT_BASE && vaddr < MODEL2_COLORXLAT_BASE + MODEL2_COLORXLAT_SIZE)
        return model2_colorxlat + (vaddr - MODEL2_COLORXLAT_BASE);
    /* Lumaram: no sparse pointer — use model2_lumaram_cpu_{load,store}. */
    if (vaddr >= CPU_WAIT_BASE && vaddr < CPU_WAIT_BASE + (u32)sizeof(model2_cpu_wait))
        return model2_cpu_wait + (vaddr - CPU_WAIT_BASE);
    if (vaddr >= BACKUP_SRAM_BASE && vaddr < BACKUP_SRAM_BASE + BACKUP_SRAM_SIZE)
        return model2_backup_sram + (vaddr - BACKUP_SRAM_BASE);
    if (vaddr >= MODEL2_TILE_MAP_BASE
        && vaddr < MODEL2_TILE_MAP_BASE + MODEL2_TILE_MAP_SIZE)
        return model2_tile_map + (vaddr - MODEL2_TILE_MAP_BASE);
    if (vaddr >= MODEL2_TILE_CHAR_BASE
        && vaddr < MODEL2_TILE_CHAR_BASE + MODEL2_TILE_CHAR_SIZE)
        return model2_tile_char + (vaddr - MODEL2_TILE_CHAR_BASE);
    if (vaddr >= TEXTURERAM0_BASE && vaddr < TEXTURERAM0_BASE + TEXTURERAM_BANK_SIZE)
        return model2_textureram + (vaddr - TEXTURERAM0_BASE);
    if (vaddr >= TEXTURERAM1_BASE && vaddr < TEXTURERAM1_BASE + TEXTURERAM_BANK_SIZE)
        return model2_textureram + TEXTURERAM_BANK_SIZE + (vaddr - TEXTURERAM1_BASE);
    if (vaddr >= MODEL2_IO_BOARD_BASE
        && vaddr < MODEL2_IO_BOARD_BASE + MODEL2_IO_BOARD_SIZE)
        return model2_io_board + (vaddr - MODEL2_IO_BOARD_BASE);
    {
        const u8 *comm = m2comm_share_at(vaddr);
        if (comm)
            return comm;
    }
    if (model2_main_data_rom) {
        if (vaddr >= MAIN_DATA_A && vaddr < MAIN_DATA_A + model2_main_data_size)
            return model2_main_data_rom + (vaddr - MAIN_DATA_A);
        if (vaddr >= MAIN_DATA_B && vaddr < MAIN_DATA_B + MAIN_DATA_MIRROR_SIZE) {
            u32 off = (vaddr - MAIN_DATA_B) + MAIN_DATA_MIRROR_OFFSET;
            if (off < model2_main_data_size)
                return model2_main_data_rom + off;
        }
    }
    return NULL;
}

u8 *model2_ram_mut(u32 vaddr)
{
    if (vaddr >= WORKRAM_BASE && vaddr < WORKRAM_BASE + WORKRAM_SIZE)
        return model2_workram + (vaddr - WORKRAM_BASE);
    if (vaddr >= BUFFERRAM_BASE && vaddr < BUFFERRAM_BASE + BUFFERRAM_SIZE)
        return model2_bufferram + (vaddr - BUFFERRAM_BASE);
    if (vaddr >= MODEL2_PALRAM_BASE && vaddr < MODEL2_PALRAM_BASE + MODEL2_PALRAM_SIZE)
        return model2_palette + (vaddr - MODEL2_PALRAM_BASE);
    if (vaddr >= MODEL2_COLORXLAT_BASE && vaddr < MODEL2_COLORXLAT_BASE + MODEL2_COLORXLAT_SIZE)
        return model2_colorxlat + (vaddr - MODEL2_COLORXLAT_BASE);
    /* Lumaram: no sparse pointer — use model2_lumaram_cpu_{load,store}. */
    if (vaddr >= CRX_RAM_BASE && vaddr < CRX_RAM_BASE + (u32)sizeof(model2_crx_ram))
        return model2_crx_ram + (vaddr - CRX_RAM_BASE);
    if (vaddr >= BACKUP_SRAM_BASE && vaddr < BACKUP_SRAM_BASE + BACKUP_SRAM_SIZE)
        return model2_backup_sram + (vaddr - BACKUP_SRAM_BASE);
    {
        u8 *tile = tile_map_mut(vaddr);
        if (tile)
            return tile;
    }
    {
        u8 *tile = tile_char_mut(vaddr);
        if (tile)
            return tile;
    }
    if (vaddr >= TEXTURERAM0_BASE && vaddr < TEXTURERAM0_BASE + TEXTURERAM_BANK_SIZE)
        return model2_textureram + (vaddr - TEXTURERAM0_BASE);
    if (vaddr >= TEXTURERAM1_BASE && vaddr < TEXTURERAM1_BASE + TEXTURERAM_BANK_SIZE)
        return model2_textureram + TEXTURERAM_BANK_SIZE + (vaddr - TEXTURERAM1_BASE);
    {
        u8 *io = io_board_mut(vaddr);
        if (io)
            return io;
    }
    {
        const u8 *comm = m2comm_share_at(vaddr);
        if (comm)
            return (u8 *)(uintptr_t)comm;
    }
    if (vaddr == 0x01040000u || vaddr == 0x01040001u)
        return (u8 *)&model2_tile_xhout + (vaddr - 0x01040000u);
    if (vaddr == 0x01060000u || vaddr == 0x01060001u)
        return (u8 *)&model2_tile_xvout + (vaddr - 0x01060000u);
    return NULL;
}

void *i960_vaddr_ptr(u32 vaddr)
{
    const u8 *p = model2_rom_at(vaddr);
    return p ? (void *)(uintptr_t)p : (void *)(uintptr_t)vaddr;
}

int model2_rom_load(const char *maincpu_path, const char *main_data_path)
{
    u32 len = 0;

    if (read_file_into(maincpu_path, model2_maincpu_rom, MAINCPU_SIZE, &len) != 0)
        return -1;

    if (model2_main_data_rom) {
        free(model2_main_data_rom);
        model2_main_data_rom = NULL;
        model2_main_data_size = 0;
    }

    if (main_data_path && main_data_path[0]) {
        if (read_file_heap(main_data_path, &model2_main_data_rom, &model2_main_data_size) != 0)
            return -1;
    }

    i960_mem_attach_rom(model2_maincpu_rom, MAINCPU_SIZE);
    model2_workram_seed_palette_gamma();
    return 0;
}

static u32 workram_rom_mirror_u32(u32 workram_vaddr)
{
    u32 rom_off;

    if (workram_vaddr < WORKRAM_ROM_MIRROR)
        return 0;
    rom_off = workram_vaddr - WORKRAM_ROM_MIRROR;
    if (rom_off + 4 > MAINCPU_SIZE)
        return 0;
    return (u32)model2_maincpu_rom[rom_off]
        | ((u32)model2_maincpu_rom[rom_off + 1] << 8)
        | ((u32)model2_maincpu_rom[rom_off + 2] << 16)
        | ((u32)model2_maincpu_rom[rom_off + 3] << 24);
}

static void workram_store_u32(u32 workram_vaddr, u32 value)
{
    u8 *p;

    if (workram_vaddr < WORKRAM_BASE || workram_vaddr + 4 > WORKRAM_BASE + WORKRAM_SIZE)
        return;
    p = model2_workram + (workram_vaddr - WORKRAM_BASE);
    p[0] = (u8)(value);
    p[1] = (u8)(value >> 8);
    p[2] = (u8)(value >> 16);
    p[3] = (u8)(value >> 24);
}

void model2_workram_seed_palette_gamma(void)
{
    static const u32 mirrored_cells[] = {
        0x005A2C70u, /* float ~0.7 gamma scale (ROM mirror @ 0x3C70) */
        0x005A2C74u, /* float ~0.85 gamma scale (ROM mirror @ 0x3C74) */
        0x005A2EB0u, /* lumaram row count as real bits (5.0 @ ROM 0x3EB0) */
    };
    u32 table_base = 0x005A2EB4u;
    size_t i;
    size_t nbytes;

    for (i = 0; i < sizeof(mirrored_cells) / sizeof(mirrored_cells[0]); i++)
        workram_store_u32(mirrored_cells[i], workram_rom_mirror_u32(mirrored_cells[i]));

    /*
     * geo_lumaram_init @ 0x4350 reads the lerp stream via a direct workram
     * pointer (model2_workram+0xa2eb4), not i960_ld — so mirror fallback does
     * not apply. Copy the ROM image @ 0x3EB4; do not invent identity rows.
     */
    nbytes = (size_t)LUMARAM_INIT_STREAM_BYTES;
    if (table_base + nbytes > WORKRAM_BASE + WORKRAM_SIZE)
        return;
    for (i = 0; i + 3u < nbytes; i += 4u)
        workram_store_u32(table_base + (u32)i,
                          workram_rom_mirror_u32(table_base + (u32)i));
}

int model2_rom_load_default(void)
{
    return model2_rom_load(MODEL2_ROM_DEFAULT_MAINCPU, MODEL2_ROM_DEFAULT_MAIN_DATA);
}

const u8 *model2_palram_ptr(void)
{
    return model2_palette;
}

const u8 *model2_colorxlat_ptr(void)
{
    return model2_colorxlat;
}

const u8 *model2_lumaram_ptr(void)
{
    return model2_lumaram;
}

int model2_lumaram_cpu_store(u32 ea, u32 value)
{
    u32 off;
    u32 idx;

    if (ea < LUMARAM_BASE || ea >= LUMARAM_BASE + LUMARAM_MAP_SIZE)
        return 0;
    off = ea - LUMARAM_BASE;
    /* umask32(0x000000ff): only dword lane 0 is wired. */
    if ((off & 3u) != 0u)
        return 1;
    idx = (off >> 2) & (LUMARAM_SIZE - 1u);
    model2_lumaram[idx] = (u8)(value & 0xffu);
    return 1;
}

int model2_lumaram_cpu_load(u32 ea, u32 *out)
{
    u32 off;
    u32 idx;

    if (!out || ea < LUMARAM_BASE || ea >= LUMARAM_BASE + LUMARAM_MAP_SIZE)
        return 0;
    off = ea - LUMARAM_BASE;
    if ((off & 3u) != 0u) {
        *out = 0;
        return 1;
    }
    idx = (off >> 2) & (LUMARAM_SIZE - 1u);
    *out = model2_lumaram[idx];
    return 1;
}

static int mkdir_parents(const char *path)
{
    char buf[512];
    size_t len;
    char *p;

    if (!path || !*path)
        return -1;
    len = strlen(path);
    if (len >= sizeof(buf))
        return -1;
    memcpy(buf, path, len + 1);
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int write_blob(const char *dir, const char *name, const u8 *data, size_t len)
{
    char path[576];
    FILE *fp;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    fp = fopen(path, "wb");
    if (!fp)
        return -1;
    if (len && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

void model2_palette_state_dump(const char *dir)
{
    char manifest_path[576];
    FILE *fp;

    if (!dir || !*dir)
        return;
    if (mkdir_parents(dir) != 0) {
        fprintf(stderr, "lift: palette dump mkdir %s failed\n", dir);
        return;
    }
    if (write_blob(dir, "palram.bin", model2_palette, MODEL2_PALRAM_SIZE) != 0 ||
        write_blob(dir, "colorxlat.bin", model2_colorxlat, MODEL2_COLORXLAT_SIZE) != 0 ||
        write_blob(dir, "lumaram.bin", model2_lumaram, LUMARAM_SIZE) != 0 ||
        write_blob(dir, "tile_char.bin", model2_tile_char, MODEL2_TILE_CHAR_SIZE) != 0 ||
        write_blob(dir, "tile_map.bin", model2_tile_map, MODEL2_TILE_MAP_SIZE) != 0) {
        fprintf(stderr, "lift: palette dump write failed under %s\n", dir);
        return;
    }
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", dir);
    fp = fopen(manifest_path, "w");
    if (!fp) {
        fprintf(stderr, "lift: palette dump manifest write failed\n");
        return;
    }
    fprintf(fp,
            "{\n"
            "  \"format\": \"segamod2_lift_palette_v1\",\n"
            "  \"palram\": {\"vaddr\": \"0x%08x\", \"size\": %u, \"file\": \"palram.bin\"},\n"
            "  \"colorxlat\": {\"vaddr\": \"0x%08x\", \"size\": %u, \"file\": \"colorxlat.bin\"},\n"
            "  \"lumaram\": {\"vaddr\": \"0x%08x\", \"size\": %u, \"file\": \"lumaram.bin\"},\n"
            "  \"tile_char\": {\"vaddr\": \"0x%08x\", \"size\": %u, \"file\": \"tile_char.bin\"},\n"
            "  \"tile_map\": {\"vaddr\": \"0x%08x\", \"size\": %u, \"file\": \"tile_map.bin\"}\n"
            "}\n",
            MODEL2_PALRAM_BASE,
            (unsigned)MODEL2_PALRAM_SIZE,
            MODEL2_COLORXLAT_BASE,
            (unsigned)MODEL2_COLORXLAT_SIZE,
            LUMARAM_BASE,
            (unsigned)LUMARAM_SIZE,
            MODEL2_TILE_CHAR_BASE,
            (unsigned)MODEL2_TILE_CHAR_SIZE,
            MODEL2_TILE_MAP_BASE,
            (unsigned)MODEL2_TILE_MAP_SIZE);
    fclose(fp);

    fprintf(stderr,
            "lift: wrote palette state to %s (palram %u, colorxlat %u, lumaram %u, tile_char %u, tile_map %u bytes)\n",
            dir,
            (unsigned)MODEL2_PALRAM_SIZE,
            (unsigned)MODEL2_COLORXLAT_SIZE,
            (unsigned)LUMARAM_SIZE,
            (unsigned)MODEL2_TILE_CHAR_SIZE,
            (unsigned)MODEL2_TILE_MAP_SIZE);
}

static int read_blob(const char *dir, const char *name, u8 *dst, size_t len)
{
    char path[576];
    FILE *fp;
    size_t n;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    n = fread(dst, 1, len, fp);
    fclose(fp);
    if (n != len)
        return -1;
    return 0;
}

int model2_palette_state_load(const char *dir)
{
    if (!dir || !*dir)
        return -1;
    if (read_blob(dir, "palram.bin", model2_palette, MODEL2_PALRAM_SIZE) != 0)
        return -1;
    if (read_blob(dir, "colorxlat.bin", model2_colorxlat, MODEL2_COLORXLAT_SIZE) != 0)
        return -1;
    if (read_blob(dir, "lumaram.bin", model2_lumaram, LUMARAM_SIZE) != 0)
        return -1;
    fprintf(stderr, "lift: loaded palette state from %s\n", dir);
    return 0;
}
