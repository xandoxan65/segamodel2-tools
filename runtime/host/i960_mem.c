/* Default stubs + optional ROM-backed loads (see i960_mem.h). */
#include "i960_mem.h"
#include "model2_rom.h"
#include "model2_memory.h"
#include "model2_hw.h"
#include "model2_snd.h"

#include <stddef.h>
#include <string.h>

/*
 * MAME model2.cpp tex0_w / tex1_w: consecutive dword writes pack low halfwords
 * into one u32 (ldos+stq texture DMA). Share is addressed at dword offset;
 * packed index is offset>>1 (1 MiB unique data in a 2 MiB map window).
 */
static int model2_textureram_pack_w(u32 ea, u32 data)
{
    u32 bank_base;
    u8 *bank;
    u32 dword_off;
    u32 idx;
    u32 word;

    if (ea >= TEXTURERAM0_BASE && ea < TEXTURERAM0_BASE + TEXTURERAM_BANK_SIZE) {
        bank_base = TEXTURERAM0_BASE;
        bank = model2_ram_mut(TEXTURERAM0_BASE);
    } else if (ea >= TEXTURERAM1_BASE && ea < TEXTURERAM1_BASE + TEXTURERAM_BANK_SIZE) {
        bank_base = TEXTURERAM1_BASE;
        bank = model2_ram_mut(TEXTURERAM1_BASE);
    } else {
        return 0;
    }
    if (!bank || (ea & 3u) != 0u)
        return 0;

    dword_off = (ea - bank_base) >> 2;
    idx = dword_off >> 1;
    /* Packed span is half the map window (get_texel max ~1 MiB). */
    if (idx >= (TEXTURERAM_BANK_SIZE / 8u))
        return 0;

    memcpy(&word, bank + idx * 4u, 4);
    if ((dword_off & 1u) == 0u)
        word = (word & 0xffff0000u) | (data & 0xffffu);
    else
        word = (word & 0x0000ffffu) | ((data & 0xffffu) << 16);
    memcpy(bank + idx * 4u, &word, 4);
    return 1;
}

static const u8 *g_rom;
static size_t g_rom_len;

void i960_mem_attach_rom(const unsigned char *data, unsigned long len)
{
    g_rom = data;
    g_rom_len = len;
}

static uintptr_t i960_ea_add(uintptr_t base, u32 offset)
{
    if (offset >= 0x80000000u)
        return base - (uintptr_t)(0u - offset);
    return base + (uintptr_t)offset;
}

static int i960_sound_uart_ea(u32 ea)
{
    return ea >= SOUND_UART && ea <= SOUND_UART + 3u;
}

static int i960_workram_ea(i960_space space, u32 base, u32 offset, u32 *ea_out)
{
    u32 ea;

    if (space != I960_WORKRAM && space != I960_ABS)
        return 0;
    ea = base + offset;
    if (ea < WORKRAM_BASE || ea >= WORKRAM_BASE + WORKRAM_SIZE)
        return 0;
    *ea_out = ea;
    return 1;
}

/* Lifted tables use mirror when workram cell is zero; match for ld/st paths @ >=0x0059F000. */
static u32 i960_ld_u8_workram(u32 ea)
{
    u8 *ram = model2_ram_mut(ea);
    u8 v = ram ? *ram : 0;

    if (ea >= WORKRAM_ROM_MIRROR) {
        u8 mv = model2_workram_mirror_u8(ea);
        if (v == 0 && mv != 0)
            return mv;
    }
    return v;
}

static u32 i960_ld_u16_workram(u32 ea)
{
    u8 *ram = model2_ram_mut(ea);
    u16 v = 0;

    if (ram)
        memcpy(&v, ram, 2);
    if (ea >= WORKRAM_ROM_MIRROR) {
        u16 mv = model2_workram_mirror_u16(ea);
        if (v == 0 && mv != 0)
            return mv;
    }
    return v;
}

static u32 i960_ld_u32_workram(u32 ea)
{
    u8 *ram = model2_ram_mut(ea);
    u32 v = 0;

    if (ram)
        memcpy(&v, ram, 4);
    if (ea >= WORKRAM_ROM_MIRROR) {
        u32 mv = model2_workram_mirror_u32(ea);
        if (v == 0 && mv != 0)
            return mv;
    }
    return v;
}

static const u8 *i960_mapped_ptr(i960_space space, u32 base, u32 offset)
{
    u32 ea;
    const u8 *rom;
    u8 *ram;

    switch (space) {
    case I960_FP:
        return (const u8 *)(uintptr_t)i960_ea_add((uintptr_t)fp, offset);
    case I960_ROM:
        ea = (u32)((uintptr_t)base + offset);
        rom = model2_rom_at(ea);
        if (rom)
            return rom;
        if (g_rom && ea < g_rom_len)
            return g_rom + ea;
        return NULL;
    case I960_REG:
    case I960_WORKRAM:
    case I960_ABS:
        ea = base + offset;
        rom = model2_rom_at(ea);
        if (rom)
            return rom;
        ram = model2_ram_mut(ea);
        return ram;
    default:
        return NULL;
    }
}

u32 i960_ld_u8(i960_space space, u32 base, u32 offset)
{
    u32 ea;
    u32 lum;

    ea = base + offset;
    if (i960_sound_uart_ea(ea))
        return model2_snd_mmio_read(ea) & 0xffu;

    /* 315-5649 analog mux: side-effect read (auto-increment channel). */
    if ((space == I960_ABS || space == I960_WORKRAM || space == I960_ROM)
        && ea == (MODEL2_IO_BOARD_BASE + MODEL2_IO_ANALOG_OFF))
        return model2_io_analog_port_read();

    if ((space == I960_ABS || space == I960_WORKRAM || space == I960_ROM)
        && model2_lumaram_cpu_load(ea, &lum))
        return lum & 0xffu;

    if (i960_workram_ea(space, base, offset, &ea))
        return i960_ld_u8_workram(ea);

    {
        const u8 *p = i960_mapped_ptr(space, base, offset);

        if (p)
            return *p;
    }
    return 0;
}

u32 i960_ld_u16(i960_space space, u32 base, u32 offset)
{
    u32 ea;
    u32 lum;

    if (space == I960_ABS || space == I960_WORKRAM || space == I960_ROM
        || space == I960_MMIO)
        ea = base + offset;
    else
        ea = 0;

    if (i960_sound_uart_ea(ea))
        return model2_snd_mmio_read(ea) & 0xffu;

    /*
     * @0x1C64 comm_board_probe: write 'M' to 0x01C00202, read back for loopback.
     * Without a comm board attached the read is not 0x4D. Host IO RAM otherwise
     * echoes stores — suppress echo on this probe word only.
     */
    if (ea == 0x01c00202u)
        return 0;

    if ((space == I960_ABS || space == I960_WORKRAM || space == I960_ROM)
        && model2_lumaram_cpu_load(ea, &lum))
        return lum & 0xffu;

    if (i960_workram_ea(space, base, offset, &ea))
        return i960_ld_u16_workram(ea);

    {
        const u8 *p = i960_mapped_ptr(space, base, offset);

        if (p) {
            u16 v;
            memcpy(&v, p, 2);
            return v;
        }
    }
    return 0;
}

u32 i960_ld_u32(i960_space space, u32 base, u32 offset)
{
    u32 ea;
    u32 lum;

    ea = base + offset;
    if (i960_sound_uart_ea(ea))
        return model2_snd_mmio_read(ea);

    /* Copro / geo MMIO — must pop HLE FIFO (vec_scale normalize readback). */
    if (space == I960_MMIO
        || (ea >= 0x00800000u && ea < 0x00900000u)) {
        if (ea >= 0x00800000u && ea < 0x00900000u)
            return model2_hw_mmio_read(ea);
    }

    if ((space == I960_ABS || space == I960_WORKRAM || space == I960_ROM)
        && model2_lumaram_cpu_load(ea, &lum))
        return lum & 0xffu;

    if (i960_workram_ea(space, base, offset, &ea))
        return i960_ld_u32_workram(ea);

    {
        const u8 *p = i960_mapped_ptr(space, base, offset);

        if (p) {
            u32 v;
            memcpy(&v, p, 4);
            return v;
        }
    }
    return 0;
}

u64 i960_ld_u64(i960_space space, u32 base, u32 offset)
{
    u32 ea;
    u32 lo;
    u32 hi;

    /* Match ld/st workram mirror fallback (ldl is two words). */
    if (i960_workram_ea(space, base, offset, &ea)) {
        lo = i960_ld_u32_workram(ea);
        hi = i960_ld_u32_workram(ea + 4u);
        return (u64)lo | ((u64)hi << 32);
    }

    {
        const u8 *p = i960_mapped_ptr(space, base, offset);

        if (p) {
            u64 v;
            memcpy(&v, p, 8);
            return v;
        }
    }
    return 0;
}

void i960_st_u8(i960_space space, u32 base, u32 offset, u8 value)
{
    u32 ea;
    u8 *p;

    ea = (space == I960_FP) ? (u32)((uintptr_t)fp + offset) : (base + offset);
    if (i960_sound_uart_ea(ea)) {
        model2_snd_mmio_write(ea, value);
        return;
    }
    if (space == I960_WORKRAM || space == I960_ABS || space == I960_ROM) {
        ea = base + offset;
        if (ea == (MODEL2_IO_BOARD_BASE + MODEL2_IO_ANALOG_OFF)) {
            model2_io_analog_port_write(value);
            return;
        }
        if (model2_lumaram_cpu_store(ea, value))
            return;
        p = model2_ram_mut(ea);
        if (p) {
            *p = value;
            return;
        }
    }
}

void i960_st_u16(i960_space space, u32 base, u32 offset, u16 value)
{
    u32 ea;
    u8 *p;

    ea = (space == I960_FP) ? (u32)((uintptr_t)fp + offset) : (base + offset);
    if (i960_sound_uart_ea(ea)) {
        model2_snd_mmio_write(ea, value);
        return;
    }
    if (space == I960_WORKRAM || space == I960_ABS || space == I960_ROM) {
        ea = base + offset;
        if (ea >= 0x10000000u && ea < 0x10200000u) {
            model2_hw_render_mode_write((u32)value);
            return;
        }
        if (model2_lumaram_cpu_store(ea, value))
            return;
        p = model2_ram_mut(ea);
        if (p) {
            /* memcpy — ARM SIGBUS on odd *(u16 *) stores. */
            memcpy(p, &value, 2);
            return;
        }
    }
}

void i960_st_u32(i960_space space, u32 base, u32 offset, u32 value)
{
    u32 ea;
    u8 *p;

    ea = (space == I960_FP) ? (u32)((uintptr_t)fp + offset) : (base + offset);
    if (i960_sound_uart_ea(ea)) {
        model2_snd_mmio_write(ea, value);
        return;
    }
    /* Include copro FIFO @ 0x884000 (was only 0x800000–0x804FFF). */
    if (ea >= 0x00800000u && ea < 0x00900000u) {
        model2_hw_mmio_write(ea, value);
        return;
    }
    if (ea >= 0x10000000u && ea < 0x10200000u) {
        model2_hw_render_mode_write(value);
        return;
    }
    if (space == I960_WORKRAM || space == I960_ABS || space == I960_ROM) {
        /* Texture RAM: MAME tex0_w/tex1_w halfword packing (not raw dword). */
        if (model2_textureram_pack_w(ea, value))
            return;
        if (model2_lumaram_cpu_store(ea, value))
            return;
        p = model2_ram_mut(ea);
        if (p) {
            /* memcpy — ARM SIGBUS on unaligned *(u32 *) stores. */
            memcpy(p, &value, 4);
            return;
        }
    }
}

void i960_st_u64(i960_space space, u32 base, u32 offset, u64 value)
{
    u32 ea;
    u8 *p;

    ea = (space == I960_FP) ? (u32)((uintptr_t)fp + offset) : (base + offset);
    if (ea >= 0x00800000u && ea < 0x00900000u) {
        model2_hw_mmio_write(ea, (u32)value);
        model2_hw_mmio_write(ea + 4, (u32)(value >> 32));
        return;
    }
    if (space == I960_WORKRAM || space == I960_ABS || space == I960_ROM) {
        p = model2_ram_mut(ea);
        if (p) {
            memcpy(p, &value, 8);
            return;
        }
    }
}

void i960_mmio_write_u32(u32 offset, u32 value)
{
    if (i960_sound_uart_ea(offset)) {
        model2_snd_mmio_write(offset, value);
        return;
    }
    model2_hw_mmio_write(offset, value);
}

void i960_mmio_write_u8(u32 offset, u8 value)
{
    if (i960_sound_uart_ea(offset)) {
        model2_snd_mmio_write(offset, value);
        return;
    }
    (void)offset;
    (void)value;
}

u32 i960_mmio_read_u8(u32 offset)
{
    if (i960_sound_uart_ea(offset))
        return model2_snd_mmio_read(offset) & 0xffu;
    return model2_hw_mmio_read(offset) & 0xffu;
}

u32 i960_mmio_read_u32(u32 offset)
{
    if (i960_sound_uart_ea(offset))
        return model2_snd_mmio_read(offset);
    return model2_hw_mmio_read(offset);
}

void i960_synmov(uintptr_t src, uintptr_t dst)
{
    (void)src;
    (void)dst;
}

void i960_synmovq(uintptr_t src, uintptr_t dst)
{
    (void)src;
    (void)dst;
}
