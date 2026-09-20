/* Integer 68000 subset for epr-17890a.30 (SCSP MIDI ISR + slot setup). */
#include "model2_snd_m68k.h"
#include "model2_snd_rom.h"
#include "model2_snd_scsp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SR_S    0x2000u
#define SR_IPL  0x0700u

static u32 d[8], a[8], pc, sr;
static int g_alive = 1;
static int g_logged_op;
static u8 g_bank;

static u8 rd8(u32 addr)
{
    addr &= 0x00ffffffu;
    if (addr < MODEL2_SND_SOUNDRAM_SIZE)
        return model2_snd_soundram()[addr];
    if (addr >= 0x100000u && addr < 0x101000u)
        return model2_snd_scsp_read8(addr);
    if (addr >= 0x400000u && addr < 0x400010u)
        return g_bank;
    if (addr >= 0x600000u && addr < 0x600000u + MODEL2_SND_68K_ROM_SIZE) {
        const u8 *rom = model2_snd_68k_rom();

        return rom ? rom[addr - 0x600000u] : 0;
    }
    /* Sample ROM: 0x800000..0xFFFFFF, and the same 8 MiB image at
     * 0x000000..0x7FFFFF outside sound RAM (copy-job A0 @ 0x600EBE). */
    if (addr >= 0x80000u) {
        const u8 *rom = model2_snd_sample_rom();
        u32 off = (addr >= 0x800000u) ? (addr - 0x800000u) : addr;

        return rom ? rom[off % MODEL2_SND_SAMPLE_ROM_SIZE] : 0;
    }
    return 0;
}

static u16 rd16(u32 addr)
{
    return (u16)(((u16)rd8(addr) << 8) | rd8(addr + 1u));
}

static u32 rd32(u32 addr)
{
    return ((u32)rd16(addr) << 16) | rd16(addr + 2u);
}

static void wr8(u32 addr, u8 v)
{
    addr &= 0x00ffffffu;
    if (addr < MODEL2_SND_SOUNDRAM_SIZE) {
        if (addr == 0x2200u && (v & 0x80u)) {
            static int logged_flag;

            if (!logged_flag) {
                fprintf(stderr, "lift: sound 68k obj+0 bit7 pc=%06x\n", pc);
                logged_flag = 1;
            }
        }
        model2_snd_soundram()[addr] = v;
        return;
    }
    if (addr >= 0x100000u && addr < 0x101000u) {
        model2_snd_scsp_write8(addr, v);
        return;
    }
    if (addr >= 0x400000u && addr < 0x400010u)
        g_bank = v;
}

static void wr16(u32 addr, u16 v)
{
    wr8(addr, (u8)(v >> 8));
    wr8(addr + 1u, (u8)v);
}

static void wr32(u32 addr, u32 v)
{
    wr16(addr, (u16)(v >> 16));
    wr16(addr + 2u, (u16)v);
}

static u16 fetch16(void)
{
    u16 w = rd16(pc);

    pc += 2u;
    return w;
}

static u32 fetch32(void)
{
    u32 w = rd32(pc);

    pc += 4u;
    return w;
}

static void push16(u16 v)
{
    a[7] -= 2u;
    wr16(a[7], v);
}

static void push32(u32 v)
{
    a[7] -= 4u;
    wr32(a[7], v);
}

static u16 pop16(void)
{
    u16 v = rd16(a[7]);

    a[7] += 2u;
    return v;
}

static u32 pop32(void)
{
    u32 v = rd32(a[7]);

    a[7] += 4u;
    return v;
}

static void set_nz(u32 v, int sz)
{
    u32 mask = (sz == 0) ? 0xffu : (sz == 1) ? 0xffffu : 0xffffffffu;

    v &= mask;
    sr &= ~0x0cu;
    if (v == 0)
        sr |= 4u;
    if ((sz == 0 && (v & 0x80u)) || (sz == 1 && (v & 0x8000u)) || (sz == 2 && (v & 0x80000000u)))
        sr |= 8u;
}

static int ipl(void)
{
    return (int)((sr >> 8) & 7u);
}

static void take_irq(int level, u32 vector_off)
{
    u16 old = (u16)sr;

    sr |= SR_S;
    sr = (sr & ~SR_IPL) | (u16)((unsigned)level << 8);
    push32(pc);
    push16(old);
    pc = rd32(vector_off);
}

enum { SZ_B, SZ_W, SZ_L };

static u32 mask_sz(int sz)
{
    if (sz == SZ_B)
        return 0xffu;
    if (sz == SZ_W)
        return 0xffffu;
    return 0xffffffffu;
}

static u32 read_ea(int mode, int reg, int sz, int fetch_imm)
{
    u32 addr;
    u16 ext;

    switch (mode) {
    case 0:
        return d[reg] & mask_sz(sz);
    case 1:
        return a[reg] & mask_sz(sz);
    case 2:
        addr = a[reg];
        break;
    case 3:
        addr = a[reg];
        a[reg] += (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;
        if (sz == SZ_B && reg == 7)
            a[reg] += 1u;
        break;
    case 4:
        a[reg] -= (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;
        if (sz == SZ_B && reg == 7)
            a[reg] -= 1u;
        addr = a[reg];
        break;
    case 5:
        addr = a[reg] + (u32)(i16)fetch16();
        break;
    case 6:
        ext = fetch16();
        {
            u32 idx = (ext & 0x8000u) ? a[(ext >> 12) & 7u] : d[(ext >> 12) & 7u];

            if ((ext & 0x800u) == 0)
                idx = (u32)(i16)idx;
            addr = a[reg] + idx + (u32)(i8)(ext & 0xffu);
        }
        break;
    case 7:
        switch (reg) {
        case 0:
            addr = (u32)(i16)fetch16();
            break;
        case 1:
            addr = fetch32();
            break;
        case 2: {
            u32 base = pc;

            addr = base + (u32)(i16)fetch16();
            break;
        }
        case 3:
            ext = fetch16();
            {
                u32 idx = (ext & 0x8000u) ? a[(ext >> 12) & 7u] : d[(ext >> 12) & 7u];
                u32 base = pc - 2u;

                if ((ext & 0x800u) == 0)
                    idx = (u32)(i16)idx;
                addr = base + idx + (u32)(i8)(ext & 0xffu);
            }
            break;
        case 4:
            if (!fetch_imm)
                return 0;
            if (sz == SZ_L)
                return fetch32();
            if (sz == SZ_W)
                return fetch16();
            return (u8)fetch16();
        default:
            return 0;
        }
        break;
    default:
        return 0;
    }
    if (sz == SZ_B)
        return rd8(addr);
    if (sz == SZ_W)
        return rd16(addr);
    return rd32(addr);
}

static void write_ea(int mode, int reg, int sz, u32 value)
{
    u32 addr;
    u16 ext;

    value &= mask_sz(sz);
    switch (mode) {
    case 0:
        if (sz == SZ_B)
            d[reg] = (d[reg] & ~0xffu) | value;
        else if (sz == SZ_W)
            d[reg] = (d[reg] & ~0xffffu) | value;
        else
            d[reg] = value;
        return;
    case 1:
        if (sz == SZ_B)
            a[reg] = (a[reg] & ~0xffu) | value;
        else if (sz == SZ_W)
            a[reg] = (u32)(i16)value;
        else
            a[reg] = value;
        return;
    case 2:
        addr = a[reg];
        break;
    case 3:
        addr = a[reg];
        a[reg] += (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;
        if (sz == SZ_B && reg == 7)
            a[reg] += 1u;
        break;
    case 4:
        a[reg] -= (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;
        if (sz == SZ_B && reg == 7)
            a[reg] -= 1u;
        addr = a[reg];
        break;
    case 5:
        addr = a[reg] + (u32)(i16)fetch16();
        break;
    case 6:
        ext = fetch16();
        {
            u32 idx = (ext & 0x8000u) ? a[(ext >> 12) & 7u] : d[(ext >> 12) & 7u];

            if ((ext & 0x800u) == 0)
                idx = (u32)(i16)idx;
            addr = a[reg] + idx + (u32)(i8)(ext & 0xffu);
        }
        break;
    case 7:
        if (reg == 0)
            addr = (u32)(i16)fetch16();
        else if (reg == 1)
            addr = fetch32();
        else
            return;
        break;
    default:
        return;
    }
    if (sz == SZ_B)
        wr8(addr, (u8)value);
    else if (sz == SZ_W)
        wr16(addr, (u16)value);
    else
        wr32(addr, value);
}

static u32 lea_ea(int mode, int reg)
{
    u16 ext;

    switch (mode) {
    case 2:
        return a[reg];
    case 5:
        return a[reg] + (u32)(i16)fetch16();
    case 6:
        ext = fetch16();
        {
            u32 idx = (ext & 0x8000u) ? a[(ext >> 12) & 7u] : d[(ext >> 12) & 7u];

            if ((ext & 0x800u) == 0)
                idx = (u32)(i16)idx;
            return a[reg] + idx + (u32)(i8)(ext & 0xffu);
        }
    case 7:
        if (reg == 0)
            return (u32)(i16)fetch16();
        if (reg == 1)
            return fetch32();
        if (reg == 2) {
            u32 base = pc;

            return base + (u32)(i16)fetch16();
        }
        if (reg == 3) {
            u32 base = pc;

            ext = fetch16();
            {
                u32 idx = (ext & 0x8000u) ? a[(ext >> 12) & 7u] : d[(ext >> 12) & 7u];

                if ((ext & 0x800u) == 0)
                    idx = (u32)(i16)idx;
                return base + idx + (u32)(i8)(ext & 0xffu);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

/* Read/write the same EA once (ANDI/ADDQ-style). read_ea+write_ea double-fetches
 * d16(An) and skips the following insn — MIDI ISR addq.b 1506(a6) was lost. */
static u32 rmw_load(int mode, int reg, int sz, u32 *addr_out)
{
    if (mode == 0) {
        *addr_out = 0;
        return d[reg] & mask_sz(sz);
    }
    if (mode == 1) {
        *addr_out = 0;
        return a[reg] & mask_sz(sz);
    }
    if (mode == 3) {
        u32 inc = (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;

        if (sz == SZ_B && reg == 7)
            inc = 2u;
        *addr_out = a[reg];
        a[reg] += inc;
    } else if (mode == 4) {
        u32 inc = (sz == SZ_L) ? 4u : (sz == SZ_W || reg == 7) ? 2u : 1u;

        if (sz == SZ_B && reg == 7)
            inc = 2u;
        a[reg] -= inc;
        *addr_out = a[reg];
    } else {
        *addr_out = lea_ea(mode, reg);
    }
    if (sz == SZ_B)
        return rd8(*addr_out);
    if (sz == SZ_W)
        return rd16(*addr_out);
    return rd32(*addr_out);
}

static void rmw_store(int mode, int reg, int sz, u32 addr, u32 v)
{
    if (mode == 0 || mode == 1) {
        write_ea(mode, reg, sz, v);
        return;
    }
    v &= mask_sz(sz);
    if (sz == SZ_B)
        wr8(addr, (u8)v);
    else if (sz == SZ_W)
        wr16(addr, (u16)v);
    else
        wr32(addr, v);
}

static int cond(int cc)
{
    int c = (int)(sr & 1u);
    int v = (int)((sr >> 1) & 1u);
    int z = (int)((sr >> 2) & 1u);
    int n = (int)((sr >> 3) & 1u);

    switch (cc) {
    case 0:
        return 1;
    case 1:
        return 0;
    case 2:
        return !c && !z;
    case 3:
        return c || z;
    case 4:
        return !c;
    case 5:
        return c;
    case 6:
        return !z;
    case 7:
        return z;
    case 8:
        return !v;
    case 9:
        return v;
    case 10:
        return !n;
    case 11:
        return n;
    case 12:
        return n == v;
    case 13:
        return n != v;
    case 14:
        return !z && n == v;
    case 15:
        return z || n != v;
    default:
        return 0;
    }
}

static unsigned g_cyc;

static void unimplemented(u16 op)
{
    if (!g_logged_op) {
        fprintf(stderr, "lift: sound 68k unimplemented op=%04x pc=%06x\n",
                op, pc - 2u);
        g_logged_op = 1;
    }
    g_alive = 0;
}

static unsigned popcount16(u16 v)
{
    unsigned n = 0;

    while (v) {
        n += v & 1u;
        v >>= 1;
    }
    return n;
}

static void exec_one(void)
{
    u16 op;
    unsigned i;

    /* MC68000UM: default 12 covers most mem/ALU. Exception is its own 44-cycle
     * stack frame; TIMA ack is SCIRE $422 bit 6 (@ 0x602702), not take_irq. */
    g_cyc = 12;
    if (model2_snd_scsp_midi_pending() && model2_snd_scsp_midi_irq_armed()
        && ipl() < 3) {
        static int logged_irq;

        if (!logged_irq) {
            fprintf(stderr,
                    "lift: sound 68k irq3 from pc=%06x a5=%08x vec6c=%08x fifo=%d\n",
                    pc, a[5], rd32(0x6cu),
                    model2_snd_scsp_midi_pending());
            logged_irq = 1;
        }
        take_irq(3, 0x6cu);
        g_cyc = 44;
        return;
    }
    if (model2_snd_scsp_timer_a_pending()
        && model2_snd_scsp_tima_armed() && ipl() < 2) {
        static int logged_tima;

        if (!logged_tima) {
            fprintf(stderr, "lift: sound 68k irq2 TIMA pc=%06x vec68=%08x\n",
                    pc, rd32(0x68u));
            logged_tima = 1;
        }
        take_irq(2, 0x68u);
        g_cyc = 44;
        return;
    }

    op = fetch16();

    /* NOP / RTE / RTS / RESET */
    if (op == 0x4e71) {
        g_cyc = 4;
        return;
    }
    if (op == 0x4e73) {
        g_cyc = 20;
        sr = pop16();
        pc = pop32();
        return;
    }
    if (op == 0x4e75) {
        g_cyc = 16;
        pc = pop32();
        return;
    }
    if (op == 0x4e70)
        return;
    if (op == 0x4e72) {
        sr = fetch16();
        return;
    }
    if ((op & 0xfff8) == 0x4e50) {
        int an = op & 7;
        i16 disp = (i16)fetch16();

        push32(a[an]);
        a[an] = a[7];
        a[7] += (u32)(i32)disp;
        return;
    }
    if ((op & 0xfff8) == 0x4e58) {
        int an = op & 7;

        a[7] = a[an];
        a[an] = pop32();
        return;
    }

    /* MOVE to SR / CCR / from SR */
    if ((op & 0xffc0) == 0x46c0) {
        sr = (u16)read_ea((op >> 3) & 7, op & 7, SZ_W, 1);
        return;
    }
    if ((op & 0xffc0) == 0x44c0) {
        u16 v = (u16)read_ea((op >> 3) & 7, op & 7, SZ_W, 1);

        sr = (u16)((sr & 0xff00u) | (v & 0xffu));
        return;
    }
    if ((op & 0xffc0) == 0x40c0) {
        write_ea((op >> 3) & 7, op & 7, SZ_W, sr);
        return;
    }

    /* NEG / NOT */
    if ((op & 0xff00) == 0x4400 || (op & 0xff00) == 0x4600) {
        int szb = (op >> 6) & 3;
        int sz, mode, reg;
        u32 v, r;

        if (szb == 3)
            goto other;
        sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        mode = (op >> 3) & 7;
        reg = op & 7;
        {
            u32 addr;

            v = rmw_load(mode, reg, sz, &addr);
            r = ((op & 0xff00) == 0x4400) ? (u32)(-(i32)v) : ~v;
            rmw_store(mode, reg, sz, addr, r);
        }
        set_nz(r, sz);
        return;
    }

    /* CLR  0100 0010 sz mode reg */
    if ((op & 0xff00) == 0x4200) {
        int sz = (op >> 6) & 3;
        int mode = (op >> 3) & 7;
        int reg = op & 7;

        if (sz == 0)
            sz = SZ_B;
        else if (sz == 1)
            sz = SZ_W;
        else
            sz = SZ_L;
        write_ea(mode, reg, sz, 0);
        set_nz(0, sz);
        return;
    }

    /* MOVEQ */
    if ((op & 0xf100) == 0x7000) {
        int dn = (op >> 9) & 7;
        i32 v = (i8)(op & 0xffu);

        d[dn] = (u32)v;
        set_nz(d[dn], SZ_L);
        return;
    }

    /* MOVE.B/W/L  00 sz destmode destreg srcmode srcreg */
    if ((op & 0xc000) == 0 && (op & 0x3000) != 0) {
        int szbits = (op >> 12) & 3;
        int sm = (op >> 3) & 7;
        int srcreg = op & 7;
        int dm = (op >> 6) & 7;
        int dreg = (op >> 9) & 7;
        int sz = (szbits == 1) ? SZ_B : (szbits == 3) ? SZ_W : SZ_L;
        u32 v = read_ea(sm, srcreg, sz, 1);

        write_ea(dm, dreg, sz, v);
        set_nz(v, sz);
        return;
    }

    /* LEA  0100 an 111 mode reg */
    if ((op & 0xf1c0) == 0x41c0) {
        int an = (op >> 9) & 7;
        a[an] = lea_ea((op >> 3) & 7, op & 7);
        return;
    }

    /* MOVEA.L  0010 an 001 ...  / MOVEA.W 0011 */
    if ((op & 0xc1c0) == 0x0040 && ((op & 0x3000) == 0x2000 || (op & 0x3000) == 0x3000)) {
        int an = (op >> 9) & 7;
        int sz = ((op & 0x3000) == 0x2000) ? SZ_L : SZ_W;
        u32 v = read_ea((op >> 3) & 7, op & 7, sz, 1);

        a[an] = (sz == SZ_W) ? (u32)(i16)v : v;
        return;
    }

    /* ADDQ/SUBQ  0101 xxx 0/1 sz mode reg */
    if ((op & 0xf000) == 0x5000 && ((op >> 6) & 3) != 3) {
        int szb = (op >> 6) & 3;
        int sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        u32 imm = (op >> 9) & 7;
        int mode = (op >> 3) & 7;
        int reg = op & 7;
        u32 v;

        if (imm == 0)
            imm = 8;
        if (mode == 1) {
            if (op & 0x0100)
                a[reg] -= imm;
            else
                a[reg] += imm;
            return;
        }
        if (mode == 0) {
            v = d[reg];
            if (op & 0x0100)
                v -= imm;
            else
                v += imm;
            write_ea(0, reg, sz, v);
            set_nz(v, sz);
            return;
        }
        {
            u32 addr = lea_ea(mode, reg);

            if (sz == SZ_B)
                v = rd8(addr);
            else if (sz == SZ_W)
                v = rd16(addr);
            else
                v = rd32(addr);
            if (op & 0x0100)
                v -= imm;
            else
                v += imm;
            if (sz == SZ_B)
                wr8(addr, (u8)v);
            else if (sz == SZ_W)
                wr16(addr, (u16)v);
            else
                wr32(addr, v);
            set_nz(v, sz);
        }
        return;
    }

    /* DBcc  0101 cc 11001 reg */
    if ((op & 0xf0f8) == 0x50c8) {
        i16 disp = (i16)fetch16();
        int cc = (op >> 8) & 0xf;
        int dn = op & 7;

        if (!cond(cc)) {
            u32 target = (pc - 2u) + (u32)disp;
            u16 body = rd16(target);

            /* RAM fill: move.l #imm,(An)+ / dbra (disp == -8). One body already ran. */
            if (disp == -8 && (body & 0xf1ffu) == 0x20fcu) {
                int an = (body >> 9) & 7;
                u32 imm = rd32(target + 2u);
                unsigned remain = (unsigned)(u16)d[dn];
                unsigned k;

                for (k = 0; k < remain; k++) {
                    wr32(a[an], imm);
                    a[an] += 4u;
                }
                d[dn] = (d[dn] & ~0xffffu) | 0xffffu;
                g_cyc = 12u + 8u * remain;
                return;
            }
            /* ROM→RAM copy: move.l (As)+,(Ad)+ / dbra (disp == -6). */
            if (disp == -6 && (body & 0xf1f8u) == 0x20d8u) {
                int ad = (body >> 9) & 7;
                int as = body & 7;
                unsigned remain = (unsigned)(u16)d[dn];
                unsigned k;

                for (k = 0; k < remain; k++) {
                    wr32(a[ad], rd32(a[as]));
                    a[as] += 4u;
                    a[ad] += 4u;
                }
                d[dn] = (d[dn] & ~0xffffu) | 0xffffu;
                g_cyc = 12u + 8u * remain;
                return;
            }
            {
                u16 cnt = (u16)(d[dn] - 1u);

                d[dn] = (d[dn] & ~0xffffu) | cnt;
                if (cnt != 0xffffu) {
                    pc = target;
                    g_cyc = 10;
                } else {
                    g_cyc = 14;
                }
            }
        }
        return;
    }

    /* Bcc / BSR */
    if ((op & 0xf000) == 0x6000) {
        int cc = (op >> 8) & 0xf;
        i32 disp = (i8)(op & 0xffu);

        if ((op & 0xffu) == 0)
            disp = (i16)fetch16();
        else if ((op & 0xffu) == 0xffu)
            disp = (i32)fetch32();
        if (cc == 1) { /* BSR */
            u32 ret = pc;

            if ((op & 0xffu) == 0)
                pc = (pc - 2u) + (u32)disp;
            else if ((op & 0xffu) == 0xffu)
                pc = (pc - 4u) + (u32)disp;
            else
                pc = ret + (u32)disp;
            push32(ret);
            return;
        }
        /* For 8-bit, pc is already past opcode; target = pc + disp. */
        if (cc == 0 || cond(cc)) {
            if ((op & 0xffu) == 0)
                pc = (pc - 2u) + (u32)disp;
            else if ((op & 0xffu) == 0xffu)
                pc = (pc - 4u) + (u32)disp;
            else
                pc = pc + (u32)disp;
        }
        return;
    }

    /* CMPI  0000 1100 sz mode reg */
    if ((op & 0xff00) == 0x0c00) {
        int szb = (op >> 6) & 3;
        int sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        u32 imm = (sz == SZ_L) ? fetch32() : fetch16();
        u32 v = read_ea((op >> 3) & 7, op & 7, sz, 0);
        u32 r = v - (imm & mask_sz(sz));

        sr &= ~1u;
        if ((imm & mask_sz(sz)) > (v & mask_sz(sz)))
            sr |= 1u;
        set_nz(r, sz);
        return;
    }

    /* BTST/BCHG/BCLR/BSET #imm, ea */
    if ((op & 0xff00) == 0x0800) {
        unsigned bit = fetch16() & 31u;
        int mode = (op >> 3) & 7;
        int reg = op & 7;
        int kind = (op >> 6) & 3;
        u32 v, mask, addr;

        if (mode == 0) {
            v = d[reg];
            mask = 1u << (bit & 31u);
            sr = (sr & ~4u) | ((v & mask) ? 0u : 4u);
            if (kind == 1)
                d[reg] ^= mask;
            else if (kind == 2)
                d[reg] &= ~mask;
            else if (kind == 3)
                d[reg] |= mask;
            return;
        }
        bit &= 7u;
        addr = lea_ea(mode, reg);
        v = rd8(addr);
        mask = 1u << bit;
        sr = (sr & ~4u) | ((v & mask) ? 0u : 4u);
        if (kind == 1)
            v ^= mask;
        else if (kind == 2)
            v &= ~mask;
        else if (kind == 3)
            v |= mask;
        if (kind != 0)
            wr8(addr, (u8)v);
        return;
    }
    /* MOVEP  0000 dn 1 ww 001 an — SCSP slot bytes at odd offsets. */
    if ((op & 0xf138) == 0x0108) {
        int dn = (op >> 9) & 7;
        int an = op & 7;
        int ww = (op >> 6) & 3;
        u32 addr = a[an] + (u32)(i16)fetch16();

        if (ww == 0) {
            u32 v = ((u32)rd8(addr) << 8) | rd8(addr + 2u);

            d[dn] = (d[dn] & ~0xffffu) | v;
        } else if (ww == 1) {
            d[dn] = ((u32)rd8(addr) << 24) | ((u32)rd8(addr + 2u) << 16)
                | ((u32)rd8(addr + 4u) << 8) | rd8(addr + 6u);
        } else if (ww == 2) {
            u16 v = (u16)d[dn];

            wr8(addr, (u8)(v >> 8));
            wr8(addr + 2u, (u8)v);
        } else {
            wr8(addr, (u8)(d[dn] >> 24));
            wr8(addr + 2u, (u8)(d[dn] >> 16));
            wr8(addr + 4u, (u8)(d[dn] >> 8));
            wr8(addr + 6u, (u8)d[dn]);
        }
        return;
    }
    if ((op & 0xf100) == 0x0100 && ((op >> 6) & 3) <= 3 && ((op >> 3) & 7) != 1) {
        int dn = (op >> 9) & 7;
        int mode = (op >> 3) & 7;
        int reg = op & 7;
        int kind = (op >> 6) & 3;
        unsigned bit;
        u32 v, mask, addr;

        if (mode == 0) {
            bit = d[dn] & 31u;
            v = d[reg];
            mask = 1u << bit;
            sr = (sr & ~4u) | ((v & mask) ? 0u : 4u);
            if (kind == 1)
                d[reg] ^= mask;
            else if (kind == 2)
                d[reg] &= ~mask;
            else if (kind == 3)
                d[reg] |= mask;
            return;
        }
        bit = d[dn] & 7u;
        addr = lea_ea(mode, reg);
        v = rd8(addr);
        mask = 1u << bit;
        sr = (sr & ~4u) | ((v & mask) ? 0u : 4u);
        if (kind == 1)
            v ^= mask;
        else if (kind == 2)
            v &= ~mask;
        else if (kind == 3)
            v |= mask;
        if (kind != 0)
            wr8(addr, (u8)v);
        return;
    }

    /* ANDI/ORI to SR / CCR */
    if (op == 0x027c) {
        sr &= fetch16();
        return;
    }
    if (op == 0x007c) {
        sr |= fetch16();
        return;
    }
    if (op == 0x023c) {
        u16 imm = fetch16();

        sr = (u16)((sr & 0xff00u) | ((sr & imm) & 0xffu));
        return;
    }
    if (op == 0x003c) {
        u16 imm = fetch16();

        sr = (u16)((sr & 0xff00u) | ((sr | imm) & 0xffu));
        return;
    }

    /* ORI / SUBI / ADDI / EORI  (ANDI/CMPI handled elsewhere) */
    if ((op & 0xff00) == 0x0000 || (op & 0xff00) == 0x0400
        || (op & 0xff00) == 0x0600 || (op & 0xff00) == 0x0a00) {
        int szb = (op >> 6) & 3;
        int sz, mode, reg;
        u32 imm, v, r;

        if (szb == 3)
            goto other;
        sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        imm = (sz == SZ_L) ? fetch32() : fetch16();
        mode = (op >> 3) & 7;
        reg = op & 7;
        {
            u32 addr;

            v = rmw_load(mode, reg, sz, &addr);
            if ((op & 0xff00) == 0x0000)
                r = v | imm;
            else if ((op & 0xff00) == 0x0a00)
                r = v ^ imm;
            else if ((op & 0xff00) == 0x0400)
                r = v - imm;
            else
                r = v + imm;
            rmw_store(mode, reg, sz, addr, r);
        }
        set_nz(r, sz);
        return;
    }

    /* CMP 1011 dn 0 sz ea / CMPA / EOR */
    if ((op & 0xf000) == 0xb000) {
        int dn = (op >> 9) & 7;
        int opmode = (op >> 6) & 7;
        int mode = (op >> 3) & 7;
        int reg = op & 7;

        if (opmode <= 2) {
            int sz = opmode;
            u32 v = read_ea(mode, reg, sz, 1);
            u32 src = d[dn] & mask_sz(sz);
            u32 r = src - v;

            sr &= ~1u;
            if (v > src)
                sr |= 1u;
            set_nz(r, sz);
            return;
        }
        if (opmode == 3 || opmode == 7) {
            int sz = (opmode == 3) ? SZ_W : SZ_L;
            u32 v = read_ea(mode, reg, sz, 1);

            if (sz == SZ_W)
                v = (u32)(i16)v;
            {
                u32 r = a[dn] - v;

                sr &= ~1u;
                if (v > a[dn])
                    sr |= 1u;
                set_nz(r, SZ_L);
            }
            return;
        }
        if (opmode >= 4 && opmode <= 6) {
            int sz = opmode - 4;
            u32 addr;
            u32 v = rmw_load(mode, reg, sz, &addr) ^ (d[dn] & mask_sz(sz));

            rmw_store(mode, reg, sz, addr, v);
            set_nz(v, sz);
            return;
        }
    }

    /* ANDI  0000 0010 sz */
    if ((op & 0xff00) == 0x0200) {
        int szb = (op >> 6) & 3;
        int sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        u32 imm = (sz == SZ_L) ? fetch32() : fetch16();
        int mode = (op >> 3) & 7;
        int reg = op & 7;
        u32 addr;
        u32 v = rmw_load(mode, reg, sz, &addr) & imm;

        rmw_store(mode, reg, sz, addr, v);
        set_nz(v, sz);
        return;
    }

    /* JSR  0100 1110 10 mode reg */
    if ((op & 0xffc0) == 0x4e80) {
        u32 t = lea_ea((op >> 3) & 7, op & 7);

        push32(pc);
        pc = t;
        return;
    }
    /* JMP */
    if ((op & 0xffc0) == 0x4ec0) {
        pc = lea_ea((op >> 3) & 7, op & 7);
        return;
    }

    /* SWAP / PEA / EXT — before MOVEM (0x4880 overlaps EXT.W) */
    if ((op & 0xfff8) == 0x4840) {
        int dn = op & 7;
        u32 v = (d[dn] << 16) | (d[dn] >> 16);

        d[dn] = v;
        set_nz(v, SZ_L);
        return;
    }
    if ((op & 0xffc0) == 0x4840) {
        u32 t = lea_ea((op >> 3) & 7, op & 7);

        push32(t);
        return;
    }
    if ((op & 0xfff8) == 0x4880) {
        int dn = op & 7;
        i16 v = (i8)d[dn];

        d[dn] = (d[dn] & ~0xffffu) | (u16)v;
        set_nz((u32)(u16)v, SZ_W);
        return;
    }
    if ((op & 0xfff8) == 0x48c0) {
        int dn = op & 7;

        d[dn] = (u32)(i16)d[dn];
        set_nz(d[dn], SZ_L);
        return;
    }

    /* MOVEM  0100 1 d 001 sz mode reg   d=0 reg-to-mem, 1 mem-to-reg */
    if ((op & 0xfb80) == 0x4880) {
        u16 list = fetch16();
        int sz = (op & 0x40) ? SZ_L : SZ_W;
        int dir = (op >> 10) & 1;
        int mode = (op >> 3) & 7;
        int reg = op & 7;
        u32 addr;
        int inc = (sz == SZ_L) ? 4 : 2;

        if (mode == 4) { /* predec: mask bit0 = A7 */
            addr = a[reg];
            for (i = 0; i < 16; i++) {
                if (list & (1u << i)) {
                    int idx = 15 - (int)i;
                    u32 v = (idx < 8) ? d[idx] : a[idx - 8];

                    addr -= (u32)inc;
                    if (dir == 0) {
                        if (sz == SZ_L)
                            wr32(addr, v);
                        else
                            wr16(addr, (u16)v);
                    }
                }
            }
            a[reg] = addr;
            g_cyc = 8u + (sz == SZ_L ? 8u : 4u) * popcount16(list);
            return;
        }
        if (mode == 2 || mode == 3)
            addr = a[reg];
        else
            addr = lea_ea(mode, reg);
        if (mode == 2 || mode == 3 || mode == 5 || mode == 7) {
            for (i = 0; i < 16; i++) {
                if (list & (1u << i)) {
                    if (dir) {
                        u32 v = (sz == SZ_L) ? rd32(addr) : (u32)(i16)rd16(addr);

                        if (i < 8)
                            d[i] = v;
                        else
                            a[i - 8] = v;
                    } else if (sz == SZ_L) {
                        wr32(addr, (i < 8) ? d[i] : a[i - 8]);
                    } else {
                        wr16(addr, (u16)((i < 8) ? d[i] : a[i - 8]));
                    }
                    addr += (u32)inc;
                }
            }
            if (mode == 3)
                a[reg] = addr;
            /* (An)+ long: 12 + 8×regs — copy pump 16×MOVEM @ 0x600F7A. */
            g_cyc = 12u + (sz == SZ_L ? 8u : 4u) * popcount16(list);
            return;
        }
        unimplemented(op);
        return;
    }

    /* ADD/SUB/AND/OR  1101 / 1001 / 1100 / 1000  with ea */
    if ((op & 0xf000) == 0xd000 || (op & 0xf000) == 0x9000
        || (op & 0xf000) == 0xc000 || (op & 0xf000) == 0x8000) {
        int dn = (op >> 9) & 7;
        int szb = (op >> 6) & 3;
        int dir = (op >> 8) & 1;
        int sz, mode, reg;
        u32 v, r;

        if (szb == 3) {
            mode = (op >> 3) & 7;
            reg = op & 7;
            if ((op & 0xf000) == 0xd000 || (op & 0xf000) == 0x9000) {
                int asz = dir ? SZ_L : SZ_W;
                u32 av = read_ea(mode, reg, asz, 1);

                if (asz == SZ_W)
                    av = (u32)(i16)av;
                if ((op & 0xf000) == 0xd000)
                    a[dn] += av;
                else
                    a[dn] -= av;
                return;
            }
            if ((op & 0xf000) == 0xc000) {
                u32 av = read_ea(mode, reg, SZ_W, 1) & 0xffffu;
                u32 pr;

                if (dir)
                    pr = (u32)((i32)(i16)d[dn] * (i32)(i16)av);
                else
                    pr = (d[dn] & 0xffffu) * av;
                d[dn] = pr;
                set_nz(pr, SZ_L);
                return;
            }
            if ((op & 0xf000) == 0x8000) {
                u32 av = read_ea(mode, reg, SZ_W, 1) & 0xffffu;

                if (av == 0u)
                    return;
                if (dir) {
                    i32 num = (i32)d[dn];
                    i32 den = (i16)av;
                    i32 q = num / den;
                    i32 rem = num % den;

                    d[dn] = ((u32)(u16)rem << 16) | (u16)q;
                } else {
                    u32 q = d[dn] / av;
                    u32 rem = d[dn] % av;

                    d[dn] = (rem << 16) | (q & 0xffffu);
                }
                set_nz(d[dn] & 0xffffu, SZ_W);
                return;
            }
            goto other;
        }
        sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        mode = (op >> 3) & 7;
        reg = op & 7;
        if (!dir) {
            v = read_ea(mode, reg, sz, 1);
            if ((op & 0xf000) == 0xd000)
                r = d[dn] + v;
            else if ((op & 0xf000) == 0x9000)
                r = d[dn] - v;
            else if ((op & 0xf000) == 0xc000)
                r = d[dn] & v;
            else
                r = d[dn] | v;
            if (sz == SZ_B)
                d[dn] = (d[dn] & ~0xffu) | (r & 0xffu);
            else if (sz == SZ_W)
                d[dn] = (d[dn] & ~0xffffu) | (r & 0xffffu);
            else
                d[dn] = r;
            set_nz(r, sz);
            return;
        }
        {
            u32 addr;
            u32 ev = rmw_load(mode, reg, sz, &addr);

            if ((op & 0xf000) == 0xd000)
                r = ev + d[dn];
            else if ((op & 0xf000) == 0x9000)
                r = ev - d[dn];
            else if ((op & 0xf000) == 0xc000)
                r = ev & d[dn];
            else
                r = ev | d[dn];
            rmw_store(mode, reg, sz, addr, r);
        }
        set_nz(r, sz);
        return;
    }
other:

    /* ASL/ASR/LSL/LSR/ROL/ROR  1110 ... */
    if ((op & 0xf018) == 0xe018 || (op & 0xf018) == 0xe008
        || (op & 0xf018) == 0xe000) {
        int dn = op & 7;
        int szb = (op >> 6) & 3;
        unsigned cnt = (op & 0x20) ? (d[(op >> 9) & 7] & 63u) : (((op >> 9) & 7) ? ((op >> 9) & 7) : 8);
        int left = (op & 0x100) != 0;
        u32 v, m;

        if (szb == 0) {
            v = d[dn] & 0xffu;
            m = 0xffu;
        } else if (szb == 1) {
            v = d[dn] & 0xffffu;
            m = 0xffffu;
        } else {
            v = d[dn];
            m = 0xffffffffu;
        }
        if ((op & 0x18) == 0x08) { /* LSR/LSL */
            v = left ? (v << cnt) : (v >> cnt);
        } else if ((op & 0x18) == 0x00) { /* ASR/ASL */
            if (left)
                v <<= cnt;
            else {
                i32 s = (szb == 0) ? (i32)(i8)v : (szb == 1) ? (i32)(i16)v : (i32)v;

                s >>= (int)cnt;
                v = (u32)s;
            }
        } else { /* ROR/ROL */
            unsigned bits = (szb == 0) ? 8u : (szb == 1) ? 16u : 32u;

            cnt %= bits;
            if (left)
                v = ((v << cnt) | (v >> (bits - cnt))) & m;
            else
                v = ((v >> cnt) | (v << (bits - cnt))) & m;
        }
        d[dn] = (d[dn] & ~m) | (v & m);
        set_nz(v, szb == 0 ? SZ_B : szb == 1 ? SZ_W : SZ_L);
        /* ROL.L #8,D1 @ 0x602A46 is 8+2n = 24; 10× is the ~1-sample CA wait. */
        g_cyc = (szb == 2 ? 8u : 6u) + 2u * cnt;
        return;
    }

    /* TST */
    if ((op & 0xff00) == 0x4a00) {
        int szb = (op >> 6) & 3;
        int sz = (szb == 0) ? SZ_B : (szb == 1) ? SZ_W : SZ_L;
        u32 v = read_ea((op >> 3) & 7, op & 7, sz, 0);

        set_nz(v, sz);
        return;
    }

    unimplemented(op);
}

void model2_snd_m68k_reset(void)
{
    const u8 *rom = model2_snd_68k_rom();
    unsigned i;

    memset(d, 0, sizeof(d));
    memset(a, 0, sizeof(a));
    g_bank = 0;
    g_alive = 1;
    g_logged_op = 0;
    sr = 0x2700;
    if (!rom) {
        g_alive = 0;
        return;
    }
    for (i = 0; i < 16u; i++)
        model2_snd_soundram()[i] = rom[i];
    a[7] = rd32(0);
    pc = rd32(4);
}

void model2_snd_m68k_run(unsigned insns)
{
    unsigned n;

    if (!g_alive)
        return;
    for (n = 0; n < insns && g_alive; n++)
        exec_one();
}

unsigned model2_snd_m68k_exec(void)
{
    if (!g_alive)
        return 0;
    exec_one();
    return g_cyc ? g_cyc : 12u;
}

int model2_snd_m68k_alive(void)
{
    return g_alive;
}

u32 model2_snd_m68k_pc(void)
{
    return pc;
}

u16 model2_snd_m68k_sr(void)
{
    return (u16)sr;
}

u32 model2_snd_m68k_areg(unsigned n)
{
    return a[n & 7u];
}
