#include "model2_snd_scsp.h"
#include "model2_snd_rom.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SLOT_COUNT 32
#define MIDI_FIFO  64
#define SCSP_RAM   MODEL2_SND_SOUNDRAM_SIZE
#define EG_ATTACK  0
#define EG_DECAY1  1
#define EG_DECAY2  2
#define EG_RELEASE 3

typedef struct {
    u16 r[16];
    u8 keyon;
    u32 pos;   /* 16.16 */
    u32 step;
    u32 sa;
    u32 lsa;
    u32 lea;
    u8 pcm8;
    u8 loop;
    u8 ssctl;
    u8 lpslnk;
    u8 eg_state;
    u8 eg_hold;
    u8 eg_dl;
    int eg_vol; /* 10.16, 0x3FF<<16 = full */
    int eg_ar;
    int eg_d1r;
    int eg_d2r;
    int eg_rr;
    int lvol; /* Q16, 65536 = 0 dB */
    int rvol;
} scsp_slot_t;

/* Sega TL/SDL/PAN: bit-weighted dB, Q8 (256 = 0 dB). */
static const int k_tl[256] = {
    256,244,233,223,215,206,196,188,181,173,165,158,152,146,139,133,
    128,123,117,112,108,103, 98, 94, 91, 87, 83, 79, 76, 73, 70, 67,
     64, 61, 59, 56, 54, 52, 49, 47, 46, 43, 42, 40, 38, 37, 35, 33,
     32, 31, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 18, 17,
     16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10, 10, 10,  9,  9,  8,
      8,  8,  7,  7,  7,  7,  6,  6,  6,  5,  5,  5,  5,  5,  4,  4,
      4,  4,  4,  4,  3,  3,  3,  3,  3,  3,  3,  3,  2,  2,  2,  2,
      2,  2,  2,  2,  2,  2,  2,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};
static const int k_pan[16] = {
    256,181,128,91,64,46,32,23,16,11,8,6,4,3,2,0
};
static const int k_sdl[8] = { 0, 4, 8, 16, 32, 64, 128, 256 };

/* MAME ARTimes/DRTimes (ms) — SCSP EG operator contract. */
static const float k_ar_ms[64] = {
    100000.f, 100000.f, 8100.f, 6900.f, 6000.f, 4800.f, 4000.f, 3400.f,
    3000.f, 2400.f, 2000.f, 1700.f, 1500.f, 1200.f, 1000.f, 860.f,
    760.f, 600.f, 500.f, 430.f, 380.f, 300.f, 250.f, 220.f,
    190.f, 150.f, 130.f, 110.f, 95.f, 76.f, 63.f, 55.f,
    47.f, 38.f, 31.f, 27.f, 24.f, 19.f, 15.f, 13.f,
    12.f, 9.4f, 7.9f, 6.8f, 6.0f, 4.7f, 3.8f, 3.4f,
    3.0f, 2.4f, 2.0f, 1.8f, 1.6f, 1.3f, 1.1f, 0.93f,
    0.85f, 0.65f, 0.53f, 0.44f, 0.40f, 0.35f, 0.f, 0.f
};
static const float k_dr_ms[64] = {
    100000.f, 100000.f, 118200.f, 101300.f, 88600.f, 70900.f, 59100.f, 50700.f,
    44300.f, 35500.f, 29600.f, 25300.f, 22200.f, 17700.f, 14800.f, 12700.f,
    11100.f, 8900.f, 7400.f, 6300.f, 5500.f, 4400.f, 3700.f, 3200.f,
    2800.f, 2200.f, 1800.f, 1600.f, 1400.f, 1100.f, 920.f, 790.f,
    690.f, 550.f, 460.f, 390.f, 340.f, 270.f, 230.f, 200.f,
    170.f, 140.f, 110.f, 98.f, 85.f, 68.f, 57.f, 49.f,
    43.f, 34.f, 28.f, 25.f, 22.f, 18.f, 14.f, 12.f,
    11.f, 8.5f, 7.1f, 6.1f, 5.4f, 4.3f, 3.6f, 3.1f
};

static scsp_slot_t g_slot[SLOT_COUNT];
static u8 g_ram[SCSP_RAM];
static u8 g_ctrl[0x40];
static u8 g_midi[MIDI_FIFO];
static unsigned g_midi_r, g_midi_w, g_midi_n;
static unsigned g_logged_keyon;
static unsigned g_tima_div;
static int g_tima_pend;
static int g_tima_insns;
static int g_artable[64];
static int g_drtable[64];
static int g_eg_gain[1024]; /* Q12 */
static u32 g_lfsr = 1u;
static int g_eg_ready;
/* MSLC: copy pump @ 0x602F74 MOVE.B 0x16(A0),$408 then advances to the next
 * job. Job +0x16 is (slot+1)<<3 (@ 0x6003C4) so the exit write selects the
 * next job's slot (bits 15–11). BTST #7,$409 @ 0x602A5A follows 10× ROR. */
static u8 g_mslc;

static u16 be16_read(const u8 *p)
{
    return (u16)(((u16)p[0] << 8) | p[1]);
}

static i16 be16s_read(const u8 *p)
{
    return (i16)be16_read(p);
}

static void eg_tables_init(void)
{
    unsigned i;

    if (g_eg_ready)
        return;
    g_artable[0] = g_artable[1] = 0;
    g_drtable[0] = g_drtable[1] = 0;
    for (i = 2; i < 64u; i++) {
        if (k_ar_ms[i] <= 0.f)
            g_artable[i] = 1024 << 16;
        else
            g_artable[i] = (int)((1023.0 * 1000.0 / 44100.0 / (double)k_ar_ms[i])
                                 * 65536.0);
        g_drtable[i] = (int)((1023.0 * 1000.0 / 44100.0 / (double)k_dr_ms[i])
                             * 65536.0);
    }
    for (i = 0; i < 1024u; i++) {
        float env_db = (3.f * ((float)i - 1023.f)) / 32.f;

        g_eg_gain[i] = (int)(powf(10.f, env_db / 20.f) * 4096.f);
    }
    g_eg_ready = 1;
}

static int eg_rate_index(const scsp_slot_t *s, unsigned r)
{
    int oct = (int)((s->r[8] >> 11) & 0xfu);
    unsigned krs = (unsigned)((s->r[5] >> 10) & 0xfu);
    unsigned fns = (unsigned)(s->r[8] & 0x3ffu);
    int rate;

    if (oct & 8)
        oct -= 16;
    if (krs != 0xfu)
        rate = oct + (int)(2u * krs) + (int)((fns >> 9) & 1u);
    else
        rate = 0;
    rate += (int)(r << 1);
    if (rate < 0)
        rate = 0;
    if (rate > 63)
        rate = 63;
    return rate;
}

static void eg_compute(scsp_slot_t *s)
{
    s->eg_ar = g_artable[eg_rate_index(s, (unsigned)(s->r[4] & 0x1fu))];
    s->eg_d1r = g_drtable[eg_rate_index(s, (unsigned)((s->r[4] >> 6) & 0x1fu))];
    s->eg_d2r = g_drtable[eg_rate_index(s, (unsigned)((s->r[4] >> 11) & 0x1fu))];
    s->eg_rr = g_drtable[eg_rate_index(s, (unsigned)(s->r[5] & 0x1fu))];
    s->eg_dl = (u8)(0x1fu - ((s->r[5] >> 5) & 0x1fu));
    s->eg_hold = (u8)((s->r[4] >> 5) & 1u);
    s->lpslnk = (u8)((s->r[5] >> 14) & 1u);
}

static void slot_start(scsp_slot_t *s)
{
    eg_compute(s);
    s->keyon = 1;
    s->pos = 0;
    s->eg_state = EG_ATTACK;
    s->eg_vol = 0x17f << 16;
}

static int eg_update(scsp_slot_t *s)
{
    switch (s->eg_state) {
    case EG_ATTACK:
        s->eg_vol += s->eg_ar;
        if (s->eg_vol >= (0x3ff << 16)) {
            s->eg_vol = 0x3ff << 16;
            if (!s->lpslnk) {
                s->eg_state = EG_DECAY1;
                if (s->eg_d1r >= (1024 << 16))
                    s->eg_state = EG_DECAY2;
            }
        }
        if (s->eg_hold)
            return 4096;
        return (s->eg_vol >> 16) << 2;
    case EG_DECAY1:
        s->eg_vol -= s->eg_d1r;
        if (s->eg_vol < 0)
            s->eg_vol = 0;
        if ((s->eg_vol >> 21) <= (int)s->eg_dl)
            s->eg_state = EG_DECAY2;
        break;
    case EG_DECAY2:
        if (s->eg_d2r == 0)
            return g_eg_gain[s->eg_vol >> 16];
        s->eg_vol -= s->eg_d2r;
        if (s->eg_vol < 0)
            s->eg_vol = 0;
        break;
        case EG_RELEASE:
        s->eg_vol -= s->eg_rr;
        if (s->eg_vol <= 0) {
            s->eg_vol = 0;
            s->keyon = 0;
            /* Idle: drop KYONB so KYONEX cannot revive a finished voice. */
            s->r[0] &= (u16)~0x0800u;
            return 0;
        }
        break;
    default:
        return 0;
    }
    return g_eg_gain[s->eg_vol >> 16];
}

void model2_snd_scsp_reset(void)
{
    unsigned i;

    eg_tables_init();
    memset(g_slot, 0, sizeof(g_slot));
    memset(g_ram, 0, sizeof(g_ram));
    memset(g_ctrl, 0, sizeof(g_ctrl));
    memset(g_midi, 0, sizeof(g_midi));
    g_midi_r = g_midi_w = g_midi_n = 0;
    g_logged_keyon = 0;
    g_tima_div = 0;
    g_tima_pend = 0;
    g_tima_insns = 0;
    g_lfsr = 1u;
    g_mslc = 0;
    for (i = 0; i < SLOT_COUNT; i++)
        g_slot[i].eg_state = EG_RELEASE;
}

u8 *model2_snd_soundram(void)
{
    return g_ram;
}

void model2_snd_scsp_midi_in(u8 byte)
{
    if (g_midi_n >= MIDI_FIFO)
        return;
    g_midi[g_midi_w] = byte;
    g_midi_w = (g_midi_w + 1u) % MIDI_FIFO;
    g_midi_n++;
}

int model2_snd_scsp_midi_pending(void)
{
    return g_midi_n != 0u;
}

u8 model2_snd_scsp_midi_pop(void)
{
    u8 b;

    if (g_midi_n == 0u)
        return 0xffu;
    b = g_midi[g_midi_r];
    g_midi_r = (g_midi_r + 1u) % MIDI_FIFO;
    g_midi_n--;
    return b;
}

void model2_snd_scsp_tima_from_insns(int enable)
{
    g_tima_insns = enable ? 1 : 0;
}

void model2_snd_scsp_tima_raise(void)
{
    g_tima_pend = 1;
}

void model2_snd_scsp_cpu_cycles(unsigned insns)
{
    unsigned per;

    if (!g_tima_insns || !model2_snd_scsp_tima_armed())
        return;
    per = model2_snd_scsp_tima_period_samples();
    if (per == 0u)
        return;
    g_tima_div += insns;
    /* Insn-clock TIMA: treat one insn ≈ one sample tick (headless only). */
    while (g_tima_div >= per) {
        g_tima_div -= per;
        g_tima_pend = 1;
    }
}

int model2_snd_scsp_timer_a_pending(void)
{
    return g_tima_pend;
}

void model2_snd_scsp_timer_a_ack(void)
{
    g_tima_pend = 0;
}

static u16 scsp_ctrl16(unsigned off)
{
    return be16_read(g_ctrl + off);
}

int model2_snd_scsp_tima_armed(void)
{
    return (scsp_ctrl16(0x1eu) & 0x40u) != 0u;
}

int model2_snd_scsp_midi_irq_armed(void)
{
    return (scsp_ctrl16(0x1eu) & 0x08u) != 0u;
}

unsigned model2_snd_scsp_tima_period_samples(void)
{
    u16 w = scsp_ctrl16(0x18u);
    unsigned pris = 1u << ((w >> 8) & 7u);
    unsigned tima = w & 0xffu;

    if (tima >= 255u)
        return 0;
    return pris * (255u - tima);
}

static void slot_recalc(scsp_slot_t *s)
{
    u16 w0 = s->r[0];
    u16 w8 = s->r[8];
    int oct = (int)((w8 >> 11) & 0xfu);
    u32 fns = (u32)(w8 & 0x3ffu);
    int shift;

    s->sa = ((u32)(w0 & 0xfu) << 16) | s->r[1];
    s->lsa = s->r[2];
    s->lea = s->r[3] ? s->r[3] : 0xffffu;
    s->pcm8 = (u8)((w0 >> 4) & 1u);
    s->loop = (u8)((w0 >> 5) & 3u);
    s->ssctl = (u8)((w0 >> 7) & 3u);
    /* TL @ word 6 bits 0-7. Dry uses DISDL; IMXL is the DSP send.
     * DISDL=0 is mute dry — do not promote unused slots to full scale. */
    {
        unsigned tl = (unsigned)(s->r[6] & 0xffu);
        unsigned disdl = (unsigned)((s->r[11] >> 13) & 7u);
        unsigned efsdl = (unsigned)((s->r[11] >> 5) & 7u);
        unsigned imxl = (unsigned)(s->r[10] & 7u);
        unsigned pan = (unsigned)((s->r[11] >> 8) & 0x1fu);
        int send, pl, pr;

        send = 0;
        if (disdl)
            send += k_tl[tl] * k_sdl[disdl];
        if (imxl)
            send += k_tl[tl] * k_sdl[imxl];
        else if (!disdl && efsdl)
            send += k_tl[tl] * k_sdl[efsdl];
        pl = k_pan[pan & 0xfu];
        pr = 256;
        if (pan >= 0x10u) {
            pr = pl;
            pl = 256;
        }
        s->lvol = (send * pl) >> 8;
        s->rvol = (send * pr) >> 8;
    }
    if (oct & 8)
        oct -= 16;
    shift = oct + 6;
    s->step = (fns + 1024u);
    if (shift >= 0)
        s->step <<= (unsigned)shift;
    else
        s->step >>= (unsigned)(-shift);
    if (s->step == 0u)
        s->step = 1u << 10;
}

static u16 slot_reg(unsigned si, unsigned wi)
{
    return g_slot[si].r[wi];
}

static void slot_set(unsigned si, unsigned wi, u16 v)
{
    g_slot[si].r[wi] = v;
}

static int slot_rw(u32 addr, unsigned *si, unsigned *wi, int *hi)
{
    u32 off;

    if (addr < 0x100000u || addr >= 0x100400u)
        return 0;
    off = addr - 0x100000u;
    *si = off / 0x20u;
    *wi = (off & 0x1fu) / 2u;
    *hi = (off & 1u) == 0u;
    return *si < SLOT_COUNT;
}

static void keyon_execute(void)
{
    unsigned i;

    for (i = 0; i < SLOT_COUNT; i++) {
        scsp_slot_t *s = &g_slot[i];
        int kyonb = (s->r[0] & 0x0800u) != 0u;

        /* KYONEX scans every slot. Already-playing KYONB=1 must not restart
         * (that retriggered loops as a repeating noise on each sequencer tick). */
        if (kyonb && s->eg_state == EG_RELEASE) {
            slot_recalc(s);
            slot_start(s);
            if (g_logged_keyon < 12u) {
                unsigned disdl = (unsigned)((s->r[11] >> 13) & 7u);
                unsigned k;
                const u8 *pcm;
                u32 sa = s->sa;
                int oct = (int)((s->r[8] >> 11) & 0xfu);

                if (oct & 8)
                    oct -= 16;
                if (sa < SCSP_RAM)
                    pcm = g_ram + sa;
                else if (model2_snd_sample_rom())
                    pcm = model2_snd_sample_rom() + (sa % MODEL2_SND_SAMPLE_ROM_SIZE);
                else
                    pcm = g_ram;
                fprintf(stderr,
                        "lift: sound scsp keyon slot=%u sa=%06x lsa=%04x lea=%04x pcm8=%u "
                        "lp=%u ssctl=%u tl=%02x disdl=%u oct=%d fns=%u step=%u ar=%u rr=%u d2r=%u pcm=",
                        i, s->sa, s->lsa, s->lea,
                        s->pcm8, s->loop, s->ssctl,
                        (unsigned)(s->r[6] & 0xffu), disdl,
                        oct, (unsigned)(s->r[8] & 0x3ffu), s->step,
                        (unsigned)(s->r[4] & 0x1fu),
                        (unsigned)(s->r[5] & 0x1fu),
                        (unsigned)((s->r[4] >> 11) & 0x1fu));
                for (k = 0; k < 8u; k++)
                    fprintf(stderr, "%02x", pcm[k]);
                fputc('\n', stderr);
                g_logged_keyon++;
            }
        } else if (!kyonb && s->keyon) {
            s->eg_state = EG_RELEASE;
        }
    }
}

static u8 *ctrl_byte(u32 addr)
{
    u32 off = addr - 0x100000u;

    if (off >= 0x400u && off < 0x440u)
        return g_ctrl + (off - 0x400u);
    return NULL;
}

/* SCSP $408/$409: write MSLC (slot to monitor); read CA|SGC|EG.
 * CA[0] = sample index bit 12 → $409 bit 7. Copy pump @ 0x602A5A / 0x602AA6
 * waits on that bit (phase 0 wants set, phase $80 wants clear) to fill the
 * silent 4KB of an 8KB lea=$1FFF RAM loop. MSLC from $408 is bits 15–11. */
static u16 scsp_monitor_compute(unsigned mslc)
{
    const scsp_slot_t *s = &g_slot[mslc & 31u];
    u32 idx = s->pos >> 16;
    u32 ca;
    u32 sgc = (u32)s->eg_state & 3u;
    u32 eg = (0x1fu - ((u32)s->eg_vol >> 21)) & 0x1fu;

    /* Copy pump BTST #7,$409 @ 0x602A5A is CA bit 0 = sample index bit 12
     * (4KB half of the 8KB lea=$1FFF RAM loop). Wrap idx into LSA..LEA so a
     * stalled 32-bit pos still reports the playing half. */
    if (s->loop && s->lea >= s->lsa) {
        u32 span = (u32)s->lea - (u32)s->lsa + 1u;

        if (span)
            idx = (u32)s->lsa + (idx - (u32)s->lsa) % span;
    }
    ca = (idx >> 12) & 0xfu;
    return (u16)((ca << 7) | (sgc << 5) | eg);
}

static void scsp_mslc_select(u8 slot)
{
    g_mslc = (u8)(slot & 31u);
}

/* MOVE.B to $408 writes bits 15–8; MSLC is bits 15–11 → slot = byte >> 3. */
static void scsp_mslc_write_hi(u8 hi)
{
    scsp_mslc_select((u8)((hi >> 3) & 31u));
}

u8 model2_snd_scsp_read8(u32 addr)
{
    unsigned si, wi;
    int hi;

    if (addr == 0x100405u)
        return model2_snd_scsp_midi_pop();
    if (addr == 0x100408u)
        return (u8)(scsp_monitor_compute(g_mslc) >> 8);
    if (addr == 0x100409u)
        return (u8)scsp_monitor_compute(g_mslc);
    if (slot_rw(addr, &si, &wi, &hi)) {
        u16 v = slot_reg(si, wi);

        return hi ? (u8)(v >> 8) : (u8)v;
    }
    {
        u8 *p = ctrl_byte(addr);

        if (p)
            return *p;
    }
    return 0;
}

u16 model2_snd_scsp_read16(u32 addr)
{
    unsigned si, wi;
    int hi;

    if (addr == 0x100404u || addr == 0x100405u)
        return (u16)model2_snd_scsp_midi_pop();
    if ((addr & ~1u) == 0x100408u)
        return scsp_monitor_compute(g_mslc);
    if (slot_rw(addr & ~1u, &si, &wi, &hi))
        return slot_reg(si, wi);
    {
        u8 *p = ctrl_byte(addr & ~1u);

        if (p)
            return be16_read(p);
    }
    return 0;
}

static void scsp_dma(void)
{
    u16 w12 = be16_read(g_ctrl + 0x12);
    u16 w14 = be16_read(g_ctrl + 0x14);
    u16 w16 = be16_read(g_ctrl + 0x16);
    u32 dmea = ((u32)(w12 & 0xfffeu)) | (((u32)(w14 & 0xf000u)) << 4);
    u32 drga = (u32)(w14 & 0x0ffeu);
    unsigned dtlg = (unsigned)(w16 & 0x0ffeu);
    int ddir = (w16 >> 13) & 1;
    unsigned i;
    static int logged;
    static int in_dma;

    if (in_dma)
        return;
    in_dma = 1;
    g_ctrl[0x16] = (u8)((w16 & ~0x1000u) >> 8);
    g_ctrl[0x17] = (u8)(w16 & ~0x1000u);
    if (!logged) {
        fprintf(stderr,
                "lift: sound scsp dma dmea=%05x drga=%03x dtlg=%u ddir=%d\n",
                dmea, drga, dtlg, ddir);
        logged = 1;
    }
    for (i = 0; i < dtlg; i += 2u) {
        u32 mem = dmea & (SCSP_RAM - 1u);
        u32 reg = 0x100000u + (drga & 0xffeu);

        if (ddir) {
            u16 v = model2_snd_scsp_read16(reg);

            g_ram[mem] = (u8)(v >> 8);
            g_ram[mem + 1u] = (u8)v;
        } else {
            u16 v = be16_read(g_ram + mem);

            model2_snd_scsp_write16(reg, v);
        }
        dmea += 2u;
        drga += 2u;
    }
    in_dma = 0;
}

static void maybe_keyon(unsigned si, u16 value, int word0)
{
    if (!word0)
        return;
    slot_recalc(&g_slot[si]);
    if (value & 0x1000u) {
        keyon_execute();
        g_slot[si].r[0] &= (u16)~0x1000u;
    }
}

void model2_snd_scsp_write8(u32 addr, u8 value)
{
    unsigned si, wi;
    int hi;

    if (slot_rw(addr, &si, &wi, &hi)) {
        u16 cur = slot_reg(si, wi);

        if (hi)
            cur = (u16)((cur & 0x00ffu) | ((u16)value << 8));
        else
            cur = (u16)((cur & 0xff00u) | value);
        slot_set(si, wi, cur);
        slot_recalc(&g_slot[si]);
        maybe_keyon(si, cur, wi == 0u && hi);
        return;
    }
    {
        u8 *p = ctrl_byte(addr);

        if (p)
            *p = value;
        if (addr == 0x100408u)
            scsp_mslc_write_hi(value);
        /* SCIRE @ $422: TIMA ISR @ 0x602702 MOVE.W #$0040,$422(A5). */
        if ((addr == 0x100422u || addr == 0x100423u) && (value & 0x40u))
            model2_snd_scsp_timer_a_ack();
        if ((addr & ~1u) == 0x100416u && (model2_snd_scsp_read16(0x100416u) & 0x1000u))
            scsp_dma();
    }
}

void model2_snd_scsp_write16(u32 addr, u16 value)
{
    unsigned si, wi;
    int hi;

    if (slot_rw(addr & ~1u, &si, &wi, &hi)) {
        slot_set(si, wi, value);
        slot_recalc(&g_slot[si]);
        maybe_keyon(si, value, wi == 0u);
        return;
    }
    {
        u8 *p = ctrl_byte(addr & ~1u);

        if (p) {
            p[0] = (u8)(value >> 8);
            p[1] = (u8)value;
        }
        if ((addr & ~1u) == 0x100408u)
            scsp_mslc_write_hi((u8)(value >> 8));
        if ((addr & ~1u) == 0x100422u && (value & 0x40u))
            model2_snd_scsp_timer_a_ack();
        if ((addr & ~1u) == 0x100416u && (value & 0x1000u))
            scsp_dma();
    }
}

static i16 fetch_pcm(const scsp_slot_t *s, u32 sa_off)
{
    const u8 *rom = model2_snd_sample_rom();
    u32 addr = s->sa + sa_off;
    const u8 *p = NULL;

    if (s->ssctl == 1u) {
        g_lfsr = g_lfsr * 1103515245u + 12345u;
        return (i16)(g_lfsr >> 16);
    }
    if (s->ssctl >= 2u)
        return 0;

    /* 68k map: RAM 0..0x7FFFF, sample ROM linear at 0x800000.
     * Slot SA is a 20/22-bit PCM address: RAM first, then ROM at the same offset. */
    if (addr >= 0x800000u && rom) {
        u32 o = (addr - 0x800000u) % MODEL2_SND_SAMPLE_ROM_SIZE;

        p = rom + o;
        addr = 0x800000u + o;
    } else if (addr < SCSP_RAM) {
        p = g_ram + addr;
    } else if (rom) {
        p = rom + (addr % MODEL2_SND_SAMPLE_ROM_SIZE);
        addr = 0x800000u;
    } else {
        return 0;
    }

    if (s->pcm8)
        return (i16)((i16)(int8_t)p[0] << 8);
    if (addr >= 0x800000u) {
        u32 o = (s->sa + sa_off - 0x800000u) % MODEL2_SND_SAMPLE_ROM_SIZE;

        if (o + 1u >= MODEL2_SND_SAMPLE_ROM_SIZE)
            return 0;
        return be16s_read(rom + o);
    }
    if (s->sa + sa_off + 1u >= SCSP_RAM)
        return 0;
    return be16s_read(p);
}

void model2_snd_scsp_render(i16 *stereo, unsigned frames)
{
    unsigned f;
    unsigned i;

    memset(stereo, 0, frames * 2u * sizeof(i16));
    for (f = 0; f < frames; f++) {
        int acc_l = 0;
        int acc_r = 0;

        for (i = 0; i < SLOT_COUNT; i++) {
            scsp_slot_t *s = &g_slot[i];
            u32 idx;
            i16 smp;
            int gain;

            if (!s->keyon)
                continue;
            idx = s->pos >> 16;
            if (s->lpslnk && s->eg_state == EG_ATTACK && idx >= s->lsa) {
                s->eg_state = EG_DECAY1;
                if (s->eg_d1r >= (1024 << 16))
                    s->eg_state = EG_DECAY2;
            }
            if (idx >= s->lea) {
                if (s->loop) {
                    idx = s->lsa;
                    s->pos = (s->lsa << 16) + (s->pos - (s->lea << 16));
                    idx = s->pos >> 16;
                } else {
                    /* One-shot done: clear KYONB so a later KYONEX (@ note-on
                     * ORI #$18) does not restart this slot — that retriggered
                     * splash one-shots as a short repeating blip over the voice. */
                    s->keyon = 0;
                    s->eg_state = EG_RELEASE;
                    s->r[0] &= (u16)~0x0800u;
                    continue;
                }
            }
            smp = fetch_pcm(s, s->pcm8 ? idx : (idx << 1));
            gain = eg_update(s);
            if (!s->keyon)
                continue;
            acc_l += (((int)smp * s->lvol) >> 16) * gain >> 12;
            acc_r += (((int)smp * s->rvol) >> 16) * gain >> 12;
            s->pos += s->step;
        }
        /* Dry DISDL on Rally BGM is ~−24 dB under a DSP wet path we do not
         * run (IMXL=0, no EFREG). 16× keeps TL/pan ratios and is audible. */
        acc_l <<= 4;
        acc_r <<= 4;
        {
            unsigned mvol = (unsigned)(g_ctrl[1] & 0x0fu);

            acc_l = (acc_l * (int)mvol) / 15;
            acc_r = (acc_r * (int)mvol) / 15;
        }
        if (acc_l > 32767)
            acc_l = 32767;
        if (acc_l < -32768)
            acc_l = -32768;
        if (acc_r > 32767)
            acc_r = 32767;
        if (acc_r < -32768)
            acc_r = -32768;
        stereo[f * 2u] = (i16)acc_l;
        stereo[f * 2u + 1u] = (i16)acc_r;
    }
}

unsigned model2_snd_scsp_keyon_count(void)
{
    unsigned i;
    unsigned n = 0;

    for (i = 0; i < SLOT_COUNT; i++) {
        if (g_slot[i].keyon)
            n++;
    }
    return n;
}
