#include "model2_snd.h"
#include "model2_snd_midi.h"
#include "model2_snd_rom.h"
#include "model2_snd_scsp.h"
#include "model2_snd_m68k.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SOUND_UART_BASE    0x01C80000u
#define I8251_TXRDY        0x01u
#define I8251_TXE          0x04u
#define MIDI_CAP           4096u
#define UART_Q             1024u
#define PCM_RATE           44100u
#define PCM_CHUNK          256u
#define PCM_RING           8192u
/* SCSP 22.5792 MHz / 2 = 11.2896 MHz 68k → 256 cycles per 44.1 kHz sample.
 * Copy pump @ 0x602A46 waits 10× ROL.L #8 (24 cyc) for $409 CA. */

static u8 g_midi[MIDI_CAP];
static unsigned g_midi_total;
static u8 g_last_command;
static int g_log;
static u8 g_pkt[3];
static unsigned g_pkt_n;

static u8 g_uart[UART_Q];
static unsigned g_uart_r, g_uart_w, g_uart_n;
static pthread_mutex_t g_uart_mu = PTHREAD_MUTEX_INITIALIZER;

static i16 g_pcm[PCM_RING * 2u];
static unsigned g_pcm_r, g_pcm_n;
static pthread_mutex_t g_pcm_mu = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_cpu_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thr;
static int g_thr_on;
static volatile int g_thr_stop;
static unsigned g_tima_samp;
static unsigned g_cyc_frac;
static int g_logged_song;
static int g_logged_mix;
static int g_logged_tima_per;

static int env_flag_on(const char *name)
{
    const char *e = getenv(name);

    return e && e[0] && e[0] != '0';
}

static int uart_is_data(u32 offset)
{
    u32 off = offset - SOUND_UART_BASE;

    return off < 4u && (off & 2u) == 0u;
}

static int uart_is_ctrl(u32 offset)
{
    u32 off = offset - SOUND_UART_BASE;

    return off < 4u && (off & 2u) != 0u;
}

static void log_midi_byte(u8 byte)
{
    if (!model2_snd_log_enabled() && g_logged_song)
        return;
    g_pkt[g_pkt_n++] = byte;
    if (g_pkt_n < 3u)
        return;
    if (g_pkt[0] == 0xaeu && g_pkt[1] == 0x20u && !g_logged_song) {
        fprintf(stderr,
                "lift: sound song start id=0x%02x (BGM after SOUND INITIALIZE)\n",
                g_pkt[2]);
        g_logged_song = 1;
    }
    if (model2_snd_log_enabled())
        fprintf(stderr, "lift: sound midi  %02x %02x %02x\n",
                g_pkt[0], g_pkt[1], g_pkt[2]);
    g_pkt_n = 0;
}

static unsigned uart_drain(u8 *dst, unsigned cap)
{
    unsigned n = 0;

    pthread_mutex_lock(&g_uart_mu);
    while (n < cap && g_uart_n) {
        dst[n++] = g_uart[g_uart_r];
        g_uart_r = (g_uart_r + 1u) % UART_Q;
        g_uart_n--;
    }
    pthread_mutex_unlock(&g_uart_mu);
    return n;
}

static void pcm_push(const i16 *stereo, unsigned frames)
{
    unsigned i;

    pthread_mutex_lock(&g_pcm_mu);
    for (i = 0; i < frames; i++) {
        unsigned w;

        if (g_pcm_n >= PCM_RING) {
            g_pcm_r = (g_pcm_r + 1u) % PCM_RING;
            g_pcm_n--;
        }
        w = (g_pcm_r + g_pcm_n) % PCM_RING;
        g_pcm[w * 2u] = stereo[i * 2u];
        g_pcm[w * 2u + 1u] = stereo[i * 2u + 1u];
        g_pcm_n++;
    }
    pthread_mutex_unlock(&g_pcm_mu);
}

static void pcm_pull(i16 *stereo, unsigned frames)
{
    unsigned i;

    pthread_mutex_lock(&g_pcm_mu);
    for (i = 0; i < frames; i++) {
        if (g_pcm_n) {
            stereo[i * 2u] = g_pcm[g_pcm_r * 2u];
            stereo[i * 2u + 1u] = g_pcm[g_pcm_r * 2u + 1u];
            g_pcm_r = (g_pcm_r + 1u) % PCM_RING;
            g_pcm_n--;
        } else {
            stereo[i * 2u] = 0;
            stereo[i * 2u + 1u] = 0;
        }
    }
    pthread_mutex_unlock(&g_pcm_mu);
}

static void boot_68k(void)
{
    unsigned n;

    model2_snd_scsp_tima_from_insns(0);
    for (n = 0; n < 4000000u && model2_snd_m68k_alive(); n += 1024u) {
        model2_snd_m68k_run(1024);
        if ((model2_snd_m68k_sr() & 0x0700u) != 0x0700u && n > 64u)
            break;
    }
    model2_snd_m68k_run(64);
    if (!model2_snd_m68k_alive())
        fprintf(stderr, "lift: sound 68k stopped during reset pc=%06x sr=%04x\n",
                (unsigned)model2_snd_m68k_pc(),
                (unsigned)model2_snd_m68k_sr());
    else
        fprintf(stderr,
                "lift: sound 68k+SCSP ready pc=%06x sr=%04x a5=%08x a6=%08x "
                "tima_armed=%d midi_irq=%d tima_period=%u\n",
                (unsigned)model2_snd_m68k_pc(),
                (unsigned)model2_snd_m68k_sr(),
                (unsigned)model2_snd_m68k_areg(5),
                (unsigned)model2_snd_m68k_areg(6),
                model2_snd_scsp_tima_armed(),
                model2_snd_scsp_midi_irq_armed(),
                model2_snd_scsp_tima_period_samples());
}

static void board_chunk(void)
{
    u8 bytes[64];
    unsigned n;
    unsigned k;
    i16 mix[PCM_CHUNK * 2u];
    int peak = 0;

    n = uart_drain(bytes, 64);
    pthread_mutex_lock(&g_cpu_mu);
    for (k = 0; k < n; k++) {
        log_midi_byte(bytes[k]);
        model2_snd_scsp_midi_in(bytes[k]);
    }
    {
        unsigned per = 0;
        unsigned i = 0;

        if (model2_snd_scsp_tima_armed())
            per = model2_snd_scsp_tima_period_samples();
        if (per != 0u && !g_logged_tima_per) {
            fprintf(stderr, "lift: sound TIMA period=%u samples (%.1f Hz)\n",
                    per, (double)PCM_RATE / (double)per);
            g_logged_tima_per = 1;
        }
        for (;;) {
            unsigned cyc;

            while (g_cyc_frac >= 256u && i < PCM_CHUNK) {
                g_cyc_frac -= 256u;
                model2_snd_scsp_render(mix + i * 2u, 1);
                if (per != 0u) {
                    g_tima_samp++;
                    if (g_tima_samp >= per) {
                        g_tima_samp -= per;
                        model2_snd_scsp_tima_raise();
                    }
                }
                i++;
            }
            if (i >= PCM_CHUNK)
                break;
            if (!model2_snd_m68k_alive()) {
                g_cyc_frac += 256u;
                continue;
            }
            cyc = model2_snd_m68k_exec();
            g_cyc_frac += cyc ? cyc : 12u;
        }
    }
    /* SOUND INITIALIZE splash is 68k boot — no i960 MIDI yet. */
    if (g_midi_total == 0u)
        memset(mix, 0, sizeof(mix));
    if (!g_logged_mix) {
        for (k = 0; k < PCM_CHUNK * 2u; k++) {
            int s = mix[k];

            if (s < 0)
                s = -s;
            if (s > peak)
                peak = s;
        }
        if (peak > 32) {
            fprintf(stderr, "lift: sound mix peak=%d keyon=%u\n",
                    peak, model2_snd_scsp_keyon_count());
            g_logged_mix = 1;
        }
    }
    pthread_mutex_unlock(&g_cpu_mu);
    pcm_push(mix, PCM_CHUNK);
}

static void *board_thread(void *arg)
{
    struct timespec deadline;

    (void)arg;
    pthread_mutex_lock(&g_cpu_mu);
    boot_68k();
    pthread_mutex_unlock(&g_cpu_mu);
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    while (!g_thr_stop) {
        struct timespec now, rem;

        board_chunk();
        deadline.tv_nsec += (long)((PCM_CHUNK * 1000000000ull) / PCM_RATE);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        rem.tv_sec = deadline.tv_sec - now.tv_sec;
        rem.tv_nsec = deadline.tv_nsec - now.tv_nsec;
        if (rem.tv_nsec < 0) {
            rem.tv_sec--;
            rem.tv_nsec += 1000000000L;
        }
        if (rem.tv_sec > 0 || (rem.tv_sec == 0 && rem.tv_nsec > 0))
            nanosleep(&rem, NULL);
        else if (rem.tv_sec < -1)
            deadline = now;
    }
    return NULL;
}

static void thread_stop(void)
{
    if (!g_thr_on)
        return;
    g_thr_stop = 1;
    pthread_join(g_thr, NULL);
    g_thr_on = 0;
    g_thr_stop = 0;
}

static int thread_start(void)
{
    if (g_thr_on)
        return 0;
    g_thr_stop = 0;
    g_tima_samp = 0;
    g_logged_song = 0;
    g_logged_mix = 0;
    g_logged_tima_per = 0;
    g_pkt_n = 0;
    g_uart_r = g_uart_w = g_uart_n = 0;
    g_pcm_r = g_pcm_n = 0;
    if (pthread_create(&g_thr, NULL, board_thread, NULL) != 0) {
        fprintf(stderr, "lift: sound thread create failed\n");
        return -1;
    }
    g_thr_on = 1;
    fprintf(stderr, "lift: sound thread 68k+SCSP @ %u Hz (TIMA from TACTL)\n",
            PCM_RATE);
    return 0;
}

void model2_snd_reset(void)
{
    thread_stop();
    memset(g_midi, 0, sizeof(g_midi));
    g_midi_total = 0;
    g_last_command = 0;
    g_pkt_n = 0;
    g_uart_r = g_uart_w = g_uart_n = 0;
    g_pcm_r = g_pcm_n = 0;
    g_tima_samp = 0;
    g_cyc_frac = 0;
    g_logged_song = 0;
    g_logged_mix = 0;
    g_logged_tima_per = 0;
    model2_snd_midi_reset();
    model2_snd_scsp_reset();
    if (model2_snd_rom_loaded())
        model2_snd_m68k_reset();
}

void model2_snd_set_log(int enable)
{
    g_log = enable ? 1 : 0;
}

int model2_snd_log_enabled(void)
{
    return g_log || env_flag_on("I960_SND_LOG");
}

void model2_snd_log_cmd(u32 index, u8 b0, u8 b1, u8 b2)
{
    if (!model2_snd_log_enabled())
        return;
    fprintf(stderr, "lift: sound cmd index=%#x  %02x %02x %02x\n",
            (unsigned)index, b0, b1, b2);
}

void model2_snd_midi_in(u8 byte)
{
    const model2_snd_host_ops_t *host;

    g_midi[g_midi_total % MIDI_CAP] = byte;
    g_midi_total++;
    host = model2_snd_host();
    if (host && host->on_midi_byte)
        host->on_midi_byte(byte);

    pthread_mutex_lock(&g_uart_mu);
    if (g_uart_n < UART_Q) {
        g_uart[g_uart_w] = byte;
        g_uart_w = (g_uart_w + 1u) % UART_Q;
        g_uart_n++;
    }
    pthread_mutex_unlock(&g_uart_mu);
}

void model2_snd_mmio_write(u32 offset, u32 value)
{
    u8 byte = (u8)(value & 0xffu);

    if (uart_is_data(offset)) {
        model2_snd_midi_in(byte);
        return;
    }
    if (uart_is_ctrl(offset))
        g_last_command = byte;
}

u32 model2_snd_mmio_read(u32 offset)
{
    if (uart_is_ctrl(offset))
        /* Tx always ready: host is faster than 31.25 kHz MIDI. */
        return (u32)(I8251_TXRDY | I8251_TXE);
    if (uart_is_data(offset))
        return 0;
    return 0;
}

unsigned model2_snd_count(void)
{
    unsigned n = g_midi_total;

    if (n > MIDI_CAP)
        n = MIDI_CAP;
    return n;
}

unsigned model2_snd_total(void)
{
    return g_midi_total;
}

const u8 *model2_snd_bytes(unsigned *out_count)
{
    if (out_count)
        *out_count = model2_snd_count();
    return g_midi;
}

unsigned model2_snd_copy_range(unsigned start_abs, unsigned end_abs, u8 *dst,
                               unsigned dst_cap)
{
    unsigned i;
    unsigned n = 0;
    unsigned oldest;

    if (!dst || !dst_cap || end_abs <= start_abs)
        return 0;

    oldest = (g_midi_total > MIDI_CAP) ? (g_midi_total - MIDI_CAP) : 0u;
    if (start_abs < oldest)
        start_abs = oldest;
    if (end_abs > g_midi_total)
        end_abs = g_midi_total;
    for (i = start_abs; i < end_abs && n < dst_cap; i++)
        dst[n++] = g_midi[i % MIDI_CAP];
    return n;
}

void model2_snd_dump(const char *path)
{
    FILE *fp;
    unsigned i;
    unsigned total;
    unsigned start;
    unsigned n;
    u8 buf[MIDI_CAP];

    if (!path || !*path)
        return;
    fp = fopen(path, "w");
    if (!fp)
        return;
    total = model2_snd_total();
    start = (total > MIDI_CAP) ? (total - MIDI_CAP) : 0u;
    fprintf(fp, "# model2_snd MIDI log  total=%u last_cmd=0x%02x\n",
            total, g_last_command);
    n = model2_snd_copy_range(start, total, buf, MIDI_CAP);
    for (i = 0; i < n; i++) {
        fprintf(fp, "%02x", buf[i]);
        if ((i % 16u) == 15u || i + 1u == n)
            fputc('\n', fp);
        else
            fputc(' ', fp);
    }
    fclose(fp);
    if (model2_snd_log_enabled()) {
        u8 *ram;

        pthread_mutex_lock(&g_cpu_mu);
        ram = model2_snd_soundram();
        fprintf(stderr,
                "lift: sound 68k end pc=%06x alive=%d keyon=%u ram2200=%02x q2506=%u\n",
                (unsigned)model2_snd_m68k_pc(),
                model2_snd_m68k_alive(),
                model2_snd_scsp_keyon_count(),
                ram[0x2200], ram[0x2506]);
        {
            unsigned k;

            fprintf(stderr, "lift: sound ram4000");
            for (k = 0; k < 20u; k++)
                fprintf(stderr, " %02x:%02x", ram[0x4000u + k * 16u],
                        ram[0x4001u + k * 16u]);
            fputc('\n', stderr);
            fprintf(stderr,
                    "lift: sound obj3000 %02x %02x delay=%02x%02x ptr=%02x%02x%02x%02x\n",
                    ram[0x3000], ram[0x3001], ram[0x3002], ram[0x3003],
                    ram[0x3004], ram[0x3005], ram[0x3006], ram[0x3007]);
            fprintf(stderr, "lift: sound pcm10000");
            for (k = 0; k < 16u; k++)
                fprintf(stderr, " %02x", ram[0x10000u + k]);
            fputc('\n', stderr);
        }
        pthread_mutex_unlock(&g_cpu_mu);
    }
}

int model2_snd_load_roms(const char *rom_dir)
{
    const char *dir = rom_dir;

    if (!dir || !*dir)
        dir = getenv("SEGAMOD2_ROM_DIR");
    if (!dir || !*dir)
        dir = getenv("DECOMP_ROM_DIR");
    if (!dir || !*dir)
        dir = "../ROMS/srallyc-b";
    thread_stop();
    if (model2_snd_rom_load(dir) != 0)
        return -1;
    model2_snd_scsp_reset();
    model2_snd_m68k_reset();
    /* 68k boot + TIMA/mix run on the board thread — UART only queues. */
    return thread_start();
}

void model2_snd_render(signed short *stereo, unsigned frames)
{
    if (!stereo || !frames)
        return;
    pcm_pull((i16 *)stereo, frames);
}
