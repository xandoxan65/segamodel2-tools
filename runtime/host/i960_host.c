#include "i960_host.h"
#include "model2_hw.h"
#include "model2_geo.h"
#include "model2_hw_lift.h"
#include "model2_rom.h"
#include "model2_snd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int i960_host_boot_screen(void)
{
    const char *boot = getenv("I960_HOST_BOOT_SCREEN");

    return boot && boot[0] && boot[0] != '0';
}

/* Skip 240-frame post-sound countdown in game_inner_dispatch (boot harness only). */
int i960_host_boot_fast_countdown(void)
{
    const char *fast;

    if (!i960_host_boot_screen())
        return 0;
    /* --practice still skips the sound wait under live vsync. */
    if (i960_host_skip_practice())
        return 1;
    /* Real-time harness uses the ROM frame counter (240 ticks ≈ 4 s @ 60 Hz). */
    if (i960_host_frame_pace_enabled())
        return 0;
    fast = getenv("I960_HOST_BOOT_FAST_COUNTDOWN");
    if (fast && (fast[0] == '0' || fast[0] == '\0'))
        return 0;
    return 1;
}

int i960_host_skip_practice(void)
{
    const char *skip = getenv("I960_HOST_SKIP_PRACTICE");

    return skip && skip[0] && skip[0] != '0';
}

/* True when geo_vsync_wait uses realtime video timer (env, --live). */
int i960_host_frame_pace_enabled(void)
{
    return model2_hw_vsync_realtime();
}

/* Minimal workram backing for fp-relative boot_entry stack slots. */
static u8 host_workram[0x2000];

extern void boot_entry(u32 arg0, u32 arg1, u32 arg2);

int i960_host_skip_hw_timer = 0;

static void zero_registers(void)
{
    g0 = g1 = g2 = g3 = g4 = g5 = g6 = g7 = g8 = g9 = 0;
    g10 = g11 = g12 = g13 = g14 = g15 = 0;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = 0;
    r8 = r9 = r10 = r11 = r12 = r13 = r14 = r15 = 0;
    fp0 = fp1 = fp2 = fp3 = 0.0;
    fp = 0;
    sp = 0;
    pfp = 0;
}

void i960_host_load_rom(void)
{
    if (model2_rom_load_default() != 0) {
        fprintf(stderr, "lift: ROM load failed (run: make rom-blocks); using zero-filled maincpu\n");
    }
    /* Geo/polygon ROM loads lazily on first FIFO decode (avoids ~8MB startup read). */
}

void i960_host_reset(void)
{
    model2_hw_init_from_lift();
    model2_snd_reset();
    if (model2_snd_load_roms(NULL) != 0)
        fprintf(stderr, "lift: sound ROMs not loaded (68k+SCSP silent)\n");
    model2_io_board_reset();
    zero_registers();
    /*
     * boot_prcb @ +0x14 holds 0x1030 (initial stack). Place fp/sp in host_workram
     * so boot_entry can use fp+0x40 without faulting.
     */
    fp = (uintptr_t)(host_workram + 0x100);
    sp = fp + 0x1030 - 0x100;
    if (sp >= (uintptr_t)(host_workram + sizeof(host_workram)))
        sp = (uintptr_t)(host_workram + 0x800);
}

void boot_entry_host(u32 arg0, u32 arg1, u32 arg2)
{
    i960_host_skip_hw_timer = 1;
    boot_entry(arg0, arg1, arg2);
    i960_host_skip_hw_timer = 0;
}

extern u32 post_reset_dispatch(u32 arg0, u32 arg1, u32 arg2);

void i960_host_run_post_reset(u32 arg0, u32 arg1, u32 arg2)
{
    fprintf(stderr, "lift: entering post_reset_dispatch @ 0x570 (callx trace on stderr)\n");
    (void)post_reset_dispatch(arg0, arg1, arg2);
    if (i960_host_milestone_boot_reached())
        return;
    fprintf(stderr, "lift: post_reset_dispatch returned unexpectedly\n");
}

static struct timespec g_boot_clock0;
static int g_boot_clock_set;

void i960_host_boot_clock_mark(void)
{
    clock_gettime(CLOCK_MONOTONIC, &g_boot_clock0);
    g_boot_clock_set = 1;
}

double i960_host_boot_clock_elapsed(void)
{
    struct timespec now;
    if (!g_boot_clock_set)
        return 0.0;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - g_boot_clock0.tv_sec)
        + (now.tv_nsec - g_boot_clock0.tv_nsec) * 1e-9;
}
