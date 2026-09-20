/* Host ROM call routing — trampoline only for unknown / traced calls. */
#include "i960_host.h"
#include "i960_host_invoke.h"
#include "i960_host_staging.h"
#include "i960_host_syms.h"
#include "model2_hw.h"
#include "model2_snd.h"
#include "lift_syms.h"
#include "model2_rom.h"
#include "model2_geo.h"
#include "sys24_viewer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define I960_HOST_TRACE_MAX 256

typedef struct {
    u32 addr;
    unsigned count;
} i960_host_hit_t;

static unsigned g_dispatch_count;
static unsigned g_dispatch_max = 64;
static int g_dispatch_halt;
static int g_trace_abort_unknown;
static int g_trace_verbose = 1;
static int g_milestone_boot_armed;
static int g_milestone_boot_reached;
static u32 g_milestone_boot_script;
static int g_milestone_boot_wants_splash;

#define BOOT_SCRIPT_SOUND_INIT   0x005b9a10u
#define BOOT_SCRIPT_COPYRIGHT_END 0x005b9960u

static i960_host_hit_t g_hits[I960_HOST_TRACE_MAX];
static unsigned g_hit_count;

static int tracing_enabled(void)
{
    return g_trace_verbose || g_trace_abort_unknown;
}

static void read_milestone_env(void)
{
    const char *boot_s = getenv("I960_HOST_MILESTONE_BOOT");
    const char *legacy_s = getenv("I960_HOST_MILESTONE_SOUND_INIT");

    g_milestone_boot_wants_splash = 0;
    g_milestone_boot_script = BOOT_SCRIPT_COPYRIGHT_END;
    if (boot_s && *boot_s) {
        if (strcmp(boot_s, "sound_init") == 0)
            g_milestone_boot_script = BOOT_SCRIPT_SOUND_INIT;
        else if (strcmp(boot_s, "copyright") == 0)
            g_milestone_boot_script = BOOT_SCRIPT_COPYRIGHT_END;
        else if (strcmp(boot_s, "splash") == 0)
            g_milestone_boot_wants_splash = 1;
    } else if (legacy_s && *legacy_s && legacy_s[0] != '0') {
        g_milestone_boot_script = BOOT_SCRIPT_SOUND_INIT;
    }
}

static void arm_boot_milestone(void)
{
    g_milestone_boot_armed = 1;
    g_dispatch_max = 0;
}

void i960_host_milestone_boot_arm(const char *target)
{
    g_milestone_boot_wants_splash = 0;
    if (target && strcmp(target, "sound_init") == 0)
        g_milestone_boot_script = BOOT_SCRIPT_SOUND_INIT;
    else if (target && strcmp(target, "splash") == 0)
        g_milestone_boot_wants_splash = 1;
    else
        g_milestone_boot_script = BOOT_SCRIPT_COPYRIGHT_END;
    arm_boot_milestone();
}

void i960_host_milestone_boot_notify_splash(u32 catalog_vaddr, u32 batch)
{
    const char *dump;

    if (!g_milestone_boot_armed || g_milestone_boot_reached || !g_milestone_boot_wants_splash)
        return;

    dump = getenv("I960_PALETTE_DUMP");
    fprintf(stderr,
            "lift: milestone — CGM splash drawn catalog=%#x batch=%u\n",
            catalog_vaddr, batch);
    /* Drain colorbase ring before halt — splash_frame uses i960_call_rom. */
    boot_tile_splash_frame(0, 0, 0);
    if (dump && *dump)
        model2_palette_state_dump(dump);
    g_milestone_boot_reached = 1;
    g_dispatch_halt = 1;
}

void i960_host_milestone_boot_notify_script(u32 script_vaddr)
{
    if (script_vaddr == BOOT_SCRIPT_COPYRIGHT_END && i960_host_boot_screen()) {
        const char *dump = getenv("I960_PALETTE_DUMP");

        fprintf(stderr,
                "lift: boot — copyright notice displayed (script @ 0x%08x) after SOUND+countdown %.2fs\n",
                script_vaddr, i960_host_boot_clock_elapsed());
        if (dump && *dump && !g_milestone_boot_wants_splash)
            model2_palette_state_dump(dump);
    }

    if (!g_milestone_boot_armed || g_milestone_boot_reached)
        return;
    if (g_milestone_boot_wants_splash)
        return;
    if (script_vaddr != g_milestone_boot_script)
        return;
    g_milestone_boot_reached = 1;
    g_dispatch_halt = 1;
    if (g_milestone_boot_script == BOOT_SCRIPT_SOUND_INIT) {
        fprintf(stderr,
                "lift: milestone — SOUND INITIALIZE script finished (tile map @ 0x01000000)\n");
    } else {
        fprintf(stderr,
                "lift: milestone — copyright notice displayed (script @ 0x%08x)\n",
                script_vaddr);
    }
}

int i960_host_milestone_boot_reached(void)
{
    return g_milestone_boot_reached;
}

void i960_host_milestone_sound_init_arm(void)
{
    i960_host_milestone_boot_arm("sound_init");
}

void i960_host_milestone_sound_init_notify(u32 script_vaddr)
{
    i960_host_milestone_boot_notify_script(script_vaddr);
}

int i960_host_milestone_sound_init_reached(void)
{
    return g_milestone_boot_reached
        && g_milestone_boot_script == BOOT_SCRIPT_SOUND_INIT;
}

static void read_env(void)
{
    const char *max_s = getenv("I960_HOST_MAX_DISPATCH");
    const char *abort_s = getenv("I960_HOST_TRACE_ABORT");
    const char *quiet_s = getenv("I960_HOST_TRACE_QUIET");
    const char *milestone_s = getenv("I960_HOST_MILESTONE_SOUND_INIT");
    const char *boot_ms_s = getenv("I960_HOST_MILESTONE_BOOT");

    if (max_s && *max_s)
        g_dispatch_max = (unsigned)strtoul(max_s, NULL, 0);
    if (abort_s && *abort_s && abort_s[0] != '0')
        g_trace_abort_unknown = 1;
    if (quiet_s && *quiet_s && quiet_s[0] != '0')
        g_trace_verbose = 0;
    read_milestone_env();
    if ((milestone_s && *milestone_s && milestone_s[0] != '0')
        || (boot_ms_s && *boot_ms_s)) {
        arm_boot_milestone();
    }
}

void i960_host_trace_init(void)
{
    read_env();
    g_dispatch_count = 0;
    g_hit_count = 0;
    g_dispatch_halt = 0;
    g_milestone_boot_reached = 0;
}

void i960_host_dispatch_reset(void)
{
    read_env();
    g_dispatch_count = 0;
    g_dispatch_halt = 0;
}

int i960_host_dispatch_halted(void)
{
    return g_dispatch_halt;
}

void i960_host_request_halt(void)
{
    g_dispatch_halt = 1;
}

void i960_host_frame_present(void)
{
    const char *dump;
    static unsigned s_boot_dump_frame;

    i960_host_skip_practice_tick();

    if (sys24_viewer_wanted()) {
        /* Live: SDL present runs inside geo_vsync_wait (one swap per frame). */
        if (sys24_viewer_poll_events() != 0) {
            fprintf(stderr, "lift: live view closed — halting dispatch\n");
            g_dispatch_halt = 1;
        }
        return;
    }

    if (!i960_host_boot_screen())
        return;
    dump = getenv("I960_PALETTE_DUMP");
    if (!dump || !*dump)
        return;
    /* Throttle PNG writes — full dump is expensive at 60+ fps. */
    s_boot_dump_frame++;
    if (s_boot_dump_frame == 1 || (s_boot_dump_frame % 30u) == 0u)
        model2_palette_state_dump(dump);
}

static void record_hit(u32 addr)
{
    unsigned i;

    for (i = 0; i < g_hit_count; i++) {
        if (g_hits[i].addr == addr) {
            g_hits[i].count++;
            return;
        }
    }
    if (g_hit_count < I960_HOST_TRACE_MAX) {
        g_hits[g_hit_count].addr = addr;
        g_hits[g_hit_count].count = 1;
        g_hit_count++;
    }
}

static void log_unknown(u32 raw_addr, u32 rom_addr, const char *via)
{
    const char *name = i960_host_sym_name(rom_addr);

    fprintf(stderr, "lift: %s 0x%08x", via, rom_addr);
    if (raw_addr != rom_addr)
        fprintf(stderr, " (raw 0x%08x)", raw_addr);
    if (name)
        fprintf(stderr, " — symbol %s is not lifted", name);
    else
        fprintf(stderr, " — unknown ROM target");
    fprintf(stderr, "\n");

    if (g_trace_abort_unknown) {
        fprintf(stderr, "lift: abort on unknown ROM call (set I960_HOST_TRACE_ABORT=0 to continue)\n");
        i960_host_trace_summary();
        abort();
    }
}

static void log_call(u32 raw_addr, u32 rom_addr, const char *via)
{
    const char *name = i960_host_sym_name(rom_addr);

    record_hit(rom_addr);
    if (!g_trace_verbose)
        return;

    if (raw_addr != rom_addr) {
        if (name)
            fprintf(stderr, "lift: %s 0x%08x → rom 0x%08x (%s, staged workram)\n",
                    via, raw_addr, rom_addr, name);
        else
            fprintf(stderr, "lift: %s 0x%08x → rom 0x%08x (staged workram)\n",
                    via, raw_addr, rom_addr);
    } else if (name) {
        fprintf(stderr, "lift: %s 0x%08x (%s)\n", via, rom_addr, name);
    } else {
        fprintf(stderr, "lift: %s 0x%08x (unknown)\n", via, rom_addr);
    }
}

void i960_host_trace_summary(void)
{
    unsigned i;

    fprintf(stderr, "lift: dispatch trace — %u call(s), %u unique address(es)\n",
            g_dispatch_count, g_hit_count);
    for (i = 0; i < g_hit_count; i++) {
        const char *name = i960_host_sym_name(g_hits[i].addr);
        if (name)
            fprintf(stderr, "  0x%08x  %s  (%u)\n", g_hits[i].addr, name, g_hits[i].count);
        else
            fprintf(stderr, "  0x%08x  ???  (%u)\n", g_hits[i].addr, g_hits[i].count);
    }
    fprintf(stderr,
            "lift: geo prg_fifo words=%u (total=%u) copro_fifo words=%u sound midi bytes=%u\n",
            model2_hw_prg_count(),
            model2_hw_prg_total(),
            model2_hw_copro_count(),
            model2_snd_total());
    {
        const char *dump = getenv("I960_GEO_DUMP");
        const char *cdump = getenv("I960_COPRO_DUMP");
        const char *summary = getenv("I960_GEO_SUMMARY");
        const char *sdump = getenv("I960_SND_DUMP");

        if (dump && *dump)
            model2_hw_dump(dump);
        if (cdump && *cdump)
            model2_hw_dump_copro(cdump);
        if (summary && *summary) {
            /* Prefer densest successfully-decoded mesh already in the collector.
             * Only re-publish/re-decode when the mesh is still empty. */
            if (model2_geo_vertex_count() == 0) {
                model2_hw_latch_prg_frame();
                model2_hw_prg_publish_best();
                model2_geo_decode();
            }
            model2_geo_dump_summary(summary);
            fprintf(stderr, "lift: geo mesh verts=%u tris=%u\n",
                    model2_geo_vertex_count(),
                    model2_geo_triangle_count());
        }
        if (sdump && *sdump) {
            model2_snd_dump(sdump);
            fprintf(stderr, "lift: sound dump %s (%u bytes)\n",
                    sdump, model2_snd_total());
        }
    }
    {
        const char *pdir = getenv("I960_PALETTE_DUMP");

        if (pdir && *pdir)
            model2_palette_state_dump(pdir);
    }
}

static void maybe_stop(void)
{
    if (g_dispatch_max == 0 || g_dispatch_halt)
        return;
    if (g_dispatch_count < g_dispatch_max)
        return;
    fprintf(stderr, "lift: reached I960_HOST_MAX_DISPATCH=%u — stopping\n", g_dispatch_max);
    g_dispatch_halt = 1;
}

static void dispatch_trampoline(u32 raw_addr, const char *via)
{
    u32 rom_addr;

    if (g_dispatch_halt)
        return;

    rom_addr = i960_host_resolve_call_target(raw_addr);

    g_dispatch_count++;

    if (tracing_enabled())
        log_call(raw_addr, rom_addr, via);

    if (i960_host_staging_call_lifted(raw_addr)) {
        maybe_stop();
        return;
    }
    if (i960_host_invoke_lifted(rom_addr)) {
        maybe_stop();
        return;
    }

    if (tracing_enabled())
        log_unknown(raw_addr, rom_addr, via);
    maybe_stop();
}

void i960_call_rom(uintptr_t addr)
{
    dispatch_trampoline((u32)addr, "call");
}

void i960_call_indirect(uintptr_t target)
{
    dispatch_trampoline((u32)target, "callx");
}
