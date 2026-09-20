/* Host emulation of videoctl @ 0x98000c (geo_vsync_wait @ 0x4788–0x47B0).
 *
 * MAME model2.cpp videoctl_r: bit 2 from screen frame number + render_mode @
 * 0x10000000 (geo_renderer_init stos 4 @ 0x372C).
 *
 * Pacing (one blocker per geo_vsync_wait):
 *   --live / SDL: one sys24_viewer_flip (SwapWindow) per wait; emulated videoctl
 *   may advance 2 steps when render_mode=0 without a second present.
 *   I960_HOST_VIDEO_SYNC without SDL: pthread timer @ model2_tile_vsync_hz().
 *   Offline: instant emulated vblank steps (no wall clock). */

#include "model2_hw.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VIDEO_CTL_BIT2  (1u << 2)

static pthread_mutex_t g_vsync_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_vsync_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_vsync_thread;
static u32 g_framenum;
static u32 g_video_ctl;
static u8 g_videocontrol;
static int g_render_mode;
static int g_thread_started;
static int g_thread_stop;
static int g_realtime_cached = -1;
static int g_logged_timing;
static int g_logged_render_mode;

static unsigned videoctl_bit2(u32 ctl)
{
    return (ctl >> 2) & 1u;
}

static u8 videoctl_compute(void)
{
    u8 frame_bits;

    if (!g_render_mode)
        frame_bits = (u8)((g_framenum & 2u) << 1);
    else
        frame_bits = (u8)((g_framenum & 1u) << 2);
    return frame_bits | (g_videocontrol & 3u);
}

static void videoctl_refresh_locked(void)
{
    g_video_ctl = (u32)videoctl_compute();
}

static double host_vsync_hz(void)
{
    const char *hz_s = getenv("I960_HOST_FRAME_HZ");
    double hz;
    const model2_hw_host_ops_t *host = model2_hw_host();

    if (hz_s && *hz_s) {
        hz = strtod(hz_s, NULL);
        if (hz >= 1.0 && hz <= 120.0)
            return hz;
    }
    if (host && host->vsync_hz) {
        hz = host->vsync_hz();
        if (hz >= 1.0 && hz <= 120.0)
            return hz;
    }
    return 57.524; /* Model 2 nominal refresh */
}

static long vsync_period_ns(void)
{
    double hz = host_vsync_hz();

    if (hz < 1.0)
        hz = 1.0;
    if (hz > 120.0)
        hz = 120.0;
    return (long)(1000000000.0 / hz);
}

static void timespec_add_ns(struct timespec *t, long ns)
{
    t->tv_nsec += ns;
    while (t->tv_nsec >= 1000000000L) {
        t->tv_nsec -= 1000000000L;
        t->tv_sec++;
    }
}

int model2_hw_vsync_realtime(void)
{
    const char *s;

    if (g_realtime_cached >= 0)
        return g_realtime_cached;

    s = getenv("I960_HOST_VIDEO_SYNC");
    if (s && *s) {
        g_realtime_cached = (s[0] != '0');
        return g_realtime_cached;
    }
    {
        const model2_hw_host_ops_t *host = model2_hw_host();
        if (host && host->display_wanted && host->display_wanted()) {
            g_realtime_cached = 1;
            return 1;
        }
    }
    s = getenv("I960_HOST_FRAME_PACE");
    if (s && *s) {
        g_realtime_cached = (s[0] != '0');
        return g_realtime_cached;
    }
    g_realtime_cached = 0;
    return 0;
}

static int display_wanted(void)
{
    const model2_hw_host_ops_t *host = model2_hw_host();
    return host && host->display_wanted && host->display_wanted();
}

static int vsync_use_sdl_clock(void)
{
    return model2_hw_vsync_realtime() && display_wanted();
}

static void log_vsync_timing_once(void)
{
    if (g_logged_timing)
        return;
    g_logged_timing = 1;
    if (vsync_use_sdl_clock()) {
        fprintf(stderr,
                "model2_hw: video sync — SDL present + %.2f Hz host pacer "
                "(videoctl frame# + render_mode@0x10000000)\n",
                host_vsync_hz());
        return;
    }
    fprintf(stderr,
            "model2_hw: video sync — %.2f Hz (%.2f ms) timer; videoctl frame# + "
            "render_mode@0x10000000 (override I960_HOST_FRAME_HZ)\n",
            host_vsync_hz(),
            (double)vsync_period_ns() / 1000000.0);
}

static int vsync_flip_one_frame(void)
{
    static struct timespec s_deadline;
    static int s_deadline_init;
    struct timespec now;
    const long period_ns = vsync_period_ns();

    /*
     * HW irq_init_major runs splash_frame each vblank before the next scanout.
     * Sync workram layer regs → tile_ram before compositing so HUD/credits
     * (sys24) overlay the 3D layer with current scroll/enable bits.
     */
    {
        const model2_hw_host_ops_t *host = model2_hw_host();
        if (host && host->boot_vblank)
            host->boot_vblank();
        if (host && host->display_flip && host->display_flip() != 0) {
            fprintf(stderr, "model2_hw: live view closed — requesting halt\n");
            if (host->request_halt)
                host->request_halt();
            return -1;
        }
    }

    /*
     * One geo_vsync_wait == one game frame. Pace to ROM refresh (~57.5 Hz) with
     * SwapInterval(0); blocking on display vsync was dropping to ~30 Hz whenever
     * a frame took >16ms (geo decode), doubling SOUND INITIALIZE to ~8s.
     */
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!s_deadline_init) {
        s_deadline = now;
        s_deadline_init = 1;
    }
    timespec_add_ns(&s_deadline, period_ns);
    if (now.tv_sec > s_deadline.tv_sec
        || (now.tv_sec == s_deadline.tv_sec && now.tv_nsec >= s_deadline.tv_nsec)) {
        /* Fell behind — resync so we don't spiral. */
        s_deadline = now;
        timespec_add_ns(&s_deadline, period_ns);
    } else {
        struct timespec rem;

        rem.tv_sec = s_deadline.tv_sec - now.tv_sec;
        rem.tv_nsec = s_deadline.tv_nsec - now.tv_nsec;
        if (rem.tv_nsec < 0) {
            rem.tv_sec--;
            rem.tv_nsec += 1000000000L;
        }
        nanosleep(&rem, NULL);
    }
    return 0;
}

static void *vsync_timer_thread(void *arg)
{
    struct timespec deadline;
    const long period_ns = vsync_period_ns();

    (void)arg;

    log_vsync_timing_once();
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    for (;;) {
        struct timespec now;
        struct timespec rem;

        timespec_add_ns(&deadline, period_ns);

        pthread_mutex_lock(&g_vsync_mtx);
        if (g_thread_stop) {
            pthread_mutex_unlock(&g_vsync_mtx);
            break;
        }
        g_framenum++;
        videoctl_refresh_locked();
        pthread_cond_broadcast(&g_vsync_cond);
        pthread_mutex_unlock(&g_vsync_mtx);

        for (;;) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec
                || (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
                break;
            rem.tv_sec = deadline.tv_sec - now.tv_sec;
            rem.tv_nsec = deadline.tv_nsec - now.tv_nsec;
            if (rem.tv_nsec < 0) {
                rem.tv_sec--;
                rem.tv_nsec += 1000000000L;
            }
            nanosleep(&rem, NULL);
        }
    }
    return NULL;
}

static void vsync_thread_ensure(void)
{
    if (!model2_hw_vsync_realtime())
        return;
    /* Live view uses SDL_RenderPresent as the sole wall-clock pacer. */
    if (display_wanted())
        return;
    if (g_thread_started)
        return;

    g_thread_stop = 0;
    if (pthread_create(&g_vsync_thread, NULL, vsync_timer_thread, NULL) != 0) {
        fprintf(stderr, "model2_hw: video sync thread create failed\n");
        return;
    }
    g_thread_started = 1;
}

void model2_hw_vsync_hw_reset(void)
{
    pthread_mutex_lock(&g_vsync_mtx);
    g_framenum = 0;
    g_videocontrol = 0;
    g_render_mode = 0;
    g_video_ctl = 0;
    g_logged_render_mode = 0;
    pthread_mutex_unlock(&g_vsync_mtx);
}

void model2_hw_vsync_hw_shutdown(void)
{
    if (!g_thread_started)
        return;

    pthread_mutex_lock(&g_vsync_mtx);
    g_thread_stop = 1;
    pthread_cond_broadcast(&g_vsync_cond);
    pthread_mutex_unlock(&g_vsync_mtx);

    pthread_join(g_vsync_thread, NULL);
    g_thread_started = 0;
    g_thread_stop = 0;
}

void model2_hw_render_mode_write(u32 value)
{
    pthread_mutex_lock(&g_vsync_mtx);
    g_render_mode = (int)((value >> 2) & 1u);
    videoctl_refresh_locked();
    if (!g_logged_render_mode) {
        g_logged_render_mode = 1;
        fprintf(stderr,
                "model2_hw: render_mode@0x10000000 <= 0x%x → videoctl bit2 every %d vblank(s)\n",
                value,
                g_render_mode ? 1 : 2);
    }
    pthread_mutex_unlock(&g_vsync_mtx);
}

u32 model2_hw_video_ctl_read(void)
{
    u32 ctl;

    pthread_mutex_lock(&g_vsync_mtx);
    ctl = g_video_ctl;
    pthread_mutex_unlock(&g_vsync_mtx);
    return ctl;
}

void model2_hw_video_ctl_write(u32 value)
{
    pthread_mutex_lock(&g_vsync_mtx);
    g_videocontrol = (u8)((g_videocontrol & (u8)~3u) | (u8)(value & 3u));
    videoctl_refresh_locked();
    pthread_mutex_unlock(&g_vsync_mtx);
}

/*
 * Replacement for the MMIO poll loop @ 0x479C–0x47B0: block until bit 2 != latched.
 * Offline harness: advance emulated vblanks until bit 2 edges (no wall clock).
 */
void model2_hw_vsync_wait_bit2_toggle(unsigned latched_bit2)
{
    if (!model2_hw_vsync_realtime()) {
        pthread_mutex_lock(&g_vsync_mtx);
        do {
            g_framenum++;
            videoctl_refresh_locked();
        } while (videoctl_bit2(g_video_ctl) == latched_bit2);
        pthread_mutex_unlock(&g_vsync_mtx);
        return;
    }

    if (vsync_use_sdl_clock()) {
        log_vsync_timing_once();
        /*
         * One SDL SwapWindow == one game frame (game_mode_apply calls geo_vsync_wait
         * once per main loop). HW may need 1–2 emulated vblanks for videoctl bit 2
         * to edge (render_mode @ 0x10000000); do not block on a second present.
         */
        if (vsync_flip_one_frame() != 0)
            return;
        pthread_mutex_lock(&g_vsync_mtx);
        g_framenum++;
        videoctl_refresh_locked();
        if (videoctl_bit2(g_video_ctl) == latched_bit2) {
            g_framenum++;
            videoctl_refresh_locked();
        }
        pthread_mutex_unlock(&g_vsync_mtx);
        return;
    }

    vsync_thread_ensure();

    pthread_mutex_lock(&g_vsync_mtx);
    while (videoctl_bit2(g_video_ctl) == latched_bit2) {
        if (g_thread_stop) {
            g_framenum++;
            videoctl_refresh_locked();
            break;
        }
        pthread_cond_wait(&g_vsync_cond, &g_vsync_mtx);
    }
    pthread_mutex_unlock(&g_vsync_mtx);
}

void model2_hw_vsync_frame_done(void)
{
    /* Latch completed frame's prg words for mesh decode (geo_vsync_wait @ 0x4758). */
    model2_hw_latch_prg_frame();
}
