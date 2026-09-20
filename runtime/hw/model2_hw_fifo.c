#include "model2_hw.h"
#include "model2_tgp.h"
#include "model2_host_aspect.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GEO_PRG_FIFO_OFF   0x00804000u
#define COPRO_FIFO_OFF     0x00884000u
#define GEO_PRG_CAP        262144u

static u32 g_geo_prg[GEO_PRG_CAP];
/* Copro matrix snapshot at each prg write (same ring indexing as g_geo_prg). */
static float g_prg_mtx[GEO_PRG_CAP][12];
/* Total words ever written (ring index = total % GEO_PRG_CAP). */
static unsigned g_geo_prg_total;
/* Absolute index where the in-progress frame's prg stream began. */
static unsigned g_prg_frame_mark;
/* Last completed frame latched at vsync_frame_done. */
static unsigned g_prg_display_start;
static unsigned g_prg_display_end;
static unsigned g_prg_display_gen;
/* Densest non-empty frame this run (headless summary / stable overlay). */
static unsigned g_prg_best_start;
static unsigned g_prg_best_end;
static unsigned g_prg_best_words;
/* 0 = texture DRAM / polygon RAM upload; do not retain words for mesh decode.
 * MAME still parses geo_texture_data / geo_polygon_data into geo RAM — see
 * upload capture below (geo_reg_texture_sync @ 0x476F0). */
static int g_prg_mesh_enable = 1;
static u32 g_geo_capture_cmd;
static unsigned g_geo_capture_n;
static u32 g_geo_capture_payload[6];
/*
 * Side-effect capture for geo cmds 0x04 / 0x05 / 0x15 (MAME geo_texture_data /
 * geo_polygon_data). Runs even when mesh retention is off so texture_sync fills
 * polygon/texture RAM for later span_table / marker_burst object draws.
 */
static u32 g_upload_cmd; /* 0, 0x04, 0x05, or 0x15 */
static u32 g_upload_addr;
static u32 g_upload_count;
static u32 g_upload_seen;
static u32 *g_upload_buf;
static unsigned g_upload_cap;
static int g_upload_have_addr;
static int g_upload_have_count;
static float g_geo_focus[2];
static u32 g_geo_window[6];
static int g_geo_projection_valid;
/*
 * MAME geo_parse persistent shading — cmds 0x06 / 0x07 / 0x0A from
 * geo_fifo_bootstrap (@ 0x4AC0). Frame latches omit bootstrap, so keep these
 * at the geo_w / prg FIFO boundary like focus/window (0x03 / 0x09).
 */
static float g_geo_light[3];
static int g_geo_mode;
static int g_geo_light_valid;
static int g_geo_mode_valid;
static int g_geo_tex_valid;
static u32 g_geo_tex_param[32]; /* packed diffuse|amb<<8|spec_s<<16|spec_c<<24 */
static float g_geo_tex_coef[32];
/* Variable-length capture for cmd 0x06. */
static unsigned g_geo_shade_need; /* total payload words still expected */
static u32 g_geo_tex_index;
static u32 g_geo_tex_count;
static u32 g_geo_tex_seen; /* pairs completed */
static int g_geo_tex_phase; /* 0=index, 1=count, 2=pairs */

static u32 g_geo_write_ptr;
static int g_trace;
static pthread_mutex_t g_fifo_mtx = PTHREAD_MUTEX_INITIALIZER;
static void (*g_fifo_notify)(void);

#define VIDEO_CTL_OFF 0x0098000cu
#define GEO_WRITE_PTR_OFF 0x00802008u

static void read_env(void)
{
    const char *s = getenv("I960_GEO_TRACE");
    g_trace = (s && *s && s[0] != '0');
}

static u32 fbits(float f)
{
    union {
        u32 u;
        float f;
    } v;
    v.f = f;
    return v.u;
}

static float u2f(u32 u)
{
    union {
        u32 u;
        float f;
    } v;
    v.u = u;
    return v.f;
}

static void prg_push_locked(u32 value);

/*
 * TGP host emit: marker 0x05 / 0x55 → GEO PRG 0x0B + 12 floats.
 * Invoked under g_fifo_mtx from model2_tgp_fifo_write.
 */
void model2_hw_tgp_emit_geo_matrix(const float m[12])
{
    unsigned i;
    static unsigned s_scale_log;

    prg_push_locked(0x0Bu << 23);
    for (i = 0; i < 12u; i++)
        prg_push_locked(fbits(m[i]));
    {
        float d0 = m[0], d4 = m[4], d8 = m[8];
        float tx = m[9], ty = m[10], tz = m[11];
        float amax = 0.f;
        unsigned j;

        for (j = 0; j < 12u; j++) {
            float a = fabsf(m[j]);

            if (a > amax)
                amax = a;
        }
        /* Cap routine view-matrix spam; keep NaN/huge-T one-shots. */
        if (s_scale_log < 12u
            || fabsf(tx) > 1.0e5f || fabsf(ty) > 1.0e5f || fabsf(tz) > 1.0e5f
            || !(amax == amax)) {
            fprintf(stderr,
                    "lift: tgp 0x05→0x0B diag=(%.4g,%.4g,%.4g) T=(%.4g,%.4g,%.4g) "
                    "maxabs=%.4g\n",
                    d0, d4, d8, tx, ty, tz, amax);
            fflush(stderr);
            if (s_scale_log < 1000u)
                s_scale_log++;
        }
    }
}

void model2_hw_set_fifo_notify(void (*fn)(void))
{
    g_fifo_notify = fn;
}

void model2_hw_reset(void)
{
    read_env();
    pthread_mutex_lock(&g_fifo_mtx);
    g_geo_prg_total = 0;
    g_prg_frame_mark = 0;
    g_prg_display_start = 0;
    g_prg_display_end = 0;
    g_prg_display_gen = 0;
    g_prg_best_start = 0;
    g_prg_best_end = 0;
    g_prg_best_words = 0;
    g_geo_capture_cmd = 0;
    g_geo_capture_n = 0;
    memset(g_geo_capture_payload, 0, sizeof(g_geo_capture_payload));
    g_geo_focus[0] = g_geo_focus[1] = 1.f;
    memset(g_geo_window, 0, sizeof(g_geo_window));
    g_geo_projection_valid = 0;
    g_geo_light[0] = 0.f;
    g_geo_light[1] = 0.f;
    g_geo_light[2] = 1.f;
    g_geo_mode = 0;
    g_geo_light_valid = 0;
    g_geo_mode_valid = 0;
    g_geo_tex_valid = 0;
    memset(g_geo_tex_param, 0, sizeof(g_geo_tex_param));
    {
        unsigned i;
        for (i = 0; i < 32u; i++)
            g_geo_tex_coef[i] = 1.f;
    }
    g_geo_shade_need = 0;
    g_geo_tex_index = 0;
    g_geo_tex_count = 0;
    g_geo_tex_seen = 0;
    g_geo_tex_phase = 0;
    g_geo_write_ptr = 0;
    model2_tgp_reset();
    pthread_mutex_unlock(&g_fifo_mtx);
    model2_hw_vsync_hw_reset();
}

void model2_hw_fifo_reset_counts(void)
{
    pthread_mutex_lock(&g_fifo_mtx);
    g_geo_prg_total = 0;
    g_prg_frame_mark = 0;
    g_prg_display_start = 0;
    g_prg_display_end = 0;
    g_prg_display_gen = 0;
    g_prg_best_start = 0;
    g_prg_best_end = 0;
    g_prg_best_words = 0;
    model2_tgp_fifo_reset_counts();
    pthread_mutex_unlock(&g_fifo_mtx);
}

u32 model2_hw_mmio_read(u32 offset)
{
    u32 v;

    if (offset == VIDEO_CTL_OFF)
        return model2_hw_video_ctl_read();
    if (offset == GEO_WRITE_PTR_OFF)
        return g_geo_write_ptr;
    if (offset == COPRO_FIFO_OFF
        || (offset >= 0x00884000u && offset < 0x00888000u)) {
        pthread_mutex_lock(&g_fifo_mtx);
        v = model2_tgp_fifo_read();
        pthread_mutex_unlock(&g_fifo_mtx);
        if (g_trace)
            fprintf(stderr, "geo: copro_fifo read → 0x%08x\n", v);
        return v;
    }
    return 0;
}

/* Push one word into the geo PRG ring (caller holds g_fifo_mtx). */
static void prg_push_locked(u32 value)
{
    unsigned slot;

    if (!g_prg_mesh_enable)
        return;
    slot = g_geo_prg_total % GEO_PRG_CAP;
    g_geo_prg[slot] = value;
    model2_tgp_matrix(g_prg_mtx[slot]);
    g_geo_prg_total++;
}

/* Pending completed upload to flush outside g_fifo_mtx (avoids render lock nesting). */
static u32 g_pending_upload_cmd;
static u32 g_pending_upload_addr;
static u32 g_pending_upload_count;
static u32 *g_pending_upload_copy;
static int g_pending_upload_ready;

static void upload_reset_locked(void)
{
    g_upload_cmd = 0;
    g_upload_addr = 0;
    g_upload_count = 0;
    g_upload_seen = 0;
    g_upload_have_addr = 0;
    g_upload_have_count = 0;
}

static void upload_queue_complete_locked(void)
{
    free(g_pending_upload_copy);
    g_pending_upload_copy = NULL;
    g_pending_upload_cmd = g_upload_cmd;
    g_pending_upload_addr = g_upload_addr;
    g_pending_upload_count = g_upload_count;
    if (g_upload_count > 0u && g_upload_buf) {
        g_pending_upload_copy =
            (u32 *)malloc((size_t)g_upload_count * sizeof(u32));
        if (g_pending_upload_copy)
            memcpy(g_pending_upload_copy, g_upload_buf,
                   (size_t)g_upload_count * sizeof(u32));
        else
            g_pending_upload_count = 0;
    }
    g_pending_upload_ready = 1;
    upload_reset_locked();
}

static void upload_start_locked(u32 cmd)
{
    /* Abandon a truncated prior command; texture_sync does not interleave. */
    upload_reset_locked();
    g_upload_cmd = cmd;
}

static void upload_feed_locked(u32 value)
{
    if (g_upload_cmd == 0u)
        return;
    if (!g_upload_have_addr) {
        g_upload_addr = value;
        g_upload_have_addr = 1;
        return;
    }
    if (!g_upload_have_count) {
        g_upload_count = value;
        g_upload_have_count = 1;
        g_upload_seen = 0;
        if (g_upload_count == 0u) {
            upload_queue_complete_locked();
            return;
        }
        if (g_upload_count > g_upload_cap) {
            u32 *nbuf =
                (u32 *)realloc(g_upload_buf, (size_t)g_upload_count * sizeof(u32));

            if (!nbuf) {
                upload_reset_locked();
                return;
            }
            g_upload_buf = nbuf;
            g_upload_cap = g_upload_count;
        }
        return;
    }
    if (g_upload_seen < g_upload_count)
        g_upload_buf[g_upload_seen++] = value;
    if (g_upload_seen >= g_upload_count)
        upload_queue_complete_locked();
}

static void upload_flush_pending(void)
{
    u32 cmd;
    u32 addr;
    u32 count;
    u32 *copy;

    pthread_mutex_lock(&g_fifo_mtx);
    if (!g_pending_upload_ready) {
        pthread_mutex_unlock(&g_fifo_mtx);
        return;
    }
    cmd = g_pending_upload_cmd;
    addr = g_pending_upload_addr;
    count = g_pending_upload_count;
    copy = g_pending_upload_copy;
    g_pending_upload_copy = NULL;
    g_pending_upload_ready = 0;
    pthread_mutex_unlock(&g_fifo_mtx);

    {
        const model2_hw_host_ops_t *host = model2_hw_host();
        if (cmd == 0x04u) {
            if (host && host->upload_texture)
                host->upload_texture(addr, count, copy);
        } else if (cmd == 0x05u || cmd == 0x15u) {
            if (host && host->upload_polygon)
                host->upload_polygon(addr, count, copy);
        }
    }
    free(copy);
}

void model2_hw_prg_mesh_enable(int enable)
{
    pthread_mutex_lock(&g_fifo_mtx);
    g_prg_mesh_enable = enable ? 1 : 0;
    if (enable) {
        /* Drop any partial frame so the next attract DL starts clean. */
        g_prg_frame_mark = g_geo_prg_total;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
}

static void geo_capture_payload_locked(u32 value)
{
    unsigned need;

    /* Cmd 0x06 texture_parameters — MAME geo_texture_parameters. */
    if (g_geo_capture_cmd == 0x06u) {
        if (g_geo_tex_phase == 0) {
            g_geo_tex_index = value >> 2;
            g_geo_tex_phase = 1;
            return;
        }
        if (g_geo_tex_phase == 1) {
            g_geo_tex_count = value;
            g_geo_tex_seen = 0;
            g_geo_tex_phase = 2;
            if (g_geo_tex_count == 0u) {
                g_geo_tex_valid = 1;
                g_geo_capture_cmd = 0;
                g_geo_tex_phase = 0;
            }
            return;
        }
        /* phase 2: alternating param, coef */
        if ((g_geo_tex_seen & 1u) == 0u) {
            g_geo_tex_param[g_geo_tex_index & 0x1fu] = value;
        } else {
            unsigned idx = g_geo_tex_index & 0x1fu;
            union {
                u32 u;
                float f;
            } cv;

            cv.u = value;
            g_geo_tex_coef[idx] = cv.f;
            g_geo_tex_index = (g_geo_tex_index + 1u) & 0x1fu;
        }
        g_geo_tex_seen++;
        if (g_geo_tex_seen >= g_geo_tex_count * 2u) {
            g_geo_tex_valid = 1;
            g_geo_capture_cmd = 0;
            g_geo_tex_phase = 0;
        }
        return;
    }

    /* Cmd 0x07 mode — one word. */
    if (g_geo_capture_cmd == 0x07u) {
        g_geo_mode = (int)value;
        g_geo_mode_valid = 1;
        g_geo_capture_cmd = 0;
        return;
    }

    /* Cmd 0x0A light — three floats. */
    if (g_geo_capture_cmd == 0x0au) {
        if (g_geo_capture_n < 3u)
            g_geo_capture_payload[g_geo_capture_n++] = value;
        if (g_geo_capture_n != 3u)
            return;
        g_geo_light[0] = u2f(g_geo_capture_payload[0]);
        g_geo_light[1] = u2f(g_geo_capture_payload[1]);
        g_geo_light[2] = u2f(g_geo_capture_payload[2]);
        g_geo_light_valid = 1;
        g_geo_capture_cmd = 0;
        g_geo_capture_n = 0;
        return;
    }

    if (g_geo_capture_cmd != 0x03u && g_geo_capture_cmd != 0x09u)
        return;
    need = (g_geo_capture_cmd == 0x03u) ? 6u : 2u;
    if (g_geo_capture_n < need)
        g_geo_capture_payload[g_geo_capture_n++] = value;
    if (g_geo_capture_n != need)
        return;

    if (g_geo_capture_cmd == 0x03u) {
        memcpy(g_geo_window, g_geo_capture_payload, sizeof(g_geo_window));
    } else {
        g_geo_focus[0] = u2f(g_geo_capture_payload[0]);
        g_geo_focus[1] = u2f(g_geo_capture_payload[1]);
        model2_host_apply_fov_scale(&g_geo_focus[0], &g_geo_focus[1]);
    }
    g_geo_projection_valid =
        g_geo_focus[0] > 0.f && g_geo_focus[1] > 0.f
        && (g_geo_window[1] != 0u || g_geo_window[0] != 0u);
    g_geo_capture_cmd = 0;
    g_geo_capture_n = 0;
}

/*
 * MAME model2.cpp geo_w — command ports @ 0x800000..0x800FFF encode a geo
 * opcode into bufferram / PRG FIFO. Attract bank poke @ 0x800010+(bank<<10)
 * with data 0 pushes object_data opcode 0x00800000 before catalog quads.
 */
static int geo_w_command_port(u32 address, u32 data)
{
    u32 r;
    u32 function;

    if (address >= 0x1000u)
        return 0;

    if (data & 0x80000000u) {
        r = (data & 0x800fffffu) | (((address >> 4) & 0x3fu) << 23);
        prg_push_locked(r);
        return 1;
    }
    if ((address & 0xfu) != 0u)
        return 0;

    function = (address >> 4) & 0x3fu;
    r = (data & 0x000fffffu) | (function << 23);
    /* Eye-mode packing used by Sega Rally car select (MAME geo_w). */
    if ((address >> 4) & 0xc0u) {
        if (function == 1u)
            r |= ((address >> 10) & 3u) << 29;
    }
    prg_push_locked(r);
    /*
     * MAME geo_texture_data (0x04) / geo_polygon_data (0x05/0x15): capture the
     * following FIFO address/count/body even when mesh retention is off.
     */
    if (function == 0x04u || function == 0x05u || function == 0x15u)
        upload_start_locked(function);
    if (function == 0x03u || function == 0x09u || function == 0x06u
        || function == 0x07u || function == 0x0au) {
        g_geo_capture_cmd = function;
        g_geo_capture_n = 0;
        g_geo_tex_phase = 0;
        g_geo_tex_seen = 0;
        g_geo_shade_need = 0;
    } else {
        g_geo_capture_cmd = 0;
        g_geo_capture_n = 0;
        g_geo_tex_phase = 0;
    }
    return 1;
}

void model2_hw_mmio_write(u32 offset, u32 value)
{
    int notify = 0;

    if (offset == GEO_WRITE_PTR_OFF) {
        g_geo_write_ptr = value;
        return;
    }
    if (offset == VIDEO_CTL_OFF) {
        model2_hw_video_ctl_write(value);
        return;
    }
    if (offset >= 0x10000000u && offset < 0x10200000u) {
        model2_hw_render_mode_write(value);
        return;
    }
    /* Geo command ports — encode opcode into PRG stream (MAME geo_w). */
    if (offset >= 0x00800000u && offset < 0x00801000u) {
        u32 address = offset - 0x00800000u;

        pthread_mutex_lock(&g_fifo_mtx);
        notify = geo_w_command_port(address, value);
        pthread_mutex_unlock(&g_fifo_mtx);
        upload_flush_pending();
        if (g_trace)
            fprintf(stderr, "geo: reg 0x%06x <= 0x%08x%s\n", offset, value,
                    notify ? " (prg cmd)" : "");
        if (notify && g_fifo_notify)
            g_fifo_notify();
        return;
    }
    /*
     * MAME geo_prg_w is mapped across the PRG port range. i960 stl/stq issue
     * successive bus writes at +4/+8/+C; every lane feeds the same FIFO.
     */
    if (offset >= GEO_PRG_FIFO_OFF && offset < GEO_PRG_FIFO_OFF + 0x4000u) {
        pthread_mutex_lock(&g_fifo_mtx);
        prg_push_locked(value);
        geo_capture_payload_locked(value);
        upload_feed_locked(value);
        pthread_mutex_unlock(&g_fifo_mtx);
        upload_flush_pending();
        notify = 1;
        if (g_trace)
            fprintf(stderr, "geo: prg_fifo 0x%08x\n", value);
        if (notify && g_fifo_notify)
            g_fifo_notify();
        return;
    }
    if (offset == COPRO_FIFO_OFF
        || (offset >= 0x00884000u && offset < 0x00888000u)) {
        pthread_mutex_lock(&g_fifo_mtx);
        model2_tgp_fifo_write(value);
        pthread_mutex_unlock(&g_fifo_mtx);
        notify = 1;
        if (g_trace)
            fprintf(stderr, "geo: copro_fifo 0x%08x\n", value);
        if (notify && g_fifo_notify)
            g_fifo_notify();
        return;
    }
}

int model2_hw_geo_projection(float focus_out[2], u32 window_out[6])
{
    int valid;

    pthread_mutex_lock(&g_fifo_mtx);
    valid = g_geo_projection_valid;
    if (focus_out) {
        focus_out[0] = g_geo_focus[0];
        focus_out[1] = g_geo_focus[1];
    }
    if (window_out)
        memcpy(window_out, g_geo_window, sizeof(g_geo_window));
    pthread_mutex_unlock(&g_fifo_mtx);
    return valid;
}

/*
 * Seed model2_geo_state from latched GEO cmds 0x06/0x07/0x0A (bootstrap).
 * Each out pointer may be NULL. Returns bitmask: 1=light, 2=mode, 4=texparams.
 */
int model2_hw_geo_shading(float light_out[3], int *mode_out, u32 tex_param_out[32],
                              float coef_out[32])
{
    int bits = 0;

    pthread_mutex_lock(&g_fifo_mtx);
    if (g_geo_light_valid) {
        if (light_out) {
            light_out[0] = g_geo_light[0];
            light_out[1] = g_geo_light[1];
            light_out[2] = g_geo_light[2];
        }
        bits |= 1;
    }
    if (g_geo_mode_valid) {
        if (mode_out)
            *mode_out = g_geo_mode;
        bits |= 2;
    }
    if (g_geo_tex_valid) {
        if (tex_param_out)
            memcpy(tex_param_out, g_geo_tex_param, sizeof(g_geo_tex_param));
        if (coef_out)
            memcpy(coef_out, g_geo_tex_coef, sizeof(g_geo_tex_coef));
        bits |= 4;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
    return bits;
}

unsigned model2_hw_prg_count(void)
{
    unsigned n;

    pthread_mutex_lock(&g_fifo_mtx);
    n = g_geo_prg_total;
    if (n > GEO_PRG_CAP)
        n = GEO_PRG_CAP;
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

unsigned model2_hw_prg_total(void)
{
    unsigned n;

    pthread_mutex_lock(&g_fifo_mtx);
    n = g_geo_prg_total;
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

const u32 *model2_hw_prg_words(unsigned *out_count)
{
    /* Ring buffer — prefer model2_hw_prg_copy for chronological order. */
    if (out_count)
        *out_count = model2_hw_prg_count();
    return g_geo_prg;
}

unsigned model2_hw_prg_copy(u32 *dst, unsigned dst_cap)
{
    unsigned n = 0;
    unsigned oldest;
    unsigned i;
    unsigned end_abs;

    if (!dst || !dst_cap)
        return 0;
    pthread_mutex_lock(&g_fifo_mtx);
    oldest = (g_geo_prg_total > GEO_PRG_CAP) ? (g_geo_prg_total - GEO_PRG_CAP) : 0u;
    end_abs = g_geo_prg_total;
    for (i = oldest; i < end_abs && n < dst_cap; i++)
        dst[n++] = g_geo_prg[i % GEO_PRG_CAP];
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

unsigned model2_hw_prg_display_gen(void)
{
    unsigned g;

    pthread_mutex_lock(&g_fifo_mtx);
    g = g_prg_display_gen;
    pthread_mutex_unlock(&g_fifo_mtx);
    return g;
}

void model2_hw_prg_display_range(unsigned *out_start, unsigned *out_end)
{
    pthread_mutex_lock(&g_fifo_mtx);
    if (out_start)
        *out_start = g_prg_display_start;
    if (out_end)
        *out_end = g_prg_display_end;
    pthread_mutex_unlock(&g_fifo_mtx);
}

/* Prefer densest frame for offline summary; falls back to latest display. */
void model2_hw_prg_best_range(unsigned *out_start, unsigned *out_end)
{
    pthread_mutex_lock(&g_fifo_mtx);
    if (g_prg_best_words > 0) {
        if (out_start)
            *out_start = g_prg_best_start;
        if (out_end)
            *out_end = g_prg_best_end;
    } else {
        if (out_start)
            *out_start = g_prg_display_start;
        if (out_end)
            *out_end = g_prg_display_end;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
}

void model2_hw_prg_publish_best(void)
{
    void (*notify)(void) = NULL;

    pthread_mutex_lock(&g_fifo_mtx);
    if (g_prg_best_words > 0
        && (g_prg_display_start != g_prg_best_start
            || g_prg_display_end != g_prg_best_end)) {
        g_prg_display_start = g_prg_best_start;
        g_prg_display_end = g_prg_best_end;
        g_prg_display_gen++;
        notify = g_fifo_notify;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
    if (notify)
        notify();
}

void model2_hw_latch_prg_frame(void)
{
    void (*notify)(void) = NULL;
    int latched = 0;

    pthread_mutex_lock(&g_fifo_mtx);
    /*
     * Only publish a new display range when the frame actually pushed prg
     * words. Empty vsyncs (common after attract settles) must not wipe the
     * last good carousel slice to [mark,mark).
     */
    if (g_geo_prg_total > g_prg_frame_mark) {
        unsigned words = g_geo_prg_total - g_prg_frame_mark;

        g_prg_display_start = g_prg_frame_mark;
        g_prg_display_end = g_geo_prg_total;
        g_prg_display_gen++;
        if (words > g_prg_best_words) {
            g_prg_best_start = g_prg_display_start;
            g_prg_best_end = g_prg_display_end;
            g_prg_best_words = words;
        }
        latched = 1;
    }
    g_prg_frame_mark = g_geo_prg_total;
    if (latched)
        notify = g_fifo_notify;
    pthread_mutex_unlock(&g_fifo_mtx);
    if (notify)
        notify();
}

unsigned model2_hw_prg_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                                     unsigned dst_cap)
{
    unsigned n = 0;
    unsigned oldest;
    unsigned i;

    if (!dst || !dst_cap || end_abs <= start_abs)
        return 0;
    pthread_mutex_lock(&g_fifo_mtx);
    oldest = (g_geo_prg_total > GEO_PRG_CAP) ? (g_geo_prg_total - GEO_PRG_CAP) : 0u;
    if (start_abs < oldest)
        start_abs = oldest;
    if (end_abs > g_geo_prg_total)
        end_abs = g_geo_prg_total;
    for (i = start_abs; i < end_abs && n < dst_cap; i++)
        dst[n++] = g_geo_prg[i % GEO_PRG_CAP];
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

unsigned model2_hw_prg_matrix_copy_range(unsigned start_abs, unsigned end_abs,
                                            float *dst, unsigned dst_cap_words)
{
    unsigned n = 0;
    unsigned oldest;
    unsigned i;

    if (!dst || !dst_cap_words || end_abs <= start_abs)
        return 0;
    pthread_mutex_lock(&g_fifo_mtx);
    oldest = (g_geo_prg_total > GEO_PRG_CAP) ? (g_geo_prg_total - GEO_PRG_CAP) : 0u;
    if (start_abs < oldest)
        start_abs = oldest;
    if (end_abs > g_geo_prg_total)
        end_abs = g_geo_prg_total;
    for (i = start_abs; i < end_abs && n < dst_cap_words; i++) {
        memcpy(dst + n * 12u, g_prg_mtx[i % GEO_PRG_CAP], 12u * sizeof(float));
        n++;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

unsigned model2_hw_prg_matrix_copy(float *dst, unsigned dst_cap_words)
{
    unsigned n = 0;
    unsigned oldest;
    unsigned i;
    unsigned end_abs;

    if (!dst || !dst_cap_words)
        return 0;
    pthread_mutex_lock(&g_fifo_mtx);
    oldest = (g_geo_prg_total > GEO_PRG_CAP) ? (g_geo_prg_total - GEO_PRG_CAP) : 0u;
    end_abs = g_geo_prg_total;
    for (i = oldest; i < end_abs && n < dst_cap_words; i++) {
        memcpy(dst + n * 12u, g_prg_mtx[i % GEO_PRG_CAP], 12u * sizeof(float));
        n++;
    }
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

void model2_hw_copro_matrix(float out[12])
{
    pthread_mutex_lock(&g_fifo_mtx);
    model2_tgp_matrix(out);
    pthread_mutex_unlock(&g_fifo_mtx);
}

int model2_hw_matrix_is_identity(void)
{
    int ok;

    pthread_mutex_lock(&g_fifo_mtx);
    ok = model2_tgp_matrix_is_identity();
    pthread_mutex_unlock(&g_fifo_mtx);
    return ok;
}

void model2_hw_latch_view_matrix(void)
{
    pthread_mutex_lock(&g_fifo_mtx);
    model2_tgp_latch_view_matrix();
    pthread_mutex_unlock(&g_fifo_mtx);
}

int model2_hw_restore_latched_view_matrix(void)
{
    int ok;

    pthread_mutex_lock(&g_fifo_mtx);
    ok = model2_tgp_restore_latched_view_matrix();
    pthread_mutex_unlock(&g_fifo_mtx);
    return ok;
}

int model2_hw_view_matrix(float out[12])
{
    int ok;

    pthread_mutex_lock(&g_fifo_mtx);
    ok = model2_tgp_view_matrix(out);
    pthread_mutex_unlock(&g_fifo_mtx);
    return ok;
}

int model2_hw_view_camera(float eye_out[3], float focus_out[3], float *pitch_seed,
                              float *seed_a, float *seed_b)
{
    int ok;

    pthread_mutex_lock(&g_fifo_mtx);
    ok = model2_tgp_view_camera(eye_out, focus_out, pitch_seed, seed_a, seed_b);
    pthread_mutex_unlock(&g_fifo_mtx);
    return ok;
}

unsigned model2_hw_copro_count(void)
{
    unsigned n;

    pthread_mutex_lock(&g_fifo_mtx);
    n = model2_tgp_count();
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

unsigned model2_hw_copro_total(void)
{
    unsigned n;

    pthread_mutex_lock(&g_fifo_mtx);
    n = model2_tgp_total();
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

const u32 *model2_hw_copro_words(unsigned *out_count)
{
    const u32 *p;

    pthread_mutex_lock(&g_fifo_mtx);
    p = model2_tgp_words(out_count);
    pthread_mutex_unlock(&g_fifo_mtx);
    return p;
}

unsigned model2_hw_copro_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                                       unsigned dst_cap)
{
    unsigned n;

    pthread_mutex_lock(&g_fifo_mtx);
    n = model2_tgp_copy_range(start_abs, end_abs, dst, dst_cap);
    pthread_mutex_unlock(&g_fifo_mtx);
    return n;
}

void model2_hw_dump(const char *path)
{
    FILE *fp;
    unsigned i;
    unsigned n;
    u32 *tmp;

    if (!path || !*path)
        return;
    n = model2_hw_prg_count();
    tmp = (u32 *)malloc(n * sizeof(u32));
    if (!tmp && n)
        return;
    n = model2_hw_prg_copy(tmp, n);
    fp = fopen(path, "wb");
    if (!fp) {
        free(tmp);
        return;
    }
    for (i = 0; i < n; i++)
        fwrite(&tmp[i], 4, 1, fp);
    fclose(fp);
    free(tmp);
    fprintf(stderr, "lift: wrote %u prg_fifo words to %s\n", n, path);
}

void model2_hw_dump_copro(const char *path)
{
    /* Debug dump: tgp has no internal lock; same race window as before. */
    model2_tgp_dump(path);
}
