/* Bridge lifted prg/copro FIFOs → mesh via C geo DL runner.
 *
 * Live path: a background worker scrapes/decodes FIFOs so the SDL present
 * thread only publishes/draws. Headless/summary still uses sync decode.
 */

#include "model2_geo_render.h"
#include "model2_geo_dl.h"
#include "model2_geo_tex.h"
#include "model2_polygon_rom.h"
#include "model2_texture_rom.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef I960_HOST_HAVE_GL
#if defined(__APPLE__)
#include <OpenGL/gl.h>
#else
#include <GL/gl.h>
#endif
#endif

enum { GEO_SCRATCH_WORDS = 8192u };

static model2_geo_fifo_ops_t g_fifo;
static int g_fifo_valid;

static model2_geo_dl_ctx_t g_ctx;
static model2_mesh_collector_t g_mesh;
static float *g_positions;
static unsigned g_n_positions;
static unsigned *g_indices;
static unsigned g_n_indices;
static unsigned g_tri_count;
static float *g_xyzuv;
static unsigned g_n_xyzuv_verts;
static model2_geo_tri_mat_t *g_tri_mats;
static unsigned g_n_tri_mats;
static int g_inited;
static int g_polygon_loaded;
static int g_logged_decode;
static unsigned g_accepted_frames;
static model2_geo_state_t g_geo_state;
static model2_geo_projection_t g_projection;

static unsigned s_last_prg_total;
static unsigned s_copro_scraped;
static unsigned s_prg_dl_at_total;
static unsigned s_last_display_gen;
static int s_have_prg_mesh;

static pthread_t g_worker;
static pthread_mutex_t g_worker_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_worker_cond = PTHREAD_COND_INITIALIZER;
static int g_worker_started;
static int g_worker_stop;
static int g_worker_kick;
static unsigned g_worker_gen;
static unsigned g_done_gen;

static pthread_mutex_t g_pub_mtx = PTHREAD_MUTEX_INITIALIZER;
/* Guards g_ctx polygon/texture RAM vs decode worker + texture_sync uploads. */
static pthread_mutex_t g_geo_ram_mtx = PTHREAD_MUTEX_INITIALIZER;

static u32 hash_bytes(u32 h, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static int signed12(u32 v)
{
    v &= 0xfffu;
    return (v & 0x800u) ? (int)v - 0x1000 : (int)v;
}

static void publish_projection_state(const model2_geo_state_t *geo)
{
    model2_geo_projection_t p;

    memset(&p, 0, sizeof(p));
    p.focal_x = geo->focus.x;
    p.focal_y = geo->focus.y;
    if (geo->window_valid) {
        /* MAME geo_window_data → raster command 03 unpacking (eye0 for GL). */
        p.viewport[0] = signed12(geo->window[0] >> 16);
        p.viewport[1] = signed12(geo->window[0]);
        p.viewport[2] = signed12(geo->window[1] >> 16);
        p.viewport[3] = signed12(geo->window[1]);
        p.center[0] = signed12(geo->window[2] >> 16);
        p.center[1] = signed12(geo->window[2]);
        p.valid = p.focal_x > 0.f && p.focal_y > 0.f
               && p.viewport[2] > p.viewport[0]
               && p.viewport[3] > p.viewport[1];
    }
    pthread_mutex_lock(&g_pub_mtx);
    /*
     * MAME persists GEO window/focus across the stream — last 0x03/0x09 wins.
     * Per-object eye centers (center_sel) are baked into verts at object_data
     * (model2_geo_bake_center_sel), not by inventing a second GL camera.
     */
    g_projection = p;
    pthread_mutex_unlock(&g_pub_mtx);
}

static int prim_z_ok(const model2_mesh_prim_t *p, float *zmax_out)
{
    float zmax = -1e30f;
    int k;

    for (k = 0; k < p->n_indices; k++) {
        int vi = p->indices[k];
        float z;
        if (vi < 0 || (unsigned)vi >= g_mesh.n_verts)
            return 0;
        z = g_mesh.verts[vi].z;
        if (z > zmax)
            zmax = z;
    }
    if (zmax_out)
        *zmax_out = zmax;
    return zmax > 0.f;
}

static void emit_tex_corner(float *dst, unsigned *vo, const model2_mesh_prim_t *p,
                            int corner)
{
    int vi = p->indices[corner];
    unsigned o = (*vo) * 5u;

    dst[o + 0u] = g_mesh.verts[vi].x;
    dst[o + 1u] = g_mesh.verts[vi].y;
    dst[o + 2u] = g_mesh.verts[vi].z;
    dst[o + 3u] = p->tex_valid ? p->u[corner] : 0.f;
    dst[o + 4u] = p->tex_valid ? p->v[corner] : 0.f;
    (*vo)++;
}

static float prim_vert_z_min(const model2_mesh_prim_t *p)
{
    float z = g_mesh.verts[p->indices[0]].z;
    int k;

    for (k = 1; k < p->n_indices; k++) {
        float zk = g_mesh.verts[p->indices[k]].z;
        if (zk < z)
            z = zk;
    }
    return z;
}

static float prim_vert_z_max(const model2_mesh_prim_t *p)
{
    float z = g_mesh.verts[p->indices[0]].z;
    int k;

    for (k = 1; k < p->n_indices; k++) {
        float zk = g_mesh.verts[p->indices[k]].z;
        if (zk > z)
            z = zk;
    }
    return z;
}

/* MAME model2_3d_process_polygon: attr[11:10] selects sort float; always updates polygon_z. */
static float mame_polygon_z_value(const model2_mesh_prim_t *p, float *polygon_z)
{
    float min_z = prim_vert_z_min(p);
    float max_z = prim_vert_z_max(p);
    float zvalue;

    switch ((p->attr >> 10) & 3u) {
    case 0:
        zvalue = *polygon_z;
        break;
    case 1:
        zvalue = min_z;
        break;
    case 2:
        zvalue = max_z;
        break;
    default:
        zvalue = 1e10f;
        break;
    }
    *polygon_z = zvalue;
    return zvalue;
}

/*
 * Emit every exportable prim (both sides). Cutout front-only cull hid the
 * upper desert sky band (black above clouds) when host n·p marked those
 * sheets back. Opaque both-sides still needed for rocker/cabin until n·p
 * matches hardware.
 */
static int prim_should_emit(const model2_mesh_prim_t *p)
{
    return model2_mame_polygon_exportable(p->attr);
}

static void emit_tri_mat(model2_geo_tri_mat_t *mats, unsigned *ti,
                         const model2_mesh_prim_t *p, float z_sort)
{
    model2_geo_tri_mat_t *m = &mats[*ti];
    m->colorbase = p->tex_valid ? p->colorbase : 0;
    m->lumabase = p->tex_valid ? p->lumabase : 0;
    m->patch_x = p->tex_valid ? p->patch_x : 0;
    m->patch_y = p->tex_valid ? p->patch_y : 0;
    m->patch_w = p->tex_valid ? p->patch_w : 32;
    m->patch_h = p->tex_valid ? p->patch_h : 32;
    m->sheet = p->tex_valid ? p->sheet : 0;
    m->flags = p->tex_valid ? p->tex_flags : 0;
    m->luma = p->tex_valid ? p->poly_luma : 255;
    /* pad: bit0 = HUD overlay, bit1 = MAME front (n·p >= 0). */
    m->pad = (u8)((p->hud_overlay ? 1u : 0u) | (p->front ? 2u : 0u));
    m->z_sort = z_sort;
    (*ti)++;
}

static void rebuild_gl_buffers(void)
{
    unsigned i, t;
    unsigned n_idx = 0;
    unsigned n_tex_tris = 0;
    float *new_pos = NULL;
    unsigned *new_idx = NULL;
    float *new_xyzuv = NULL;
    model2_geo_tri_mat_t *new_mats = NULL;
    unsigned new_npos = 0;
    unsigned new_nidx = 0;
    unsigned new_tris = 0;
    unsigned new_xyzuv_verts = 0;
    unsigned new_n_mats = 0;

    if (g_mesh.n_verts == 0) {
        pthread_mutex_lock(&g_pub_mtx);
        free(g_positions);
        free(g_indices);
        free(g_xyzuv);
        free(g_tri_mats);
        g_positions = NULL;
        g_indices = NULL;
        g_xyzuv = NULL;
        g_tri_mats = NULL;
        g_n_positions = 0;
        g_n_indices = 0;
        g_tri_count = 0;
        g_n_xyzuv_verts = 0;
        g_n_tri_mats = 0;
        pthread_mutex_unlock(&g_pub_mtx);
        return;
    }

    new_npos = g_mesh.n_verts * 3u;
    new_pos = (float *)malloc(new_npos * sizeof(float));
    if (!new_pos)
        return;
    for (i = 0; i < g_mesh.n_verts; i++) {
        new_pos[i * 3u + 0u] = g_mesh.verts[i].x;
        new_pos[i * 3u + 1u] = g_mesh.verts[i].y;
        new_pos[i * 3u + 2u] = g_mesh.verts[i].z;
    }

    /*
     * Emit every exportable prim (both sides). MAME check_culling uses hardware
     * front after transform; host n·p still drops rockers until that matches.
     * Coplanar occlusion is fillmap in the GL path, not a second cull here.
     */
    for (i = 0; i < g_mesh.n_prims; i++) {
        const model2_mesh_prim_t *p = &g_mesh.prims[i];

        if (!prim_should_emit(p))
            continue;
        if (p->n_indices == 3) {
            n_idx += 3u;
            n_tex_tris += 1u;
        } else if (p->n_indices == 4) {
            n_idx += 6u;
            n_tex_tris += 2u;
        }
    }
    if (n_idx > 0) {
        new_idx = (unsigned *)malloc(n_idx * sizeof(unsigned));
        new_xyzuv = (float *)malloc(n_tex_tris * 3u * 5u * sizeof(float));
        new_mats = (model2_geo_tri_mat_t *)malloc(n_tex_tris * sizeof(*new_mats));
        if (new_idx && new_xyzuv && new_mats) {
            unsigned vo = 0;
            unsigned ti = 0;
            /* MAME render_frame_start: polygon_z = 1e10 before the frame. */
            float polygon_z = 1e10f;
            t = 0;
            for (i = 0; i < g_mesh.n_prims; i++) {
                const model2_mesh_prim_t *p = &g_mesh.prims[i];
                int i0, i1, i2, i3;
                float z_sort;

                /*
                 * Always advance polygon_z (MAME updates even when culled),
                 * then skip non-visible prims for emit.
                 */
                z_sort = mame_polygon_z_value(p, &polygon_z);
                if (!prim_should_emit(p))
                    continue;
                if (!prim_z_ok(p, NULL))
                    continue;
                if (p->n_indices == 3) {
                    i0 = p->indices[0];
                    i1 = p->indices[1];
                    i2 = p->indices[2];
                    new_idx[t++] = (unsigned)i0;
                    new_idx[t++] = (unsigned)i1;
                    new_idx[t++] = (unsigned)i2;
                    emit_tex_corner(new_xyzuv, &vo, p, 0);
                    emit_tex_corner(new_xyzuv, &vo, p, 1);
                    emit_tex_corner(new_xyzuv, &vo, p, 2);
                    emit_tri_mat(new_mats, &ti, p, z_sort);
                    new_tris++;
                } else if (p->n_indices == 4) {
                    i0 = p->indices[0];
                    i1 = p->indices[1];
                    i2 = p->indices[2];
                    i3 = p->indices[3];
                    new_idx[t++] = (unsigned)i0;
                    new_idx[t++] = (unsigned)i1;
                    new_idx[t++] = (unsigned)i2;
                    new_idx[t++] = (unsigned)i0;
                    new_idx[t++] = (unsigned)i2;
                    new_idx[t++] = (unsigned)i3;
                    emit_tex_corner(new_xyzuv, &vo, p, 0);
                    emit_tex_corner(new_xyzuv, &vo, p, 1);
                    emit_tex_corner(new_xyzuv, &vo, p, 2);
                    emit_tri_mat(new_mats, &ti, p, z_sort);
                    emit_tex_corner(new_xyzuv, &vo, p, 0);
                    emit_tex_corner(new_xyzuv, &vo, p, 2);
                    emit_tex_corner(new_xyzuv, &vo, p, 3);
                    emit_tri_mat(new_mats, &ti, p, z_sort);
                    new_tris += 2u;
                }
            }
            new_nidx = t;
            new_xyzuv_verts = vo;
            new_n_mats = ti;
        } else {
            free(new_idx);
            free(new_xyzuv);
            free(new_mats);
            new_idx = NULL;
            new_xyzuv = NULL;
            new_mats = NULL;
        }
    }

    pthread_mutex_lock(&g_pub_mtx);
    free(g_positions);
    free(g_indices);
    free(g_xyzuv);
    free(g_tri_mats);
    g_positions = new_pos;
    g_indices = new_idx;
    g_xyzuv = new_xyzuv;
    g_tri_mats = new_mats;
    g_n_positions = new_npos;
    g_n_indices = new_nidx;
    g_tri_count = new_tris;
    g_n_xyzuv_verts = new_xyzuv_verts;
    g_n_tri_mats = new_n_mats;
    pthread_mutex_unlock(&g_pub_mtx);
}

static int scrape_point_ok(float x, float y, float z)
{
    if (!isfinite(x) || !isfinite(y) || !isfinite(z))
        return 0;
    if (fabsf(x) > 25000.f || fabsf(y) > 25000.f || fabsf(z) > 25000.f)
        return 0;
    if (fabsf(x) + fabsf(y) + fabsf(z) < 1e-4f)
        return 0;
    return 1;
}

static void append_mesh_filtered(model2_mesh_collector_t *dst,
                                 const model2_mesh_collector_t *src)
{
    unsigned i;
    int *map;

    if (src->n_verts == 0)
        return;
    map = (int *)malloc(src->n_verts * sizeof(int));
    if (!map)
        return;
    for (i = 0; i < src->n_verts; i++) {
        float x = src->verts[i].x, y = src->verts[i].y, z = src->verts[i].z;
        /*
         * PRG vertices are already focal-scaled camera coordinates. Large
         * off-frustum x/y are valid and must reach hardware-style clipping.
         */
        if (!isfinite(x) || !isfinite(y) || !isfinite(z)) {
            map[i] = -1;
            continue;
        }
        map[i] = model2_mesh_collector_add_vertex(dst, x, y, z);
    }
    for (i = 0; i < src->n_prims; i++) {
        const model2_mesh_prim_t *p = &src->prims[i];
        int idx[MODEL2_MESH_MAX_INDICES];
        int j, ok = 1;
        for (j = 0; j < p->n_indices; j++) {
            int vi = p->indices[j];
            if (vi < 0 || (unsigned)vi >= src->n_verts || map[vi] < 0) {
                ok = 0;
                break;
            }
            idx[j] = map[vi];
        }
        if (ok) {
            unsigned di = dst->n_prims;
            model2_mesh_collector_add_prim(dst, p->attr, idx, p->n_indices, p->nx,
                                           p->ny, p->nz, p->front, p->poly_luma);
            if (dst->n_prims > di)
                model2_mesh_prim_copy_tex(&dst->prims[di], p);
        }
    }
    free(map);
}

/*
 * Attract geo_script_finish / glyph_emit: opcode 0x13802727 then three IEEE floats.
 */
static void scrape_copro_points_words(const u32 *words, unsigned n)
{
    unsigned i;

    for (i = 0; i + 3u < n; i++) {
        float x, y, z;
        if (words[i] != 0x13802727u)
            continue;
        x = model2_u2f(words[i + 1u]);
        y = model2_u2f(words[i + 2u]);
        z = model2_u2f(words[i + 3u]);
        if (scrape_point_ok(x, y, z))
            model2_mesh_collector_add_vertex(&g_mesh, x, y, z);
    }
}

static void ensure_polygon_rom(void)
{
    unsigned n_poly = 0;
    const u32 *poly;

    if (g_polygon_loaded)
        return;
    if (model2_polygon_rom_load_default() != 0)
        fprintf(stderr, "lift: geo render: continuing without polygon ROM\n");
    poly = model2_polygon_rom_words(&n_poly);
    if (poly && n_poly)
        model2_geo_dl_ctx_set_rom(&g_ctx, poly, n_poly);
    if (model2_texture_rom_load_default() != 0)
        fprintf(stderr, "lift: geo render: continuing without textures ROM\n");
    g_polygon_loaded = 1;
}

/*
 * MAME geo_parse-style walk: one geo_state (focus/mode/light) across the frame.
 * Object poses come from per-word TGP snapshots. Falls back to per-object scan
 * only if the sequential run draws nothing (legacy rings without geo_w opcodes).
 */
static int decode_prg_stream(const u32 *prg_buf, unsigned prg_n, const float *prg_mtx,
                             unsigned mtx_n, model2_geo_state_t *state,
                             model2_mesh_collector_t *prg_mesh, unsigned *objects_ok)
{
    model2_geo_dl_result_t result;
    int ok = 0;
    static unsigned soft_error_logs;

    model2_geo_dl_result_init(&result);
    if (model2_geo_dl_run_stream_state(&g_ctx, prg_buf, prg_n, prg_mtx, mtx_n,
                                       state, &result) == 0
        && result.objects_drawn > 0 && result.mesh.n_verts > 0) {
        append_mesh_filtered(prg_mesh, &result.mesh);
        *objects_ok += (unsigned)result.objects_drawn;
        ok = 1;
    }
    if (result.error[0] && soft_error_logs < 8u) {
        fprintf(stderr,
                "lift: geo stream stopped word=%d ops=%u objects=%d: %s\n",
                result.words_consumed, result.commands_executed,
                result.objects_drawn, result.error);
        soft_error_logs++;
    }
    model2_geo_dl_result_free(&result);
    if (ok)
        return 1;

    /* Legacy: scan packed pens / bare catalog quads (pre-geo_w host). */
    {
        int start;
        int object_tries = 0;

        for (start = 0; start < (int)prg_n && object_tries < 8192; start++) {
            u32 op = prg_buf[start];
            const float *mtx = NULL;
            u32 catalog_words[5];
            int got = 0;

            if ((unsigned)start < mtx_n)
                mtx = &prg_mtx[(unsigned)start * 12u];

            if ((op & 0xFFFF00u) == 0x800100u) {
                object_tries++;
                model2_geo_dl_result_init(&result);
                got = model2_geo_dl_run_mtx(&g_ctx, prg_buf, prg_n, start, 0, 1u, mtx,
                                            &result) == 0
                      && result.objects_drawn > 0 && result.mesh.n_verts > 0;
                if (got) {
                    append_mesh_filtered(prg_mesh, &result.mesh);
                    *objects_ok += (unsigned)result.objects_drawn;
                    ok = 1;
                }
                model2_geo_dl_result_free(&result);
                continue;
            }

            if (start + 3 < (int)prg_n
                && model2_is_polygon_rom_oba(prg_buf[start + 2])
                && ((op >> 23) & 0x1fu) == 0u) {
                object_tries++;
                catalog_words[0] = 0x00800000u;
                catalog_words[1] = prg_buf[start];
                catalog_words[2] = prg_buf[start + 1];
                catalog_words[3] = prg_buf[start + 2];
                catalog_words[4] = prg_buf[start + 3];
                model2_geo_dl_result_init(&result);
                got = model2_geo_dl_run_mtx(&g_ctx, catalog_words, 5, 0, 0, 1u, mtx,
                                            &result) == 0
                      && result.objects_drawn > 0 && result.mesh.n_verts > 0;
                if (got) {
                    append_mesh_filtered(prg_mesh, &result.mesh);
                    *objects_ok += (unsigned)result.objects_drawn;
                    ok = 1;
                    start += 3;
                }
                model2_geo_dl_result_free(&result);
            }
        }
    }
    return ok;
}

static int decode_fifos_locked(void)
{
    unsigned prg_n = 0;
    unsigned prg_total = 0;
    unsigned copro_total = 0;
    static u32 prg_buf[262144];
    static float prg_mtx[262144 * 12];
    u32 copro_buf[GEO_SCRATCH_WORDS];
    int best_verts = 0;
    int decoded = 0;
    unsigned mtx_n = 0;
    unsigned disp_start = 0, disp_end = 0, disp_gen = 0;
    int use_frame_slice = 0;
    int mesh_changed = 0;
    const char *prg_dl_env;
    int want_prg_dl;
    float focus_xy[2] = {1.f, 1.f};
    unsigned before;

    prg_total = (g_fifo_valid && g_fifo.prg_total) ? g_fifo.prg_total() : 0u;
    copro_total = (g_fifo_valid && g_fifo.copro_total) ? g_fifo.copro_total() : 0u;
    disp_gen = (g_fifo_valid && g_fifo.display_gen) ? g_fifo.display_gen() : 0u;
    if (g_fifo_valid && g_fifo.display_range)
        g_fifo.display_range(&disp_start, &disp_end);

    if (prg_total == s_last_prg_total && copro_total == s_copro_scraped
        && disp_gen == s_last_display_gen)
        return (int)g_mesh.n_verts;

    /* Default on — attract/boot viewer always needs PRG decode. Opt out with =0. */
    prg_dl_env = getenv("I960_GEO_PRG_DECODE");
    want_prg_dl = !(prg_dl_env && prg_dl_env[0] == '0');

    /*
     * Prefer the last completed vsync frame's prg words (latched in
     * geo_vsync_wait → latch_prg_frame). Until the first non-empty latch,
     * fall back to the retained ring.
     */
    if (disp_end > disp_start && g_fifo_valid && g_fifo.copy_prg_range) {
        prg_n = g_fifo.copy_prg_range(disp_start, disp_end, prg_buf, 262144u);
        mtx_n = g_fifo.copy_mtx_range
                    ? g_fifo.copy_mtx_range(disp_start, disp_end, prg_mtx, 262144u)
                    : 0u;
        use_frame_slice = 1;
    } else if (disp_gen == 0 && g_fifo_valid && g_fifo.copy_prg) {
        prg_n = g_fifo.copy_prg(prg_buf, 262144u);
        mtx_n = g_fifo.copy_mtx ? g_fifo.copy_mtx(prg_mtx, 262144u) : 0u;
    } else {
        /* Prior latch exists but this vsync was empty — keep published mesh. */
        s_last_prg_total = prg_total;
        s_last_display_gen = disp_gen;
        s_copro_scraped = copro_total;
        return (int)g_mesh.n_verts;
    }
    if (mtx_n > prg_n)
        mtx_n = prg_n;

    if (want_prg_dl && prg_n > 4
        && (use_frame_slice ? disp_gen != s_last_display_gen
                            : prg_total != s_prg_dl_at_total)) {
        model2_mesh_collector_t prg_mesh;
        unsigned objects_ok = 0;
        float hw_focus[2];
        u32 hw_window[6];

        ensure_polygon_rom();
        model2_mesh_collector_init(&prg_mesh);
        /*
         * Bootstrap commands precede the first displayed frame. MAME GEO state
         * persists, so seed the frame interpreter from command-boundary state
         * captured by the emulated geo_w hardware (03/09 focus+window;
         * 06/07/0A texture_parameters + mode + light from geo_fifo_bootstrap).
         */
        if (g_fifo_valid && g_fifo.projection
            && g_fifo.projection(hw_focus, hw_window)) {
            g_geo_state.focus.x = hw_focus[0];
            g_geo_state.focus.y = hw_focus[1];
            memcpy(g_geo_state.window, hw_window, sizeof(g_geo_state.window));
            g_geo_state.window_valid = 1;
            publish_projection_state(&g_geo_state);
        }
        if (g_fifo_valid && g_fifo.shading) {
            float hw_light[3];
            int hw_mode = 0;
            u32 hw_tex[32];
            float hw_coef[32];
            int shade = g_fifo.shading(hw_light, &hw_mode, hw_tex, hw_coef);

            if (shade & 1) {
                g_geo_state.light.x = hw_light[0];
                g_geo_state.light.y = hw_light[1];
                g_geo_state.light.z = hw_light[2];
            }
            if (shade & 2)
                g_geo_state.mode = hw_mode;
            if (shade & 4) {
                unsigned ti;

                for (ti = 0; ti < 32u; ti++) {
                    u32 p = hw_tex[ti];

                    g_geo_state.texture_parameters[ti].diffuse = (float)(p & 0xffu);
                    g_geo_state.texture_parameters[ti].ambient =
                        (float)((p >> 8) & 0xffu);
                    g_geo_state.texture_parameters[ti].specular_scale =
                        (float)((p >> 16) & 0xffu);
                    g_geo_state.texture_parameters[ti].specular_control =
                        (int)((p >> 24) & 0xffu);
                    g_geo_state.coef_table[ti] = hw_coef[ti];
                }
            }
        }

        /*
         * Primary: MAME geo_parse walk (geo_w object opcodes + persistent focus).
         * Fallback inside decode_prg_stream for rings built before geo_w.
         */
        model2_geo_state_t frame_state;

        model2_geo_state_copy(&frame_state, &g_geo_state);
        pthread_mutex_lock(&g_geo_ram_mtx);
        decoded = decode_prg_stream(prg_buf, prg_n, prg_mtx, mtx_n, &frame_state,
                                    &prg_mesh, &objects_ok);
        pthread_mutex_unlock(&g_geo_ram_mtx);
        /* MAME geo_state persists across geo_parse calls / completed frames. */
        model2_geo_state_copy(&g_geo_state, &frame_state);
        focus_xy[0] = g_geo_state.focus.x;
        focus_xy[1] = g_geo_state.focus.y;
        publish_projection_state(&g_geo_state);

        best_verts = (int)prg_mesh.n_verts;

        /*
         * Always publish this vsync's latch. No thin-hold / denser-keep /
         * best-range — those caused close-geometry pop on shots 14/16/18 while
         * chasing desert remote flash. Empty latches keep the last mesh above.
         */
        if (decoded && prg_mesh.n_verts > 0) {
            u32 matrix_sig =
                hash_bytes(2166136261u, prg_mtx,
                           (size_t)mtx_n * 12u * sizeof(float));
            u32 mesh_sig =
                hash_bytes(2166136261u, prg_mesh.verts,
                           (size_t)prg_mesh.n_verts * sizeof(*prg_mesh.verts));

            model2_mesh_collector_reset(&g_mesh);
            model2_mesh_collector_append(&g_mesh, &prg_mesh);
            s_copro_scraped = copro_total;
            s_have_prg_mesh = 1;
            mesh_changed = 1;
            g_accepted_frames++;
            if (!g_logged_decode || g_logged_decode < 12
                || (g_accepted_frames % 30u) == 0u) {
                unsigned mi, non_ident = 0;
                unsigned exp_tris = 0;
                float zmin = 0.f, zmax = 0.f;
                float xmin = 0.f, xmax = 0.f;

                for (mi = 0; mi < mtx_n; mi++) {
                    const float *m = &prg_mtx[mi * 12u];

                    if (m[0] != 1.f || m[4] != 1.f || m[8] != 1.f
                        || m[1] != 0.f || m[2] != 0.f || m[3] != 0.f
                        || m[5] != 0.f || m[6] != 0.f || m[7] != 0.f
                        || m[9] != 0.f || m[10] != 0.f || m[11] != 0.f)
                        non_ident++;
                }
                if (prg_mesh.n_verts > 0) {
                    zmin = zmax = prg_mesh.verts[0].z;
                    xmin = xmax = prg_mesh.verts[0].x;
                    for (mi = 1; mi < prg_mesh.n_verts; mi++) {
                        if (prg_mesh.verts[mi].z < zmin)
                            zmin = prg_mesh.verts[mi].z;
                        if (prg_mesh.verts[mi].z > zmax)
                            zmax = prg_mesh.verts[mi].z;
                        if (prg_mesh.verts[mi].x < xmin)
                            xmin = prg_mesh.verts[mi].x;
                        if (prg_mesh.verts[mi].x > xmax)
                            xmax = prg_mesh.verts[mi].x;
                    }
                }
                for (mi = 0; mi < prg_mesh.n_prims; mi++) {
                    const model2_mesh_prim_t *p = &prg_mesh.prims[mi];
                    float z0, z1, z2, z3, pzmax;
                    int i0, i1, i2, i3;

                    if (!model2_mame_polygon_exportable(p->attr))
                        continue;
                    if (p->n_indices == 3) {
                        i0 = p->indices[0];
                        i1 = p->indices[1];
                        i2 = p->indices[2];
                        if (i0 < 0 || i1 < 0 || i2 < 0)
                            continue;
                        z0 = prg_mesh.verts[i0].z;
                        z1 = prg_mesh.verts[i1].z;
                        z2 = prg_mesh.verts[i2].z;
                        pzmax = z0;
                        if (z1 > pzmax)
                            pzmax = z1;
                        if (z2 > pzmax)
                            pzmax = z2;
                        if (pzmax > 0.f)
                            exp_tris += 1u;
                    } else if (p->n_indices == 4) {
                        i0 = p->indices[0];
                        i1 = p->indices[1];
                        i2 = p->indices[2];
                        i3 = p->indices[3];
                        if (i0 < 0 || i1 < 0 || i2 < 0 || i3 < 0)
                            continue;
                        z0 = prg_mesh.verts[i0].z;
                        z1 = prg_mesh.verts[i1].z;
                        z2 = prg_mesh.verts[i2].z;
                        z3 = prg_mesh.verts[i3].z;
                        pzmax = z0;
                        if (z1 > pzmax)
                            pzmax = z1;
                        if (z2 > pzmax)
                            pzmax = z2;
                        if (z3 > pzmax)
                            pzmax = z3;
                        if (pzmax > 0.f)
                            exp_tris += 2u;
                    }
                }
                /*
                 * Screen-third histogram of exportable verts (sx≈248+x/z).
                 * Car-select catalogs bake cx≈−10/0/+10 → expect L/C/R thirds
                 * populated; a center-only pile means composite/coverage, not
                 * missing panel X.
                 */
                {
                    unsigned bin[3] = {0, 0, 0};
                    unsigned mi2;

                    for (mi2 = 0; mi2 < prg_mesh.n_prims; mi2++) {
                        const model2_mesh_prim_t *p = &prg_mesh.prims[mi2];
                        int k;

                        if (!model2_mame_polygon_exportable(p->attr))
                            continue;
                        for (k = 0; k < p->n_indices; k++) {
                            int vi = p->indices[k];
                            float sx, z;

                            if (vi < 0 || (unsigned)vi >= prg_mesh.n_verts)
                                continue;
                            z = prg_mesh.verts[vi].z;
                            if (z <= 1e-4f)
                                continue;
                            sx = 248.f + prg_mesh.verts[vi].x / z;
                            if (sx < 496.f / 3.f)
                                bin[0]++;
                            else if (sx < 2.f * 496.f / 3.f)
                                bin[1]++;
                            else
                                bin[2]++;
                        }
                    }
                    fprintf(stderr,
                            "lift: geo prg-dl objects=%u verts=%u prims=%u "
                            "tris=%u words=%u mtx_nonident=%u/%u "
                            "focus=(%.3g,%.3g) x=(%.3g,%.3g) z=(%.3g,%.3g) "
                            "sx_thirds=%u/%u/%u sig=%08x/%08x%s\n",
                            objects_ok, prg_mesh.n_verts, prg_mesh.n_prims,
                            exp_tris, prg_n, non_ident, mtx_n,
                            focus_xy[0], focus_xy[1],
                            xmin, xmax, zmin, zmax,
                            bin[0], bin[1], bin[2],
                            matrix_sig, mesh_sig,
                            use_frame_slice ? " (frame slice)" : "");
                }
            }
            g_logged_decode++;
        }
        model2_mesh_collector_free(&prg_mesh);
        if (use_frame_slice)
            s_last_display_gen = disp_gen;
        else
            s_prg_dl_at_total = prg_total;
        (void)best_verts;
    }

    s_last_prg_total = prg_total;
    s_last_display_gen = disp_gen;

    if (s_have_prg_mesh || want_prg_dl) {
        /*
         * With prg DL enabled, never fall back to copro point scrape — a miss
         * on one frame must not block the worker on multi-million-word scrapes
         * and starve later carousel latches.
         */
        s_copro_scraped = copro_total;
    } else if (!decoded && copro_total > s_copro_scraped) {
        /* Copro point scrape is a last-resort overlay when no catalog/pen DL mesh. */
        unsigned cstart = s_copro_scraped;
        unsigned oldest;
        unsigned got;

        /* If the ring overwrote unread words, jump to the oldest retained. */
        oldest = (copro_total > GEO_SCRATCH_WORDS) ? (copro_total - GEO_SCRATCH_WORDS) : 0u;
        if (cstart < oldest)
            cstart = oldest;

        before = g_mesh.n_verts;
        while (cstart < copro_total) {
            unsigned chunk_end = cstart + GEO_SCRATCH_WORDS;
            if (chunk_end > copro_total)
                chunk_end = copro_total;
            got = (g_fifo_valid && g_fifo.copy_copro_range)
                      ? g_fifo.copy_copro_range(cstart, chunk_end, copro_buf,
                                               GEO_SCRATCH_WORDS)
                      : 0u;
            if (got == 0)
                break;
            scrape_copro_points_words(copro_buf, got);
            cstart += got;
        }
        s_copro_scraped = copro_total;
        if (g_mesh.n_verts != before)
            mesh_changed = 1;
    }

    if (mesh_changed)
        rebuild_gl_buffers();

    if (!g_logged_decode || (g_mesh.n_verts > 0 && g_logged_decode < 8)) {
        fprintf(stderr,
                "lift: geo decode prg=%u copro=%u verts=%u tris=%u objects_dl=%d\n",
                prg_n, copro_total, g_mesh.n_verts, g_tri_count, decoded);
        g_logged_decode++;
    }
    return (int)g_mesh.n_verts;
}

static void *geo_worker_main(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_worker_mtx);
    while (!g_worker_stop) {
        while (!g_worker_kick && !g_worker_stop)
            pthread_cond_wait(&g_worker_cond, &g_worker_mtx);
        if (g_worker_stop)
            break;
        g_worker_kick = 0;
        pthread_mutex_unlock(&g_worker_mtx);

        decode_fifos_locked();

        pthread_mutex_lock(&g_worker_mtx);
        g_done_gen = g_worker_gen;
        pthread_cond_broadcast(&g_worker_cond);
    }
    pthread_mutex_unlock(&g_worker_mtx);
    return NULL;
}

static void geo_fifo_notify(void)
{
    model2_geo_render_kick();
}

void model2_geo_render_bind_fifo(const model2_geo_fifo_ops_t *fifo)
{
    if (fifo) {
        g_fifo = *fifo;
        g_fifo_valid = 1;
    } else {
        memset(&g_fifo, 0, sizeof(g_fifo));
        g_fifo_valid = 0;
    }
    /* Uploads may init the worker before ops are bound — attach notify now. */
    if (g_worker_started && g_fifo_valid && g_fifo.set_notify)
        g_fifo.set_notify(geo_fifo_notify);
}

void model2_geo_render_kick(void)
{
    if (!g_inited)
        model2_geo_render_init();
    if (!g_worker_started)
        return;
    pthread_mutex_lock(&g_worker_mtx);
    g_worker_gen++;
    g_worker_kick = 1;
    pthread_cond_signal(&g_worker_cond);
    pthread_mutex_unlock(&g_worker_mtx);
}

int model2_geo_render_init(void)
{
    if (g_inited)
        return 0;

    model2_geo_dl_ctx_init(&g_ctx);
    model2_mesh_collector_init(&g_mesh);
    model2_geo_state_init(&g_geo_state);
    memset(&g_projection, 0, sizeof(g_projection));
    s_last_prg_total = 0;
    s_copro_scraped = 0;
    s_prg_dl_at_total = 0;
    s_last_display_gen = 0;
    s_have_prg_mesh = 0;
    g_accepted_frames = 0;
    g_inited = 1;

    g_worker_stop = 0;
    g_worker_kick = 0;
    g_worker_gen = 0;
    g_done_gen = 0;
    if (pthread_create(&g_worker, NULL, geo_worker_main, NULL) == 0) {
        g_worker_started = 1;
        if (g_fifo_valid && g_fifo.set_notify)
            g_fifo.set_notify(geo_fifo_notify);
        fprintf(stderr, "lift: geo decode worker thread started\n");
    } else {
        g_worker_started = 0;
        fprintf(stderr, "lift: geo decode worker thread create failed — sync decode\n");
    }
    return 0;
}

void model2_geo_render_texture_data(u32 address, u32 count, const u32 *data)
{
    if (!g_inited)
        model2_geo_render_init();
    pthread_mutex_lock(&g_geo_ram_mtx);
    model2_geo_dl_texture_data(&g_ctx, address, count, data);
    pthread_mutex_unlock(&g_geo_ram_mtx);
}

void model2_geo_render_polygon_data(u32 address, u32 count, const u32 *data)
{
    static unsigned s_poly_uploads;
    static unsigned s_poly_words;

    if (!g_inited)
        model2_geo_render_init();
    pthread_mutex_lock(&g_geo_ram_mtx);
    model2_geo_dl_polygon_data(&g_ctx, address, count, data);
    pthread_mutex_unlock(&g_geo_ram_mtx);
    s_poly_uploads++;
    s_poly_words += count;
    if (s_poly_uploads <= 3u || (s_poly_uploads % 17u) == 0u) {
        u32 sample = 0;

        pthread_mutex_lock(&g_geo_ram_mtx);
        if (g_ctx.polygon_ram0 && count > 0u) {
            u32 addr = address & 0x7FFFu;

            if (!(address & 0x01000000u) && addr < 0x8000u)
                sample = g_ctx.polygon_ram0[addr];
        }
        pthread_mutex_unlock(&g_geo_ram_mtx);
        fprintf(stderr,
                "lift: geo_polygon_data #%u addr=%#x count=%u sample0=%#x total_words=%u\n",
                s_poly_uploads, (unsigned)address, (unsigned)count,
                (unsigned)sample, s_poly_words);
    }
}

/* Return 1 if polygon_ram0[addr] matches expect (debug / disasm checks). */
int model2_geo_render_polygon_ram0_peek(u32 addr, u32 *out)
{
    if (!g_inited || !out)
        return 0;
    addr &= 0x7FFFu;
    pthread_mutex_lock(&g_geo_ram_mtx);
    if (!g_ctx.polygon_ram0) {
        pthread_mutex_unlock(&g_geo_ram_mtx);
        return 0;
    }
    *out = g_ctx.polygon_ram0[addr];
    pthread_mutex_unlock(&g_geo_ram_mtx);
    return 1;
}

void model2_geo_render_shutdown(void)
{
    if (g_worker_started) {
        if (g_fifo_valid && g_fifo.set_notify)
            g_fifo.set_notify(NULL);
        pthread_mutex_lock(&g_worker_mtx);
        g_worker_stop = 1;
        g_worker_kick = 1;
        pthread_cond_signal(&g_worker_cond);
        pthread_mutex_unlock(&g_worker_mtx);
        pthread_join(g_worker, NULL);
        g_worker_started = 0;
    }
    model2_mesh_collector_free(&g_mesh);
    model2_geo_dl_ctx_free(&g_ctx);
    free(g_positions);
    free(g_indices);
    free(g_xyzuv);
    free(g_tri_mats);
    g_positions = NULL;
    g_indices = NULL;
    g_xyzuv = NULL;
    g_tri_mats = NULL;
    g_n_positions = 0;
    g_n_indices = 0;
    g_tri_count = 0;
    g_n_xyzuv_verts = 0;
    g_n_tri_mats = 0;
    model2_polygon_rom_shutdown();
    model2_texture_rom_shutdown();
    g_polygon_loaded = 0;
    g_inited = 0;
}

int model2_geo_render_projection(model2_geo_projection_t *out)
{
    int valid;

    if (!out)
        return 0;
    pthread_mutex_lock(&g_pub_mtx);
    *out = g_projection;
    valid = out->valid;
    pthread_mutex_unlock(&g_pub_mtx);
    return valid;
}

int model2_geo_render_decode_prg_file(const char *path, int require_end)
{
    FILE *fp;
    long sz;
    u32 *words = NULL;
    unsigned n_words;
    model2_geo_dl_result_t result;
    size_t nread;

    if (!g_inited)
        model2_geo_render_init();
    if (!path || !*path)
        return -1;
    ensure_polygon_rom();
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    sz = ftell(fp);
    rewind(fp);
    if (sz < 4 || (sz % 4) != 0) {
        fclose(fp);
        return -1;
    }
    n_words = (unsigned)(sz / 4);
    words = (u32 *)malloc((size_t)sz);
    if (!words) {
        fclose(fp);
        return -1;
    }
    nread = fread(words, 4, n_words, fp);
    fclose(fp);
    if (nread != n_words) {
        free(words);
        return -1;
    }

    model2_mesh_collector_reset(&g_mesh);
    model2_geo_dl_result_init(&result);
    if (model2_geo_dl_run(&g_ctx, words, n_words, 0, require_end, 0x8000u, &result) != 0) {
        fprintf(stderr, "lift: geo file decode failed: %s\n", result.error);
        model2_geo_dl_result_free(&result);
        free(words);
        return -1;
    }
    model2_mesh_collector_append(&g_mesh, &result.mesh);
    model2_geo_dl_result_free(&result);
    free(words);
    rebuild_gl_buffers();
    fprintf(stderr, "lift: geo file decode verts=%u tris=%u\n", g_mesh.n_verts, g_tri_count);
    return (int)g_mesh.n_verts;
}

int model2_geo_render_decode_fifos(void)
{
    unsigned want;

    if (!g_inited)
        model2_geo_render_init();

    if (!g_worker_started)
        return decode_fifos_locked();

    pthread_mutex_lock(&g_worker_mtx);
    g_worker_gen++;
    want = g_worker_gen;
    g_worker_kick = 1;
    pthread_cond_signal(&g_worker_cond);
    while (!g_worker_stop && g_done_gen < want)
        pthread_cond_wait(&g_worker_cond, &g_worker_mtx);
    pthread_mutex_unlock(&g_worker_mtx);
    return (int)g_mesh.n_verts;
}

unsigned model2_geo_render_vertex_count(void)
{
    unsigned n;

    pthread_mutex_lock(&g_pub_mtx);
    n = g_n_positions / 3u;
    pthread_mutex_unlock(&g_pub_mtx);
    return n;
}

unsigned model2_geo_render_triangle_count(void)
{
    unsigned n;

    pthread_mutex_lock(&g_pub_mtx);
    n = g_tri_count;
    pthread_mutex_unlock(&g_pub_mtx);
    return n;
}

const float *model2_geo_render_positions(unsigned *out_n_floats)
{
    /* Pointer is stable only until the next publish; viewers should copy. */
    pthread_mutex_lock(&g_pub_mtx);
    if (out_n_floats)
        *out_n_floats = g_n_positions;
    pthread_mutex_unlock(&g_pub_mtx);
    return g_positions;
}

const unsigned *model2_geo_render_indices(unsigned *out_n_indices)
{
    pthread_mutex_lock(&g_pub_mtx);
    if (out_n_indices)
        *out_n_indices = g_n_indices;
    pthread_mutex_unlock(&g_pub_mtx);
    return g_indices;
}

/* Copy published buffers for a race-free draw. Caller frees *out_pos / *out_idx. */
int model2_geo_render_copy_draw_buffers(float **out_pos, unsigned *out_npos,
                                        unsigned **out_idx, unsigned *out_nidx)
{
    float *pos = NULL;
    unsigned *idx = NULL;
    unsigned npos = 0, nidx = 0;

    if (!out_pos || !out_npos)
        return -1;
    *out_pos = NULL;
    *out_npos = 0;
    if (out_idx)
        *out_idx = NULL;
    if (out_nidx)
        *out_nidx = 0;

    pthread_mutex_lock(&g_pub_mtx);
    npos = g_n_positions;
    nidx = g_n_indices;
    if (npos && g_positions) {
        pos = (float *)malloc(npos * sizeof(float));
        if (pos)
            memcpy(pos, g_positions, npos * sizeof(float));
    }
    if (nidx && g_indices && out_idx) {
        idx = (unsigned *)malloc(nidx * sizeof(unsigned));
        if (idx)
            memcpy(idx, g_indices, nidx * sizeof(unsigned));
    }
    pthread_mutex_unlock(&g_pub_mtx);

    if (npos && !pos) {
        free(idx);
        return -1;
    }
    *out_pos = pos;
    *out_npos = npos;
    if (out_idx)
        *out_idx = idx;
    if (out_nidx)
        *out_nidx = nidx;
    return 0;
}

int model2_geo_render_copy_draw_textured(float **out_xyzuv, unsigned *out_nverts,
                                         model2_geo_tri_mat_t **out_mats,
                                         unsigned *out_ntris)
{
    float *xyzuv = NULL;
    model2_geo_tri_mat_t *mats = NULL;
    unsigned nverts = 0, ntris = 0;

    if (!out_xyzuv || !out_nverts || !out_mats || !out_ntris)
        return -1;
    *out_xyzuv = NULL;
    *out_nverts = 0;
    *out_mats = NULL;
    *out_ntris = 0;

    pthread_mutex_lock(&g_pub_mtx);
    nverts = g_n_xyzuv_verts;
    ntris = g_n_tri_mats;
    if (nverts && g_xyzuv) {
        xyzuv = (float *)malloc(nverts * 5u * sizeof(float));
        if (xyzuv)
            memcpy(xyzuv, g_xyzuv, nverts * 5u * sizeof(float));
    }
    if (ntris && g_tri_mats) {
        mats = (model2_geo_tri_mat_t *)malloc(ntris * sizeof(*mats));
        if (mats)
            memcpy(mats, g_tri_mats, ntris * sizeof(*mats));
    }
    pthread_mutex_unlock(&g_pub_mtx);

    if ((nverts && !xyzuv) || (ntris && !mats)) {
        free(xyzuv);
        free(mats);
        return -1;
    }
    *out_xyzuv = xyzuv;
    *out_nverts = nverts;
    *out_mats = mats;
    *out_ntris = ntris;
    return 0;
}

int model2_geo_render_lock_draw_textured(const float **out_xyzuv, unsigned *out_nverts,
                                         const model2_geo_tri_mat_t **out_mats,
                                         unsigned *out_ntris)
{
    if (!out_xyzuv || !out_nverts || !out_mats || !out_ntris)
        return -1;
    pthread_mutex_lock(&g_pub_mtx);
    if (!g_xyzuv || !g_tri_mats || g_n_tri_mats == 0u) {
        pthread_mutex_unlock(&g_pub_mtx);
        *out_xyzuv = NULL;
        *out_nverts = 0;
        *out_mats = NULL;
        *out_ntris = 0;
        return -1;
    }
    *out_xyzuv = g_xyzuv;
    *out_nverts = g_n_xyzuv_verts;
    *out_mats = g_tri_mats;
    *out_ntris = g_n_tri_mats;
    return 0;
}

void model2_geo_render_unlock_draw(void)
{
    pthread_mutex_unlock(&g_pub_mtx);
}

void model2_geo_render_clear_draw(void)
{
    pthread_mutex_lock(&g_pub_mtx);
    free(g_positions);
    free(g_indices);
    free(g_xyzuv);
    free(g_tri_mats);
    g_positions = NULL;
    g_indices = NULL;
    g_xyzuv = NULL;
    g_tri_mats = NULL;
    g_n_positions = 0;
    g_n_indices = 0;
    g_tri_count = 0;
    g_n_xyzuv_verts = 0;
    g_n_tri_mats = 0;
    pthread_mutex_unlock(&g_pub_mtx);

    pthread_mutex_lock(&g_worker_mtx);
    model2_mesh_collector_reset(&g_mesh);
    s_have_prg_mesh = 0;
    pthread_mutex_unlock(&g_worker_mtx);
}

int model2_geo_render_dump_summary(const char *path)
{
    FILE *fp;
    unsigned i;
    float xmin = 0, xmax = 0, ymin = 0, ymax = 0, zmin = 0, zmax = 0;

    if (!path || !*path)
        return -1;
    fp = fopen(path, "w");
    if (!fp)
        return -1;

    if (g_mesh.n_verts > 0) {
        xmin = xmax = g_mesh.verts[0].x;
        ymin = ymax = g_mesh.verts[0].y;
        zmin = zmax = g_mesh.verts[0].z;
        for (i = 1; i < g_mesh.n_verts; i++) {
            if (g_mesh.verts[i].x < xmin)
                xmin = g_mesh.verts[i].x;
            if (g_mesh.verts[i].x > xmax)
                xmax = g_mesh.verts[i].x;
            if (g_mesh.verts[i].y < ymin)
                ymin = g_mesh.verts[i].y;
            if (g_mesh.verts[i].y > ymax)
                ymax = g_mesh.verts[i].y;
            if (g_mesh.verts[i].z < zmin)
                zmin = g_mesh.verts[i].z;
            if (g_mesh.verts[i].z > zmax)
                zmax = g_mesh.verts[i].z;
        }
    }

    fprintf(fp,
            "{\n"
            "  \"vertex_count\": %u,\n"
            "  \"triangle_count\": %u,\n"
            "  \"primitive_count\": %u,\n"
            "  \"bbox\": [%.6g, %.6g, %.6g, %.6g, %.6g, %.6g],\n"
            "  \"first_verts\": [\n",
            g_mesh.n_verts, g_tri_count, g_mesh.n_prims, xmin, ymin, zmin, xmax, ymax,
            zmax);
    for (i = 0; i < g_mesh.n_verts && i < 16u; i++) {
        fprintf(fp, "    [%.6g, %.6g, %.6g]%s\n", g_mesh.verts[i].x, g_mesh.verts[i].y,
                g_mesh.verts[i].z, (i + 1u < g_mesh.n_verts && i + 1u < 16u) ? "," : "");
    }
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    return 0;
}

void model2_geo_render_draw_gl(void)
{
#ifdef I960_HOST_HAVE_GL
    unsigned i;

    if (g_n_indices >= 3u && g_positions) {
        glEnable(GL_DEPTH_TEST);
        glEnable(GL_CULL_FACE);
        glCullFace(GL_BACK);
        glColor4f(0.85f, 0.9f, 1.0f, 0.9f);
        glBegin(GL_TRIANGLES);
        for (i = 0; i + 2u < g_n_indices; i += 3u) {
            unsigned i0 = g_indices[i] * 3u;
            unsigned i1 = g_indices[i + 1u] * 3u;
            unsigned i2 = g_indices[i + 2u] * 3u;
            glVertex3f(g_positions[i0], g_positions[i0 + 1u], g_positions[i0 + 2u]);
            glVertex3f(g_positions[i1], g_positions[i1 + 1u], g_positions[i1 + 2u]);
            glVertex3f(g_positions[i2], g_positions[i2 + 1u], g_positions[i2 + 2u]);
        }
        glEnd();
    } else if (g_n_positions >= 3u && g_positions) {
        glDisable(GL_DEPTH_TEST);
        glPointSize(3.f);
        glColor4f(1.f, 0.85f, 0.2f, 1.f);
        glBegin(GL_POINTS);
        for (i = 0; i < g_n_positions; i += 3u)
            glVertex3f(g_positions[i], g_positions[i + 1u], g_positions[i + 2u]);
        glEnd();
    }
#else
    (void)0;
#endif
}
