#include "model2_tgp.h"
#include "model2_tgp_fw.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u32 tgp_workram_ld(u32 vaddr)
{
    const model2_tgp_host_ops_t *host = model2_tgp_host();
    if (host && host->workram_ld_u32)
        return host->workram_ld_u32(vaddr);
    return 0;
}

static void tgp_emit_geo_matrix(const float m[12])
{
    const model2_tgp_host_ops_t *host = model2_tgp_host();
    if (host && host->emit_geo_matrix)
        host->emit_geo_matrix(m);
}

#define COPRO_CAP          8192u
#define COPRO_OUT_CAP      64u
#define COPRO_IN_CAP       16u
#define COPRO_MTX_STACK_CAP 32u

static u32 g_copro[COPRO_CAP];
/* Total words ever written (ring index = total % COPRO_CAP). */
static unsigned g_copro_total;
/*
 * Copro @ 0x884000 — semantics from attract disasm call sites (slot_call /
 * object_extra / marker_burst / glyph / script_finish / vec_scale). Host math,
 * not a full TGP firmware sim; arity and formulas match how the lifted ROM
 * uses the results.
 */
static u32 g_copro_out[COPRO_OUT_CAP];
static unsigned g_copro_out_r;
static unsigned g_copro_out_w;
static unsigned g_copro_out_n;

static u32 g_copro_cmd;
static u32 g_copro_in[COPRO_IN_CAP];
static unsigned g_copro_in_n;
static unsigned g_copro_need;
static float g_copro_matrix[12];
static float g_copro_matrix_stack[COPRO_MTX_STACK_CAP][12];
static unsigned g_copro_matrix_sp;
/*
 * TGP 0x60/0x61 external list (fw @ 0x3DB / 0x3E9). i960 stores selector
 * 0 or 16 at *0x20a290; firmware copies 12 floats to/from $7+selector.
 * Host keeps one current matrix, so selector is the slot index.
 */
#define COPRO_EXT_MTX_WORDS 32u
static float g_copro_ext_mtx[COPRO_EXT_MTX_WORDS][12];
/*
 * Attract camera latched at script_finish @ 0x128AC (after st to 0x20220c):
 *   view 3×4 from TGP, focus xyz from workram, scene seeds from geo_view_matrix_seed.
 * 0x214284/288/28c feed geo_view_scene_apply — they are not GL FOV / near / far.
 */
static float g_view_matrix[12];
static float g_view_focus[3];
static float g_view_pitch_seed; /* 0x214284 seed: 25.0 */
static float g_view_seed_a;     /* 0x214288 seed: 260.0 */
static float g_view_seed_b;     /* 0x21428c seed: 120.0 */
static int g_view_matrix_valid;
/* Object pose angles from markers 0x14802929 / 0x15002a2a / 0x15802b2b
 * (obj+0x18 / +0x1c / +0x20). 0x150 is heading — see pen_angle_push. */
static float g_copro_ang_x; /* 0x14802929 */
static float g_copro_ang_y; /* 0x15002a2a */
static float g_copro_ang_z; /* 0x15802b2b */
static float g_copro_scale[3]; /* 0x14002828 — marker_burst uses (40,1,40) */
/* 0x2a005454 — direction / delta register (script_finish, vec_scale). */
static float g_copro_vec[3];
/*
 * Vector slots (markers 0x42 / 0x43 / 0x44 / 0x45 / 0x48).
 * Call sites: geo_view_scene_prep @ 0x34380, geo_view_frame_update @ 0x382e8,
 * desert pose_step @ 0x422B0 (sole 0x45 site in maincpu).
 * Index is a raw u32 (0..3), not a float bit-pattern.
 *
 * pose_step dataflow forces slot accumulate on 0x44 and slot−=point on 0x45:
 *   0x42 slot←w0·P0; 0x44×3 add w1..w3·Pi; 0x45 subtract node XZ; 0x48→0x43.
 * Without accumulate, only w0 would survive into 0x48. frame_update's
 * 0x48→0x44→0x43 path still latches M×immediate for readback (slot side
 * effect unused after pop).
 */
#define COPRO_VEC_SLOTS 8u
static float g_copro_vslot[COPRO_VEC_SLOTS][3];
static unsigned g_copro_vsel;

/*
 * Road-query capture for TGP 0x52 / 0x53.
 *
 * geo_view_table_index_a @ 0x2AC2C writes a nine-word indirect block through
 * *(0x20a290), issues 0x52, and only then advances 0x20a290 by 0x24. Thus the
 * value of 0x20a290 at command issue is the block base (not base-0x24).
 *
 * 0x53 readback (table_index_b @ 0x2ACC0): 16 floats + flag. flag==0 →
 * early out (out+0x1c=15). Non-bit7 path consumes floats[12..15] as
 * Ax+By+Cz+D with height = (−A·x − C·z − D)/B − y (disasm @ 0x2ADCC).
 *
 * Mesh source: copro_data directory (course row word1, e.g. 0x1ada0);
 * 0x52 selects entry index/next/prev and walks tris. 0x07 still resolves
 * main_data list only for the segment-count readback.
 *
 * Bit7 (force_slot chkbit 7 / contact bbc 7) — table_index_b @ 0x2AE6C:
 *   floats[12..14] → out normal (raw, no 0x2f); float[15] = r11 divisor;
 *   height = |(f0−x)(f5−z)−(f2−z)(f3−x)| / r11 (always ≥0).
 * Cam vec_push: bit7 → clear_path; plane height<0 → clear_path; else main.
 *
 * Firmware (srally_tgp_program.asm): jump table 0xAF+op; 0x53 @ PC 0x63C
 * loads data-RAM slot {ptr_flag, ptr_floats} @ $0x68+fifo_arg (filled by
 * 0x52 @ 0x58A), pushes 16 floats then flag; flag==0 → 17×0. i960 bit7 is
 * (flag>>16)&0x80 from that word — not an i960/HLE invention.
 *
 * 0x52 walks copro_data (mpr-17754/55) via model2_tgp_fw_run_52; 0x53 only
 * emits the slot. Attr hi16 bit7 selects table_index_b bit7 vs plane path.
 */
static struct {
    u32 words[9];
    u32 list; /* last 0x07-resolved list VA (main_data) */
    int captured;
} g_copro_road;

static int g_copro_handle_armed;
static u32 g_copro_handle_armed_val;
static int g_copro_52_armed;
static u32 g_copro_52_armed_words[9];

void model2_tgp_arm_course_handle(u32 handle)
{
    g_copro_handle_armed = 1;
    g_copro_handle_armed_val = handle;
}

void model2_tgp_arm_52_block(const u32 words[9])
{
    unsigned i;

    if (words == NULL)
        return;
    for (i = 0; i < 9u; i++)
        g_copro_52_armed_words[i] = words[i];
    g_copro_52_armed = 1;
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

static void copro_out_push(u32 w)
{
    if (g_copro_out_n >= COPRO_OUT_CAP) {
        /* Drop oldest. */
        g_copro_out_r = (g_copro_out_r + 1u) % COPRO_OUT_CAP;
        g_copro_out_n--;
    }
    g_copro_out[g_copro_out_w] = w;
    g_copro_out_w = (g_copro_out_w + 1u) % COPRO_OUT_CAP;
    g_copro_out_n++;
}

static u32 copro_out_pop(void)
{
    u32 w;

    if (g_copro_out_n == 0)
        return 0;
    w = g_copro_out[g_copro_out_r];
    g_copro_out_r = (g_copro_out_r + 1u) % COPRO_OUT_CAP;
    g_copro_out_n--;
    return w;
}

static unsigned copro_ext_selector(void)
{
    u32 cursor = tgp_workram_ld(0x20a290u);
    u32 word = cursor != 0u ? tgp_workram_ld(cursor) : 0u;

    /* road_span_basis / xz_clamp / car_motion: lda 0 / 16 then 0x60/0x61. */
    if (word >= COPRO_EXT_MTX_WORDS)
        word = COPRO_EXT_MTX_WORDS - 1u;
    return (unsigned)word;
}

static void copro_matrix_identity(void)
{
    memset(g_copro_matrix, 0, sizeof(g_copro_matrix));
    /* MAME model2 / tools/model2_geo.py column layout: diag at 0,4,8; T at 9,10,11. */
    g_copro_matrix[0] = 1.f;
    g_copro_matrix[4] = 1.f;
    g_copro_matrix[8] = 1.f;
    g_copro_ang_x = g_copro_ang_y = g_copro_ang_z = 0.f;
    g_copro_scale[0] = g_copro_scale[1] = g_copro_scale[2] = 1.f;
    g_copro_vec[0] = g_copro_vec[1] = g_copro_vec[2] = 0.f;
}

static void copro_matrix_sanitize(void);

static void copro_translate(float x, float y, float z)
{
    copro_matrix_sanitize();
    if (!isfinite(x) || !isfinite(y) || !isfinite(z))
        return;
    g_copro_matrix[9] += g_copro_matrix[0] * x + g_copro_matrix[3] * y
                       + g_copro_matrix[6] * z;
    g_copro_matrix[10] += g_copro_matrix[1] * x + g_copro_matrix[4] * y
                        + g_copro_matrix[7] * z;
    g_copro_matrix[11] += g_copro_matrix[2] * x + g_copro_matrix[5] * y
                        + g_copro_matrix[8] * z;
}

static void copro_xform_point(float x, float y, float z, float out[3])
{
    copro_matrix_sanitize();
    if (!isfinite(x) || !isfinite(y) || !isfinite(z)) {
        out[0] = out[1] = out[2] = 0.f;
        return;
    }
    out[0] = g_copro_matrix[0] * x + g_copro_matrix[3] * y
           + g_copro_matrix[6] * z + g_copro_matrix[9];
    out[1] = g_copro_matrix[1] * x + g_copro_matrix[4] * y
           + g_copro_matrix[7] * z + g_copro_matrix[10];
    out[2] = g_copro_matrix[2] * x + g_copro_matrix[5] * y
           + g_copro_matrix[8] * z + g_copro_matrix[11];
    if (!isfinite(out[0]) || !isfinite(out[1]) || !isfinite(out[2])) {
        out[0] = out[1] = out[2] = 0.f;
    }
}

/*
 * Set R so camera +Z looks along unit forward; leave T unchanged.
 * Evidence: geo_view_scene_frame does 0x2f then explicit 0x25 — it only wants
 * the normalize readback. Mode 7 vec_scale does 0x2f then 0x27 with no
 * identity, so the oriented R is intentional for attract dolly shots.
 */
static void copro_orient_look_along(float fx, float fy, float fz)
{
    float f[3], s[3], u[3];
    float wx = 0.f, wy = 1.f, wz = 0.f;
    float len, inv;
    int i;

    f[0] = fx;
    f[1] = fy;
    f[2] = fz;
    /* right = normalize(world_up × forward); fall back if nearly parallel. */
    s[0] = wy * f[2] - wz * f[1];
    s[1] = wz * f[0] - wx * f[2];
    s[2] = wx * f[1] - wy * f[0];
    len = sqrtf(s[0] * s[0] + s[1] * s[1] + s[2] * s[2]);
    if (len < 1e-5f) {
        wx = 1.f;
        wy = 0.f;
        wz = 0.f;
        s[0] = wy * f[2] - wz * f[1];
        s[1] = wz * f[0] - wx * f[2];
        s[2] = wx * f[1] - wy * f[0];
        len = sqrtf(s[0] * s[0] + s[1] * s[1] + s[2] * s[2]);
    }
    if (len < 1e-6f)
        return;
    inv = 1.f / len;
    for (i = 0; i < 3; i++)
        s[i] *= inv;
    /* up = forward × right (RH: right × up = forward). */
    u[0] = f[1] * s[2] - f[2] * s[1];
    u[1] = f[2] * s[0] - f[0] * s[2];
    u[2] = f[0] * s[1] - f[1] * s[0];
    /* Rows = (right, up, forward) in column-major 3×4 layout. */
    g_copro_matrix[0] = s[0];
    g_copro_matrix[3] = s[1];
    g_copro_matrix[6] = s[2];
    g_copro_matrix[1] = u[0];
    g_copro_matrix[4] = u[1];
    g_copro_matrix[7] = u[2];
    g_copro_matrix[2] = f[0];
    g_copro_matrix[5] = f[1];
    g_copro_matrix[8] = f[2];
}

static unsigned copro_vslot_index(u32 raw)
{
    /* Indices are small integers (0..3); tolerate float 0.f bit-patterns. */
    if (raw < COPRO_VEC_SLOTS)
        return (unsigned)raw;
    {
        float f = u2f(raw);
        if (f >= 0.f && f < (float)COPRO_VEC_SLOTS)
            return (unsigned)f;
    }
    return 0;
}

/*
 * TGP sincos is in a 2π domain. Host sinf/cosf of |θ|≫1e6 (poisoned
 * object +0x3c, leftover 0x2c rates) return NaN and collapse R. Reduce
 * before the rotate — not a game-side float_clamp loop (ROM @ 0x27B28
 * wraps once).
 *
 * remainderf of |θ| whose ulp ≫ 2π is an invalid op (NaN). Treat that
 * the same as a non-finite payload: identity rotate, not a random R.
 */
static float copro_reduce_angle(float angle)
{
    const float two_pi = 6.28318530717958647692f;
    float r;

    if (!isfinite(angle) || fabsf(angle) > 1.0e6f)
        return 0.f;
    r = remainderf(angle, two_pi);
    if (!isfinite(r))
        return 0.f;
    return r;
}

static int copro_matrix_finite(void)
{
    unsigned i;

    for (i = 0; i < 12u; i++) {
        if (!isfinite(g_copro_matrix[i]))
            return 0;
    }
    return 1;
}

static void copro_matrix_sanitize(void)
{
    if (!copro_matrix_finite())
        copro_matrix_identity();
}

static void copro_rotate_x(float angle)
{
    /*
     * TGP 0x29: same sin-sign convention as 0x2a yaw HLE — opposite the
     * usual RH Rx so raw obj+0x18 (no notbit on object paths) tips the mesh
     * with keyframe pitch. Textbook Rx nosed cars into the road plane.
     */
    float a = copro_reduce_angle(angle);
    float c = cosf(a), s = sinf(a);
    float c1[3], c2[3];
    int r;

    copro_matrix_sanitize();
    if (!isfinite(c) || !isfinite(s))
        return;
    for (r = 0; r < 3; r++) {
        c1[r] = g_copro_matrix[3 + r];
        c2[r] = g_copro_matrix[6 + r];
        g_copro_matrix[3 + r] = c1[r] * c - c2[r] * s;
        g_copro_matrix[6 + r] = c1[r] * s + c2[r] * c;
    }
}

static void copro_rotate_y(float angle)
{
    /*
     * TGP 0x2a: post-compose yaw. Sign is opposite the usual RH active Ry
     * used in textbooks: desert keyframes store yaw ≈ +125° while XZ motion
     * heading is ≈ −126°, and glyph_emit feeds raw obj+0x1c (no notbit).
     * With +Z as model forward, this convention maps +Z → (−sin θ, 0, cos θ)
     * so world heading matches travel. (Mode 0 view paths notbit before
     * rotate — that pairs with this HLE, not a second object-side negate.)
     */
    float a = copro_reduce_angle(angle);
    float c = cosf(a), s = sinf(a);
    float c0[3], c2[3];
    int r;

    copro_matrix_sanitize();
    if (!isfinite(c) || !isfinite(s))
        return;
    for (r = 0; r < 3; r++) {
        c0[r] = g_copro_matrix[r];
        c2[r] = g_copro_matrix[6 + r];
        g_copro_matrix[r] = c0[r] * c + c2[r] * s;
        g_copro_matrix[6 + r] = -c0[r] * s + c2[r] * c;
    }
}

static void copro_rotate_z(float angle)
{
    /*
     * TGP 0x2b: same sin-sign convention as 0x29/0x2a — opposite textbook Rz
     * so raw obj+0x20 and glyph_emit centroid roll (no notbit on object paths)
     * bank the mesh with keyframe travel. Textbook Rz rolls cars the wrong way.
     */
    float a = copro_reduce_angle(angle);
    float c = cosf(a), s = sinf(a);
    float c0[3], c1[3];
    int r;

    copro_matrix_sanitize();
    if (!isfinite(c) || !isfinite(s))
        return;
    for (r = 0; r < 3; r++) {
        c0[r] = g_copro_matrix[r];
        c1[r] = g_copro_matrix[3 + r];
        g_copro_matrix[r] = c0[r] * c - c1[r] * s;
        g_copro_matrix[3 + r] = c0[r] * s + c1[r] * c;
    }
}

static void copro_scale(float x, float y, float z)
{
    int r;

    copro_matrix_sanitize();
    if (!isfinite(x) || !isfinite(y) || !isfinite(z))
        return;
    for (r = 0; r < 3; r++) {
        g_copro_matrix[r] *= x;
        g_copro_matrix[3 + r] *= y;
        g_copro_matrix[6 + r] *= z;
    }
}

/*
 * Course-table typed resolve for table_index_a @ 0x2ABC0 only:
 *   0x5dcac0 row word0 = handle stored before 0x07
 *   row word2 = main_data list head; list[0] = segment count (centroid @ 0x41E70)
 * Not a generic 0x07 contract — site @ 0x29840 feeds sequential integers into
 * 0x07 for a CRC fold, so unmatched handles return 0.
 */
static u32 copro_course_list_for_handle(u32 handle, unsigned handle_word,
                                        int allow_zero)
{
    unsigned course;

    if (handle_word > 1u)
        return 0;
    /* Course 2 row word0 is 0. Unarmed *(cursor)==0 is a polluted GEO slot,
     * not that row — CRC @ 0x29840 unmatched stays 0. */
    if (handle == 0u && !allow_zero)
        return 0;
    for (course = 0; course < 8u; course++) {
        u32 row = 0x5dcac0u + course * 12u;

        if (tgp_workram_ld(row + handle_word * 4u) == handle)
            return tgp_workram_ld(row + 8u);
    }
    return 0;
}

static void copro_road_capture_from_indirect(void)
{
    u32 cursor = tgp_workram_ld(0x20a290u);
    u32 list = g_copro_road.list;
    unsigned i;

    memset(&g_copro_road, 0, sizeof(g_copro_road));
    g_copro_road.list = list; /* keep last 0x07 list across capture clear */
    if (g_copro_52_armed) {
        for (i = 0; i < 9u; i++)
            g_copro_road.words[i] = g_copro_52_armed_words[i];
        g_copro_52_armed = 0;
        g_copro_road.captured = 1;
        return;
    }
    if (cursor == 0u)
        return;
    for (i = 0; i < 9u; i++)
        g_copro_road.words[i] = tgp_workram_ld(cursor + i * 4u);
    g_copro_road.captured = 1;
}

/*
 * Emit 0x53 readback. arg_shifted = FIFO word after marker (arg2<<1).
 * Slot must already be filled by 0x52 (model2_tgp_fw_run_52).
 */
static void copro_road_emit_53(u32 arg_shifted)
{
    model2_tgp_fw_emit_53(arg_shifted, copro_out_push);
}

static void copro_finish_cmd(void)
{
    unsigned i;
    float x, y, z, r;

    switch (g_copro_cmd) {
    case 0x03800707u:
        /*
         * table_index_a @ 0x2ABD0: word at *(0x20a290) is course row word0;
         * readback is compared as segment count. Resolve via typed 0x5dcac0
         * → list[0]. Unmatched (e.g. 0x29840 integer stream) → 0.
         */
        {
            u32 cursor = tgp_workram_ld(0x20a290u);
            u32 ram_handle = cursor ? tgp_workram_ld(cursor) : 0u;
            u32 handle = ram_handle;
            int armed = g_copro_handle_armed;
            u32 list;

            if (armed) {
                handle = g_copro_handle_armed_val;
                g_copro_handle_armed = 0;
            }
            list = copro_course_list_for_handle(handle, 0u, armed);

            g_copro_road.list = list;
            copro_out_push(list ? tgp_workram_ld(list) : 0u);
            {
                static int log07;

                if (log07 < 8) {
                    u32 count = list ? tgp_workram_ld(list) : 0u;

                    fprintf(stderr,
                            "lift: tgp 0x07 cursor=%#x ram=%#x handle=%#x "
                            "armed=%d list=%#x count=%u\n",
                            (unsigned)cursor, (unsigned)ram_handle,
                            (unsigned)handle, armed, (unsigned)list,
                            (unsigned)count);
                    fflush(stderr);
                    log07++;
                }
            }
        }
        break;
    case 0x29005252u:
        /* Capture nine-word block and walk copro_data → slot (PC 0x58A). */
        copro_road_capture_from_indirect();
        if (g_copro_road.captured) {
            static int hit_logged;
            static int miss_logged;
            int hit = model2_tgp_fw_run_52(g_copro_road.words);

            if (hit && !hit_logged) {
                fprintf(stderr,
                        "lift: tgp 0x52 hit dir=%#x idx=%u slot=%u "
                        "q=(%.4g,%.4g,%.4g)\n",
                        (unsigned)g_copro_road.words[3],
                        (unsigned)(g_copro_road.words[6] >> 2),
                        (unsigned)(g_copro_road.words[8] >> 1),
                        u2f(g_copro_road.words[0]), u2f(g_copro_road.words[1]),
                        u2f(g_copro_road.words[2]));
                fflush(stderr);
                hit_logged = 1;
            } else if (!hit && !miss_logged) {
                fprintf(stderr,
                        "lift: tgp 0x52 miss dir=%#x idx=%u "
                        "q=(%.4g,%.4g,%.4g)\n",
                        (unsigned)g_copro_road.words[3],
                        (unsigned)(g_copro_road.words[6] >> 2),
                        u2f(g_copro_road.words[0]), u2f(g_copro_road.words[1]),
                        u2f(g_copro_road.words[2]));
                fflush(stderr);
                miss_logged = 1;
            }
        }
        break;
    case 0x29805353u:
        /*
         * table_index_b @ 0x2ACC0: 16 floats + flag. flag==0 → early out
         * (out+0x1c=15). FIFO arg = arg2<<1 → slot @ $0x68+arg (fw @ 0x63C).
         */
        copro_road_emit_53(g_copro_in_n >= 1u ? g_copro_in[0] : 0u);
        break;
    case 0x19003232u:
    case 0x19803333u:
    case 0x1a003434u:
        if (g_copro_in_n >= 1u) {
            i32 half = (i32)(g_copro_in[0] & 0xffffu);
            float angle;

            if ((half & 0x8000) != 0)
                half -= 0x10000;
            /*
             * ldis sites @ 0x28178/0x28194/0x281B0 pass signed halfwords.
             * The halfword turn domain is 0x8000=pi.
             */
            angle = (float)half * (3.14159265358979323846f / 32768.f);
            if (g_copro_cmd == 0x19003232u)
                copro_rotate_x(angle);
            else if (g_copro_cmd == 0x19803333u)
                copro_rotate_y(angle);
            else
                copro_rotate_z(angle);
        }
        break;
    case 0x1f003e3eu:
        if (g_copro_in_n >= 2u) {
            float x = u2f(g_copro_in[0]);
            float y = u2f(g_copro_in[1]);
            i32 angle = (i32)(atan2f(y, x)
                              * (32768.f / 3.14159265358979323846f));

            /*
             * desert node_frame @ 0x42B7C reads this word then sign-extends
             * lo16 into 0x34/0x32, which round-trips through the halfword
             * rotate commands above.
             */
            copro_out_push((u32)angle);
        }
        break;
    case 0x2e005c5cu:
        /*
         * slot_call @ 0x3B334: six floats per edge of a ground quad, order
         *   (obj.z, pi.z, pj.x, obj.x, pi.x, pj.z)
         * → signed XZ cross of edge pi→pj vs point obj (side / winding test).
         * Four edges; cmpr path keeps candidates with mixed signs.
         */
        if (g_copro_in_n >= 6u) {
            float oz = u2f(g_copro_in[0]);
            float iz = u2f(g_copro_in[1]);
            float jx = u2f(g_copro_in[2]);
            float ox = u2f(g_copro_in[3]);
            float ix = u2f(g_copro_in[4]);
            float jz = u2f(g_copro_in[5]);

            r = (jx - ix) * (oz - iz) - (jz - iz) * (ox - ix);
            copro_out_push(fbits(r));
        }
        break;
    case 0x2c805959u:
        /*
         * Firmware @ 0x530 (jump 0xAF+0x59): 6 floats → one float
         *   out = in0*in1 + in2*in3 + in4*in5
         * matrix_prep @ 0x3A4FC: cam.xyz interleaved with R·(0,0,1) →
         * cam·forward (r10). span_test @ 0x22894: delta × normal.
         */
        if (g_copro_in_n >= 6u) {
            r = u2f(g_copro_in[0]) * u2f(g_copro_in[1])
              + u2f(g_copro_in[2]) * u2f(g_copro_in[3])
              + u2f(g_copro_in[4]) * u2f(g_copro_in[5]);
            copro_out_push(fbits(r));
        }
        break;
    case 0x2c005858u:
        /* Two points (ax,ay,az, bx,by,bz) → |B−A|. slot_call uses A=0. */
        if (g_copro_in_n >= 6u) {
            float ax = u2f(g_copro_in[0]);
            float ay = u2f(g_copro_in[1]);
            float az = u2f(g_copro_in[2]);
            float bx = u2f(g_copro_in[3]);
            float by = u2f(g_copro_in[4]);
            float bz = u2f(g_copro_in[5]);

            x = bx - ax;
            y = by - ay;
            z = bz - az;
            r = sqrtf(x * x + y * y + z * z);
            if (r < 1e-6f)
                r = 1e-6f;
            copro_out_push(fbits(r));
        }
        break;
    case 0x28005050u:
        /*
         * Same six-float |B−A| as 0x58. Call sites: desert_near_pick /
         * desert_obj_near_flag / car_motion @ 0x30B04 (threshold vs 200).
         */
        if (g_copro_in_n >= 6u) {
            float ax = u2f(g_copro_in[0]);
            float ay = u2f(g_copro_in[1]);
            float az = u2f(g_copro_in[2]);
            float bx = u2f(g_copro_in[3]);
            float by = u2f(g_copro_in[4]);
            float bz = u2f(g_copro_in[5]);

            x = bx - ax;
            y = by - ay;
            z = bz - az;
            r = sqrtf(x * x + y * y + z * z);
            if (r < 1e-6f)
                r = 1e-6f;
            copro_out_push(fbits(r));
        }
        break;
    case 0x30806161u:
        /*
         * Firmware @ 0x3E9: a = *$125++; copy 12 floats from $7+a into $7.
         * i960 word at *0x20a290 is 0 (road_span first store / motion) or
         * 16 (look-along store). Host current ≡ $7+$200 working matrix.
         */
        memcpy(g_copro_matrix, g_copro_ext_mtx[copro_ext_selector()],
               sizeof(g_copro_matrix));
        break;
    case 0x2d805b5bu:
        /*
         * scene_prep @ 0x34A88 / scene_frame @ 0x35994, 0x36BF4:
         * six floats → A×B, but push order is (Ay, Bz, Az, By, Bx, Ax),
         * not sequential Axyz then Bxyz. Both call sites match:
         *   hy, vz, hz, vy, vx, hx  (heading × unit pos / table vec)
         * Reconstruct A=(Ax,Ay,Az), B=(Bx,By,Bz) then cross. Sequential
         * HLE made Y≈Az·Bx−Ax·Bz with Ax=hy → ~cos(yaw)·vy, so XZ heading
         * steer (214204) died and yaw froze near ±π.
         */
        if (g_copro_in_n >= 6u) {
            float ay = u2f(g_copro_in[0]);
            float bz = u2f(g_copro_in[1]);
            float az = u2f(g_copro_in[2]);
            float by = u2f(g_copro_in[3]);
            float bx = u2f(g_copro_in[4]);
            float ax = u2f(g_copro_in[5]);

            copro_out_push(fbits(ay * bz - az * by));
            copro_out_push(fbits(az * bx - ax * bz));
            copro_out_push(fbits(ax * by - ay * bx));
        }
        break;
    case 0x11002222u:
        /* 12 floats → current matrix. */
        for (i = 0; i < 12u && i < g_copro_in_n; i++)
            g_copro_matrix[i] = u2f(g_copro_in[i]);
        break;
    case 0x12002424u:
        /* cam_seed @ 0x1F934: same 12-float matrix load (alternate marker). */
        for (i = 0; i < 12u && i < g_copro_in_n; i++)
            g_copro_matrix[i] = u2f(g_copro_in[i]);
        break;
    case 0x13802727u:
        /* TGP command 0x27: post-compose local translation. */
        if (g_copro_in_n >= 3u) {
            copro_translate(u2f(g_copro_in[0]), u2f(g_copro_in[1]),
                            u2f(g_copro_in[2]));
        }
        break;
    case 0x28805151u:
        /*
         * Orient R to look along FIFO xyz (fw @ 0x48E → 0x4E3/0x4F8).
         * road_span_basis @ 0x31554: after 0x25+0x27(bx,0,cx), 0x51(bz,0,by)
         * then 0x2c(ox,0,0) → node+0x90/98 world XZ. Cam path @ 0x4491C:
         * 0x27(pos) then 0x51(focus_delta) before 0x05 emit.
         * Same R side-effect family as 0x54; no direction store.
         */
        if (g_copro_in_n >= 3u) {
            float vx = u2f(g_copro_in[0]);
            float vy = u2f(g_copro_in[1]);
            float vz = u2f(g_copro_in[2]);
            float len = sqrtf(vx * vx + vy * vy + vz * vz);

            if (len > 1e-6f)
                copro_orient_look_along(vx / len, vy / len, vz / len);
        }
        break;
    case 0x30006060u:
        /*
         * Firmware @ 0x3DB: a = *$125++; copy 12 floats from $7+0x200
         * (working matrix) to $7+a. road_span_basis stores identity+translate
         * at 0, then look-along at 16; motion/xz_clamp 0x61 those slots.
         */
        memcpy(g_copro_ext_mtx[copro_ext_selector()], g_copro_matrix,
               sizeof(g_copro_matrix));
        break;
    case 0x2a005454u:
        /*
         * Store direction vector and orient R to look along it.
         * Mode 4 @ 0x11F24: 0x54(scene) then 0x27(−(obj−scene)). Mode 7
         * vec_scale @ 0x11A80: 0x54(delta) → 0x2f (unit only) → 0x27.
         * Look-along is 0x54's side effect; 0x2f does not touch R.
         */
        if (g_copro_in_n >= 3u) {
            float vx = u2f(g_copro_in[0]);
            float vy = u2f(g_copro_in[1]);
            float vz = u2f(g_copro_in[2]);
            float len = sqrtf(vx * vx + vy * vy + vz * vz);

            g_copro_vec[0] = vx;
            g_copro_vec[1] = vy;
            g_copro_vec[2] = vz;
            if (len >= 1e-5f)
                copro_orient_look_along(vx / len, vy / len, vz / len);
        }
        break;
    case 0x17802f2fu:
        /*
         * 3 in → 3 out unit vector only. Disasm sites that need look-along
         * R issue 0x54 first (attract vec_scale @ 0x11A80: 0x54 → 0x2f →
         * 0x27). Race table_index_b @ 0x2AE04 is bare 0x2f then ret — if
         * 0x2f also oriented R, every road sample would clobber the view.
         * Host previously oriented here for mode-7 parity; that invented
         * side effect spun chase after 0x52 started hitting.
         * Non-finite / tiny in → zero out.
         */
        if (g_copro_in_n >= 3u) {
            x = u2f(g_copro_in[0]);
            y = u2f(g_copro_in[1]);
            z = u2f(g_copro_in[2]);
            if (!(x == x && y == y && z == z)) {
                copro_out_push(0);
                copro_out_push(0);
                copro_out_push(0);
            } else {
                r = sqrtf(x * x + y * y + z * z);
                if (r < 1e-6f) {
                    copro_out_push(0);
                    copro_out_push(0);
                    copro_out_push(0);
                } else {
                    copro_out_push(fbits(x / r));
                    copro_out_push(fbits(y / r));
                    copro_out_push(fbits(z / r));
                }
            }
        }
        break;
    case 0x2a805555u:
        /*
         * copro_submit @ 0x31FC0: 10 floats then write_ptr += 0x34 (same
         * contract as TGP 0x05 → GEO 0x0B + 12 floats). Payload order from
         * disasm:
         *   ox, oy, oz, eye.x, ox, eye.z, oz, 1.5, scale, 1.0
         * Record xyz is world (object_extra pose); eye.xz from 0x20220c/14.
         * eye.y is not pushed to the FIFO; script_finish stores the full eye
         * triplet at 0x20220c/210/214 — use 0x202210 for ey (same store).
         * Emit object matrix to GEO only — do not replace the TGP working
         * matrix. script_finish calls course_carousel_draw next, which
         * 0x05-pushes the current matrix then composes placements; if 0x55
         * left the last car as current, scenery parents to the vehicle.
         *
         * GEO 0x0B replaces modelview. Cars are already in view space after
         * mode-7 look-along R; world T=(obj−eye) with R=I puts dust at
         * focal·Tx≈1e4. Transform spawn through the current view (same as
         * TGP 0x2c) so T is view-space; keep diag scale, no billboard R.
         */
        if (g_copro_in_n >= 10u) {
            float ox = u2f(g_copro_in[0]);
            float oy = u2f(g_copro_in[1]);
            float oz = u2f(g_copro_in[2]);
            float ex = u2f(g_copro_in[3]);
            float ez = u2f(g_copro_in[5]);
            float sx = u2f(g_copro_in[7]);
            float sy = u2f(g_copro_in[8]);
            float sz = u2f(g_copro_in[9]);
            /* Companion to FIFO eye.xz — script_finish @ 0x128B8. */
            float ey = u2f(tgp_workram_ld(0x202210u));
            float saved[12];
            float view_pt[3];
            float tx, ty, tz;
            static unsigned s_cmd55_log;

            memcpy(saved, g_copro_matrix, sizeof(saved));
            copro_xform_point(ox, oy, oz, view_pt);
            tx = view_pt[0];
            ty = view_pt[1];
            tz = view_pt[2];
            memset(g_copro_matrix, 0, sizeof(g_copro_matrix));
            g_copro_matrix[0] = sx;
            g_copro_matrix[4] = sy;
            g_copro_matrix[8] = sz;
            g_copro_matrix[9] = tx;
            g_copro_matrix[10] = ty;
            g_copro_matrix[11] = tz;
            tgp_emit_geo_matrix(g_copro_matrix);
            memcpy(g_copro_matrix, saved, sizeof(g_copro_matrix));
            if (s_cmd55_log < 6u) {
                fprintf(stderr,
                        "lift: tgp 0x55 emit T=(%.3g,%.3g,%.3g) scale=(%.3g,%.3g,%.3g) "
                        "obj=(%.3g,%.3g,%.3g) eye=(%.3g,%.3g,%.3g) "
                        "world_delta=(%.3g,%.3g,%.3g) (view matrix kept)\n",
                        tx, ty, tz, sx, sy, sz, ox, oy, oz, ex, ey, ez,
                        ox - ex, oy - ey, oz - ez);
                s_cmd55_log++;
            }
        }
        break;
    case 0x2e805d5du:
        /*
         * Course-obj draw_4 @ 0x2B46C: seven FIFO words, two packings of
         * obj.xyz + eye.xz (side bit). No following TGP 0x05 — the marker
         * itself must emit GEO 0x0B then restore the working view (same
         * contract as 0x55). Unknown-marker used to drop the seven floats
         * so catalogs drew under the view matrix at the origin.
         */
        if (g_copro_in_n >= 7u) {
            float ox = u2f(g_copro_in[0]);
            float oy = u2f(g_copro_in[1]);
            float oz = u2f(g_copro_in[2]);
            float pt[3];
            float saved[12];
            static unsigned s_cmd5d_log;

            (void)g_copro_in[3];
            (void)g_copro_in[4];
            (void)g_copro_in[5];
            (void)g_copro_in[6];
            memcpy(saved, g_copro_matrix, sizeof(saved));
            copro_xform_point(ox, oy, oz, pt);
            /* Keep the current view R. Eye.xz in the FIFO is not a look-at. */
            g_copro_matrix[9] = pt[0];
            g_copro_matrix[10] = pt[1];
            g_copro_matrix[11] = pt[2];
            tgp_emit_geo_matrix(g_copro_matrix);
            memcpy(g_copro_matrix, saved, sizeof(saved));
            if (s_cmd5d_log < 4u) {
                fprintf(stderr,
                        "lift: tgp 0x5d emit T=(%.3g,%.3g,%.3g) "
                        "obj=(%.3g,%.3g,%.3g) (view R kept)\n",
                        pt[0], pt[1], pt[2], ox, oy, oz);
                s_cmd5d_log++;
            }
        }
        break;
    case 0x14802929u:
        if (g_copro_in_n >= 1u) {
            g_copro_ang_x = u2f(g_copro_in[0]);
            copro_rotate_x(g_copro_ang_x);
        }
        break;
    case 0x15002a2au:
        if (g_copro_in_n >= 1u) {
            g_copro_ang_y = u2f(g_copro_in[0]);
            copro_rotate_y(g_copro_ang_y);
        }
        break;
    case 0x15802b2bu:
        if (g_copro_in_n >= 1u) {
            g_copro_ang_z = u2f(g_copro_in[0]);
            copro_rotate_z(g_copro_ang_z);
        }
        break;
    case 0x14002828u:
        /* 3 floats → scale (marker_burst @ 0x32410 uses 40,1,40). */
        if (g_copro_in_n >= 3u) {
            g_copro_scale[0] = u2f(g_copro_in[0]);
            g_copro_scale[1] = u2f(g_copro_in[1]);
            g_copro_scale[2] = u2f(g_copro_in[2]);
            copro_scale(g_copro_scale[0], g_copro_scale[1], g_copro_scale[2]);
        }
        break;
    case 0x16002c2cu:
        /* 3 floats in → 3 floats out (stored matrix × point; MAME column layout). */
        if (g_copro_in_n >= 3u) {
            float out[3];

            copro_xform_point(u2f(g_copro_in[0]), u2f(g_copro_in[1]),
                              u2f(g_copro_in[2]), out);
            copro_out_push(fbits(out[0]));
            copro_out_push(fbits(out[1]));
            copro_out_push(fbits(out[2]));
        }
        break;
    case 0x21004242u:
        /*
         * Store vector slot: index (u32) + xyz.
         * scene_prep loads four basis vectors; frame_update stores offsets.
         */
        if (g_copro_in_n >= 4u) {
            unsigned idx = copro_vslot_index(g_copro_in[0]);

            g_copro_vslot[idx][0] = u2f(g_copro_in[1]);
            g_copro_vslot[idx][1] = u2f(g_copro_in[2]);
            g_copro_vslot[idx][2] = u2f(g_copro_in[3]);
            g_copro_vsel = idx;
        }
        break;
    case 0x24004848u:
        /*
         * Firmware @ 0x44c–0x46a transforms the selected slot in place.
         */
        if (g_copro_in_n >= 1u) {
            unsigned idx = copro_vslot_index(g_copro_in[0]);
            float out[3];

            g_copro_vsel = idx;
            copro_xform_point(g_copro_vslot[idx][0], g_copro_vslot[idx][1],
                              g_copro_vslot[idx][2], out);
            g_copro_vslot[idx][0] = out[0];
            g_copro_vslot[idx][1] = out[1];
            g_copro_vslot[idx][2] = out[2];
        }
        break;
    case 0x22004444u:
        /*
         * Firmware @ 0x414–0x420 adds immediate xyz directly to slot[idx].
         */
        if (g_copro_in_n >= 4u) {
            unsigned idx = copro_vslot_index(g_copro_in[0]);
            float px = u2f(g_copro_in[1]);
            float py = u2f(g_copro_in[2]);
            float pz = u2f(g_copro_in[3]);

            g_copro_vsel = idx;
            g_copro_vslot[idx][0] += px;
            g_copro_vslot[idx][1] += py;
            g_copro_vslot[idx][2] += pz;
        }
        break;
    case 0x22804545u:
        /*
         * Firmware @ 0x422–0x42e subtracts immediate xyz from slot[idx].
         */
        if (g_copro_in_n >= 4u) {
            unsigned idx = copro_vslot_index(g_copro_in[0]);
            float px = u2f(g_copro_in[1]);
            float py = u2f(g_copro_in[2]);
            float pz = u2f(g_copro_in[3]);

            g_copro_vsel = idx;
            g_copro_vslot[idx][0] -= px;
            g_copro_vslot[idx][1] -= py;
            g_copro_vslot[idx][2] -= pz;
        }
        break;
    case 0x21804343u:
        /* Firmware @ 0x40c–0x412 reads the selected slot directly. */
        if (g_copro_in_n >= 1u)
            g_copro_vsel = copro_vslot_index(g_copro_in[0]);
        copro_out_push(fbits(g_copro_vslot[g_copro_vsel][0]));
        copro_out_push(fbits(g_copro_vslot[g_copro_vsel][1]));
        copro_out_push(fbits(g_copro_vslot[g_copro_vsel][2]));
        break;
    case 0x0a801515u:
        /*
         * View mode_apply @ 0x39D1C: one angle (already ×π) in, one float out.
         * Host HLE uses sinf — matches TGP sincos-class use before 0x202049 encode.
         */
        if (g_copro_in_n >= 1u)
            copro_out_push(fbits(sinf(copro_reduce_angle(u2f(g_copro_in[0])))));
        break;
    case 0x08801111u:
        /*
         * Opcode 0x11: table 0xC0 → 0x1A7. FIFO in, helper 0x1AB (fabd +
         * $570/$571 interpolate, reconstruct sign), FIFO out. Zero early-out
         * at 0x1AD. scene_frame @ 0x36600 / hud_speed @ 0x1DFC0.
         */
        if (g_copro_in_n >= 1u) {
            float x = u2f(g_copro_in[0]);

            if (x == 0.f)
                copro_out_push(0);
            else
                copro_out_push(fbits(1.f / x));
        }
        break;
    default:
        break;
    }
    g_copro_cmd = 0;
    g_copro_in_n = 0;
    g_copro_need = 0;
}

static void copro_start_cmd(u32 marker)
{
    unsigned i;

    g_copro_cmd = marker;
    g_copro_in_n = 0;
    g_copro_need = 0;

    switch (marker) {
    case 0x03800707u:
    case 0x29005252u:
        /* Memory-indirect commands: all operands were written before marker. */
        copro_finish_cmd();
        break;
    case 0x29805353u:
        g_copro_need = 1;
        break;
    case 0x19003232u:
    case 0x19803333u:
    case 0x1a003434u:
        g_copro_need = 1;
        break;
    case 0x1f003e3eu:
        g_copro_need = 2;
        break;
    case 0x2e005c5cu:
        g_copro_need = 6;
        break;
    case 0x2e805d5du:
        g_copro_need = 7;
        break;
    case 0x2c805959u:
    case 0x2c005858u:
    case 0x28005050u:
        g_copro_need = 6;
        break;
    case 0x2d805b5bu:
        g_copro_need = 6;
        break;
    case 0x30806161u:
        /* Zero FIFO operands — finish immediately. */
        copro_finish_cmd();
        break;
    case 0x30006060u:
        /* Store matrix to external list (fw @ 0x3DB) — no FIFO operands. */
        copro_finish_cmd();
        break;
    case 0x28805151u:
        g_copro_need = 3;
        break;
    case 0x10002020u:
        /* TGP command 0x20: save current matrix around an object/local query. */
        if (g_copro_matrix_sp < COPRO_MTX_STACK_CAP) {
            memcpy(g_copro_matrix_stack[g_copro_matrix_sp], g_copro_matrix,
                   sizeof(g_copro_matrix));
            g_copro_matrix_sp++;
        } else {
            static int stack_full_logged;

            if (!stack_full_logged) {
                fprintf(stderr,
                        "lift: tgp 0x20 matrix stack full (cap=%u) — "
                        "push dropped; a later 0x21 will unbalance\n",
                        (unsigned)COPRO_MTX_STACK_CAP);
                fflush(stderr);
                stack_full_logged = 1;
            }
        }
        g_copro_cmd = 0;
        break;
    case 0x10802121u:
        /* TGP command 0x21: restore the matrix saved by command 0x20. */
        if (g_copro_matrix_sp > 0) {
            g_copro_matrix_sp--;
            memcpy(g_copro_matrix, g_copro_matrix_stack[g_copro_matrix_sp],
                   sizeof(g_copro_matrix));
        }
        g_copro_cmd = 0;
        break;
    case 0x12802525u:
        /* Load identity before composing a new pose (object_extra @ 0x31860). */
        copro_matrix_identity();
        g_copro_cmd = 0;
        break;
    case 0x13002626u:
        /* 12-word current-matrix readback (slot_call tail @ 0x3B5E4). */
        for (i = 0; i < 12u; i++)
            copro_out_push(fbits(g_copro_matrix[i]));
        g_copro_cmd = 0;
        break;
    case 0x11002222u:
        g_copro_need = 12;
        break;
    case 0x12002424u:
        g_copro_need = 12;
        break;
    case 0x13802727u:
        g_copro_need = 3;
        break;
    case 0x2a005454u:
        g_copro_need = 3;
        break;
    case 0x17802f2fu:
        g_copro_need = 3;
        break;
    case 0x2a805555u:
        g_copro_need = 10;
        break;
    case 0x14802929u:
    case 0x15002a2au:
    case 0x15802b2bu:
        g_copro_need = 1;
        break;
    case 0x14002828u:
        g_copro_need = 3;
        break;
    case 0x16002c2cu:
        g_copro_need = 3;
        break;
    case 0x21004242u:
        g_copro_need = 4;
        break;
    case 0x24004848u:
    case 0x21804343u:
        g_copro_need = 1;
        break;
    case 0x22004444u:
    case 0x22804545u:
        g_copro_need = 4;
        break;
    case 0x0a801515u:
        g_copro_need = 1;
        break;
    case 0x08801111u:
        g_copro_need = 1;
        break;
    case 0x02800505u:
        /* Emit GEO matrix_write (0x0B) + 12 floats via host emit_geo_matrix. */
        tgp_emit_geo_matrix(g_copro_matrix);
        g_copro_cmd = 0;
        break;
    case 0x11802323u:
        /*
         * Marker before 0x25 in course/car/race frames. Not the 0x20 stack
         * push — course_select issues 0x23 every frame with no matching 0x21,
         * so treating it as push would overflow the matrix stack.
         */
        g_copro_cmd = 0;
        break;
    default:
        /* Unknown marker / register poke — no collect. */
        g_copro_cmd = 0;
        break;
    }
}

static int copro_is_marker(u32 value)
{
    u8 lo = (u8)(value & 0xffu);
    u8 hi = (u8)((value >> 8) & 0xffu);

    if (lo != hi)
        return 0;
    switch (value) {
    case 0x03800707u:
    case 0x29005252u:
    case 0x29805353u:
    case 0x19003232u:
    case 0x19803333u:
    case 0x1a003434u:
    case 0x1f003e3eu:
    case 0x2e005c5cu:
    case 0x2e805d5du:
    case 0x2c805959u:
    case 0x2c005858u:
    case 0x28005050u:
    case 0x2d805b5bu:
    case 0x30806161u:
    case 0x30006060u:
    case 0x28805151u:
    case 0x10002020u:
    case 0x10802121u:
    case 0x11002222u:
    case 0x11802323u:
    case 0x12802525u:
    case 0x13002626u:
    case 0x16002c2cu:
    case 0x02800505u:
    case 0x13802727u:
    case 0x14002828u:
    case 0x14802929u:
    case 0x15002a2au:
    case 0x15802b2bu:
    case 0x17802f2fu:
    case 0x2a005454u:
    case 0x2a805555u:
    case 0x0a801515u:
    case 0x08801111u:
    case 0x21004242u:
    case 0x21804343u:
    case 0x22004444u:
    case 0x22804545u:
    case 0x24004848u:
    case 0x12002424u:
        return 1;
    default:
        return 0;
    }
}

static void copro_on_write(u32 value)
{
    if (copro_is_marker(value)) {
        if (g_copro_cmd != 0 && g_copro_need != 0 && g_copro_in_n > 0)
            copro_finish_cmd();
        copro_start_cmd(value);
        return;
    }
    if (g_copro_cmd == 0 || g_copro_need == 0)
        return;
    if (g_copro_in_n < COPRO_IN_CAP)
        g_copro_in[g_copro_in_n++] = value;
    if (g_copro_in_n >= g_copro_need)
        copro_finish_cmd();
}

void model2_tgp_reset(void)
{
    g_copro_total = 0;
    g_copro_out_r = g_copro_out_w = g_copro_out_n = 0;
    g_copro_cmd = 0;
    g_copro_in_n = 0;
    g_copro_need = 0;
    g_copro_matrix_sp = 0;
    memset(&g_copro_road, 0, sizeof(g_copro_road));
    g_copro_handle_armed = 0;
    g_copro_handle_armed_val = 0;
    g_copro_52_armed = 0;
    memset(g_copro_52_armed_words, 0, sizeof(g_copro_52_armed_words));
    model2_tgp_fw_reset();
    memset(g_copro_vslot, 0, sizeof(g_copro_vslot));
    g_copro_vsel = 0;
    memset(g_copro_ext_mtx, 0, sizeof(g_copro_ext_mtx));
    {
        unsigned s;

        for (s = 0; s < COPRO_EXT_MTX_WORDS; s++) {
            g_copro_ext_mtx[s][0] = 1.f;
            g_copro_ext_mtx[s][4] = 1.f;
            g_copro_ext_mtx[s][8] = 1.f;
        }
    }
    copro_matrix_identity();
    memcpy(g_view_matrix, g_copro_matrix, sizeof(g_view_matrix));
    g_view_focus[0] = g_view_focus[1] = g_view_focus[2] = 0.f;
    g_view_pitch_seed = 25.f;
    g_view_seed_a = 260.f;
    g_view_seed_b = 120.f;
    g_view_matrix_valid = 0;
}

void model2_tgp_fifo_reset_counts(void)
{
    g_copro_total = 0;
    g_copro_out_r = g_copro_out_w = g_copro_out_n = 0;
    g_copro_cmd = 0;
    g_copro_in_n = 0;
    g_copro_need = 0;
}

void model2_tgp_fifo_write(u32 value)
{
    g_copro[g_copro_total % COPRO_CAP] = value;
    g_copro_total++;
    copro_on_write(value);
}

u32 model2_tgp_fifo_read(void)
{
    return copro_out_pop();
}

void model2_tgp_matrix(float out[12])
{
    if (!out)
        return;
    memcpy(out, g_copro_matrix, sizeof(g_copro_matrix));
}

int model2_tgp_matrix_is_identity(void)
{
    return (g_copro_matrix[0] == 1.f && g_copro_matrix[4] == 1.f
            && g_copro_matrix[8] == 1.f && g_copro_matrix[1] == 0.f
            && g_copro_matrix[2] == 0.f && g_copro_matrix[3] == 0.f
            && g_copro_matrix[5] == 0.f && g_copro_matrix[6] == 0.f
            && g_copro_matrix[7] == 0.f && g_copro_matrix[9] == 0.f
            && g_copro_matrix[10] == 0.f && g_copro_matrix[11] == 0.f);
}

void model2_tgp_latch_view_matrix(void)
{
    u32 fx, fy, fz, pitch_bits, seed_a, seed_b;

    /* Disasm @ 0x128B8: focus already stored to 0x20220c / 0x202214. */
    fx = tgp_workram_ld(0x20220cu);
    fy = tgp_workram_ld(0x202210u);
    fz = tgp_workram_ld(0x202214u);
    pitch_bits = tgp_workram_ld(0x214284u);
    seed_a = tgp_workram_ld(0x214288u);
    seed_b = tgp_workram_ld(0x21428cu);

    /* script_finish calls this while the composed TGP view is current.
     * A non-finite T (chase 0x27 of a poisoned follow pose) must not
     * replace the last finite latch — restore would then feed NaN T
     * into course 0x05 / scene_frame 0x20. */
    if (!copro_matrix_finite())
        return;
    memcpy(g_view_matrix, g_copro_matrix, sizeof(g_view_matrix));
    g_view_focus[0] = u2f(fx);
    g_view_focus[1] = u2f(fy);
    g_view_focus[2] = u2f(fz);
    g_view_pitch_seed = u2f(pitch_bits);
    g_view_seed_a = u2f(seed_a);
    g_view_seed_b = u2f(seed_b);
    if (!(g_view_pitch_seed > 0.f))
        g_view_pitch_seed = 25.f;
    if (!(g_view_seed_a > 0.f))
        g_view_seed_a = 260.f;
    if (!(g_view_seed_b > 0.f))
        g_view_seed_b = 120.f;
    g_view_matrix_valid = 1;
    {
        static unsigned s_cam_log;
        static unsigned s_cam_latches;
        float eye_tmp[3];
        float tx = g_view_matrix[9], ty = g_view_matrix[10], tz = g_view_matrix[11];

        s_cam_latches++;
        eye_tmp[0] = -(g_view_matrix[0] * tx + g_view_matrix[1] * ty + g_view_matrix[2] * tz);
        eye_tmp[1] = -(g_view_matrix[3] * tx + g_view_matrix[4] * ty + g_view_matrix[5] * tz);
        eye_tmp[2] = -(g_view_matrix[6] * tx + g_view_matrix[7] * ty + g_view_matrix[8] * tz);
        if (s_cam_log < 3u || (s_cam_latches % 120u) == 0u) {
            u32 cam_mode = tgp_workram_ld(0x20a7f4u);
            int r_ident = (g_view_matrix[0] == 1.f && g_view_matrix[4] == 1.f
                           && g_view_matrix[8] == 1.f && g_view_matrix[1] == 0.f
                           && g_view_matrix[2] == 0.f && g_view_matrix[3] == 0.f
                           && g_view_matrix[5] == 0.f && g_view_matrix[6] == 0.f
                           && g_view_matrix[7] == 0.f);
            /* Col-major R: look axis = third column (view +Z). */
            float lx = g_view_matrix[6], ly = g_view_matrix[7], lz = g_view_matrix[8];
            float ax = u2f(tgp_workram_ld(0x202200u));
            float ay = u2f(tgp_workram_ld(0x202204u));
            float az = u2f(tgp_workram_ld(0x202208u));

            fprintf(stderr,
                    "lift: cam mode=%u eye=(%.3g,%.3g,%.3g) focus=(%.3g,%.3g,%.3g) "
                    "T=(%.3g,%.3g,%.3g) R=%s look=(%.3g,%.3g,%.3g) "
                    "ang=(%.3g,%.3g,%.3g) pitch_seed=%.3g seeds=%.3g/%.3g\n",
                    (unsigned)(cam_mode & 0xffu),
                    eye_tmp[0], eye_tmp[1], eye_tmp[2],
                    g_view_focus[0], g_view_focus[1], g_view_focus[2],
                    tx, ty, tz, r_ident ? "I" : "non-I",
                    lx, ly, lz,
                    ax, ay, az,
                    g_view_pitch_seed, g_view_seed_b, g_view_seed_a);
            s_cam_log++;
        }
    }
}

int model2_tgp_restore_latched_view_matrix(void)
{
    if (!g_view_matrix_valid)
        return 0;
    memcpy(g_copro_matrix, g_view_matrix, sizeof(g_copro_matrix));
    return 1;
}

int model2_tgp_view_matrix(float out[12])
{
    if (!out || !g_view_matrix_valid)
        return 0;
    memcpy(out, g_view_matrix, sizeof(g_view_matrix));
    return 1;
}

int model2_tgp_view_camera(float eye_out[3], float focus_out[3], float *pitch_seed,
                           float *seed_a, float *seed_b)
{
    float m[12];
    float fx, fy, fz;
    float pitch, sa, sb;

    if (!g_view_matrix_valid)
        return 0;

    memcpy(m, g_view_matrix, sizeof(m));
    fx = g_view_focus[0];
    fy = g_view_focus[1];
    fz = g_view_focus[2];
    pitch = g_view_pitch_seed;
    sa = g_view_seed_a;
    sb = g_view_seed_b;

    /*
     * script_finish pushes T = −eye (0x13802727 after sign-flip). With R≈I,
     * eye = −T. Generally eye = −RᵀT for the MAME column 3×4.
     */
    if (eye_out) {
        float tx = m[9], ty = m[10], tz = m[11];

        eye_out[0] = -(m[0] * tx + m[1] * ty + m[2] * tz);
        eye_out[1] = -(m[3] * tx + m[4] * ty + m[5] * tz);
        eye_out[2] = -(m[6] * tx + m[7] * ty + m[8] * tz);
    }
    if (focus_out) {
        focus_out[0] = fx;
        focus_out[1] = fy;
        focus_out[2] = fz;
    }
    if (pitch_seed)
        *pitch_seed = pitch;
    if (seed_a)
        *seed_a = sa;
    if (seed_b)
        *seed_b = sb;
    return 1;
}

unsigned model2_tgp_count(void)
{
    unsigned n = g_copro_total;
    if (n > COPRO_CAP)
        n = COPRO_CAP;
    return n;
}

unsigned model2_tgp_total(void)
{
    return g_copro_total;
}

const u32 *model2_tgp_words(unsigned *out_count)
{
    if (out_count)
        *out_count = model2_tgp_count();
    return g_copro;
}

unsigned model2_tgp_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                               unsigned dst_cap)
{
    unsigned i;
    unsigned n = 0;
    unsigned oldest;

    if (!dst || !dst_cap || end_abs <= start_abs)
        return 0;

    oldest = (g_copro_total > COPRO_CAP) ? (g_copro_total - COPRO_CAP) : 0u;
    if (start_abs < oldest)
        start_abs = oldest;
    if (end_abs > g_copro_total)
        end_abs = g_copro_total;
    for (i = start_abs; i < end_abs && n < dst_cap; i++)
        dst[n++] = g_copro[i % COPRO_CAP];
    return n;
}

void model2_tgp_dump(const char *path)
{
    FILE *fp;
    unsigned i;
    unsigned total;
    unsigned start;
    unsigned n;
    u32 *tmp;

    if (!path || !*path)
        return;
    total = model2_tgp_total();
    start = (total > COPRO_CAP) ? (total - COPRO_CAP) : 0u;
    n = total - start;
    tmp = (u32 *)malloc((n ? n : 1u) * sizeof(u32));
    if (!tmp)
        return;
    n = model2_tgp_copy_range(start, total, tmp, n);
    fp = fopen(path, "wb");
    if (!fp) {
        free(tmp);
        return;
    }
    for (i = 0; i < n; i++)
        fwrite(&tmp[i], 4, 1, fp);
    fclose(fp);
    free(tmp);
    fprintf(stderr, "lift: wrote %u copro_fifo words to %s\n", n, path);
}
