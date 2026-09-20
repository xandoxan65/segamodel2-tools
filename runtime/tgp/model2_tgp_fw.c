/* TGP firmware handlers — uplift from decomp/disasm/tgp/srally_tgp_program.asm
 *
 * Source blob: firmware/srally_tgp_program.bin (workram 0x5F9E94 mirror).
 * Focus: 0x52 @ PC 0x58A (copro_data walk → slot) and 0x53 @ PC 0x63C (emit).
 */

#include "model2_tgp_fw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Data-RAM slot table @ TGP $0x68 + arg (arg = i960 arg2<<1).
 * Microcode: a=*slot, b=*(slot+1); a==0 → 17×0; else flag=*ext(a), 16×*ext(b).
 *
 * Host compression: store flag + 16 floats directly (ext pointers elided).
 * 0x52 fills these; 0x53 only emits.
 */
#define TGP_SLOT_BASE 0x68u
#define TGP_SLOT_COUNT 64u

typedef struct {
    u32 flag;
    u32 floats[16];
    int valid;
} tgp_road_slot;

static tgp_road_slot g_slots[TGP_SLOT_COUNT];

/* copro_data ROM (mpr-17754/55), word-addressed like TGP bank 0x800000. */
static const u32 *g_copro;
static u32 g_copro_words;
static u32 *g_copro_owned;

static u32 copro_ld(u32 word_addr)
{
    if (g_copro == NULL || word_addr >= g_copro_words)
        return 0u;
    return g_copro[word_addr];
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

static u32 f2u(float f)
{
    union {
        u32 u;
        float f;
    } v;
    v.f = f;
    return v.u;
}

void model2_tgp_fw_reset(void)
{
    memset(g_slots, 0, sizeof(g_slots));
}

void model2_tgp_fw_bind_copro_data(const u32 *words, u32 nwords)
{
    if (g_copro_owned) {
        free(g_copro_owned);
        g_copro_owned = NULL;
    }
    g_copro = words;
    g_copro_words = nwords;
}

int model2_tgp_fw_load_copro_data_default(void)
{
    /*
     * make lift-boot-viewer runs with cwd=decomp/; extract writes the blob at
     * repo-root out/heightmaps/. Try both layouts (and the mistaken
     * decomp/out path) so 0x52 does not silently no-op → flag 15 → Y dive.
     */
    static const char *const paths[] = {
        "out/heightmaps/copro_data_deinterleaved.bin",
        "../out/heightmaps/copro_data_deinterleaved.bin",
        "decomp/out/heightmaps/copro_data_deinterleaved.bin",
        NULL,
    };
    const char *const *p;
    FILE *fp = NULL;
    long sz;
    u32 nwords;
    u32 *buf;
    static int load_fail_logged;

    if (g_copro != NULL)
        return 0;

    for (p = paths; *p; p++) {
        fp = fopen(*p, "rb");
        if (fp)
            break;
    }
    if (!fp) {
        if (!load_fail_logged) {
            fprintf(stderr,
                    "lift: tgp copro_data missing — 0x52 walk disabled "
                    "(tried out/ and ../out/heightmaps/)\n");
            fflush(stderr);
            load_fail_logged = 1;
        }
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    sz = ftell(fp);
    if (sz < 16 || (sz & 3) != 0) {
        fclose(fp);
        return -1;
    }
    nwords = (u32)(sz / 4);
    buf = (u32 *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    if (fread(buf, 4, nwords, fp) != nwords) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (g_copro_owned)
        free(g_copro_owned);
    g_copro_owned = buf;
    g_copro = buf;
    g_copro_words = nwords;
    fprintf(stderr, "lift: tgp copro_data loaded %u words from %s\n",
            (unsigned)nwords, *p);
    fflush(stderr);
    return 0;
}

void model2_tgp_fw_slot_store(u32 arg_shifted, u32 flag, const u32 floats16[16])
{
    u32 idx;

    /* Microcode x1 = 0x68 + arg; host indexes by arg/2 (pairs). */
    idx = arg_shifted >> 1;
    if (idx >= TGP_SLOT_COUNT)
        return;
    g_slots[idx].flag = flag;
    if (floats16 != NULL)
        memcpy(g_slots[idx].floats, floats16, sizeof(g_slots[idx].floats));
    else
        memset(g_slots[idx].floats, 0, sizeof(g_slots[idx].floats));
    /* word0==0 is miss; keep valid only when flag!=0 (matches brif zrd). */
    g_slots[idx].valid = (flag != 0u) ? 1 : 0;
}

void model2_tgp_fw_slot_clear(u32 arg_shifted)
{
    u32 idx = arg_shifted >> 1;

    if (idx >= TGP_SLOT_COUNT)
        return;
    memset(&g_slots[idx], 0, sizeof(g_slots[idx]));
}

/*
 * 0x53 @ 0x63C — disasm:
 *   lia #0x68 / mov rf1,d / addd / mov d,x1
 *   mov (x1+),a / mov (x1+),b
 *   test a; zrd → clr0 a; rep #17; mov a,rf2
 *   else: a=*ext(a); rf3=b; x1=b; rep #16; mov (x1+)(e),rf2; mov a,rf2
 *
 * FIFO out order: 16 floats then flag (table_index_b @ 0x2ACC0).
 * Bit7: (flag>>16)&0x80 — set only if 0x52 stored such a flag.
 */
int model2_tgp_fw_emit_53(u32 arg_shifted, void (*out_push)(u32))
{
    u32 idx;
    unsigned i;
    const tgp_road_slot *s;

    if (out_push == NULL)
        return 0;

    idx = arg_shifted >> 1;
    if (idx >= TGP_SLOT_COUNT) {
        for (i = 0; i < 17u; i++)
            out_push(0u);
        return 1;
    }

    s = &g_slots[idx];
    if (!s->valid || s->flag == 0u) {
        /* PC 0x64D–0x64F: rep #17 zeros */
        for (i = 0; i < 17u; i++)
            out_push(0u);
        return 1;
    }

    /* PC 0x649–0x64B: 16 floats then flag */
    for (i = 0; i < 16u; i++)
        out_push(s->floats[i]);
    out_push(s->flag);
    return 1;
}

/* XZ edge cross — same formula as TGP 0x5c / slot_call. */
static float edge_cross_xz(float ox, float oz, float ix, float iz, float jx, float jz)
{
    return (jx - ix) * (oz - iz) - (jz - iz) * (ox - ix);
}

/*
 * Firmware sign test @ 0x60D–0x61A ($55 = 0x80000000):
 *   OR of sign bits clear → all positive/zero → hit
 *   AND of sign bits set → all negative → hit
 *   otherwise → mixed signs → next record
 *
 * Test the raw sign bits exactly as the TGP does. Float comparisons collapse
 * negative zero into zero and do not preserve the firmware's NaN sign test.
 */
static int tris_side(float ox, float oz, const float *xyz4, int nverts)
{
    unsigned i;
    u32 sign_or = 0u;
    u32 sign_and = 0x80000000u;

    for (i = 0; i < (unsigned)nverts; i++) {
        unsigned j = (i + 1u) % (unsigned)nverts;
        float c = edge_cross_xz(ox, oz, xyz4[i * 3u], xyz4[i * 3u + 2u],
                                xyz4[j * 3u], xyz4[j * 3u + 2u]);
        u32 sign = f2u(c) & 0x80000000u;

        sign_or |= sign;
        sign_and &= sign;
    }
    return (sign_or == 0u || sign_and != 0u) ? 1 : 0;
}

/*
 * Walk one directory entry (PC 0x5C3). Entry words:
 *   [0]=tri count, [1]=geom byte-off, [2]=attr byte-off, [3]=0
 * geom/attr → word addr via >>2 (bank 0x800000 + word).
 */
static int walk_entry(u32 entry_wa, float ox, float oz, u32 slot_arg)
{
    u32 count;
    u32 geom_b;
    u32 attr_b;
    u32 geom;
    u32 attr;
    u32 i;

    count = copro_ld(entry_wa);
    geom_b = copro_ld(entry_wa + 1u);
    attr_b = copro_ld(entry_wa + 2u);
    if (count == 0u || count > 0x10000u)
        return 0;
    geom = geom_b >> 2;
    attr = attr_b >> 2;

    for (i = 0; i < count; i++) {
        u32 floats[16];
        float xyz[12];
        u32 flag;
        unsigned k;
        int nverts;
        int side;

        for (k = 0; k < 16u; k++)
            floats[k] = copro_ld(geom + i * 16u + k);
        for (k = 0; k < 12u; k++)
            xyz[k] = u2f(floats[k]);

        flag = copro_ld(attr + i);
        /* attr & 4 → quad (4 edges); else triangle (3). PC 0x5F4–0x5F6. */
        nverts = (flag & 4u) ? 4 : 3;
        side = tris_side(ox, oz, xyz, nverts);
        if (side > 0) {
            model2_tgp_fw_slot_store(slot_arg, flag, floats);
            return 1;
        }
    }
    return 0;
}

/*
 * 0x52 @ 0x58A — nine-word bufferram block (table_index_a @ 0x2AC2C):
 *   [0..2] ox,oy,oz
 *   [3]    directory word addr (course row word1, e.g. 0x1ada0)
 *   [4]    count<<2 (segment count; unused by walk)
 *   [5]    prev<<2
 *   [6]    index<<2
 *   [7]    next<<2
 *   [8]    g3<<1 → slot arg
 *
 * PC 0x5A6: addd : mov d,$61 stores *pre-add* d (= 0x800000+dir) into $61,
 * call uses dir+index. Then try dir+next, dir+prev. Hit → slot {$63,$62}.
 */
int model2_tgp_fw_run_52(const u32 words[9])
{
    u32 dir;
    u32 slot_arg;
    float ox, oz;
    u32 try_off[3];
    unsigned t;

    if (words == NULL)
        return 0;
    if (g_copro == NULL && model2_tgp_fw_load_copro_data_default() != 0)
        return 0;

    ox = u2f(words[0]);
    oz = u2f(words[2]);
    dir = words[3];
    slot_arg = words[8];
    try_off[0] = words[6]; /* index<<2 */
    try_off[1] = words[7]; /* next<<2 */
    try_off[2] = words[5]; /* prev<<2 */

    for (t = 0; t < 3u; t++) {
        u32 entry_wa = dir + try_off[t];

        if (walk_entry(entry_wa, ox, oz, slot_arg))
            return 1;
    }

    model2_tgp_fw_slot_clear(slot_arg);
    return 0;
}
