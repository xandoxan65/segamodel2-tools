/* Texheader / UV / palette — operator contracts from MAME model2_v / model2rd. */

#include "model2_geo_tex.h"
#include "model2_geo_hw.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int header_tho_words(u32 attr)
{
    int tho = (int)((attr >> 12) & 0x1fu);
    if (tho & 0x10)
        tho |= -16;
    return tho;
}

static u16 tex_read_tpa(const model2_tex_state_t *st)
{
    /* MAME model2_v.cpp: bit 0x800000 → texture_ram, else texture_rom. */
    if (st->tpa & 0x800000u) {
        if (!st->ram)
            return 0;
        return st->ram[st->tpa & 0xffffu];
    }
    if (!st->rom || st->rom_mask == 0)
        return 0;
    return st->rom[st->tpa & st->rom_mask];
}

static u16 tex_read_tha(const model2_tex_state_t *st, u32 off)
{
    if (st->tha & 0x800000u) {
        if (!st->ram)
            return 0;
        return st->ram[(st->tha + off) & 0xffffu];
    }
    if (!st->rom || st->rom_mask == 0)
        return 0;
    return st->rom[(st->tha + off) & st->rom_mask];
}

static void tex_advance_tpa(model2_tex_state_t *st, u32 n)
{
    if (st->tpa & 0x800000u)
        st->tpa = 0x800000u | ((st->tpa + n) & 0xffffu);
    else if (st->rom_mask)
        st->tpa = (st->tpa + n) & st->rom_mask;
    else
        st->tpa += n;
}

static void tex_advance_tha(model2_tex_state_t *st, int delta)
{
    if (st->tha & 0x800000u)
        st->tha = 0x800000u | ((u32)((int)st->tha + delta) & 0xffffu);
    else if (st->rom_mask)
        st->tha = (u32)((int)st->tha + delta) & st->rom_mask;
    else
        st->tha = (u32)((int)st->tha + delta);
}

void model2_tex_state_init(model2_tex_state_t *st, const u16 *rom, u32 rom_mask,
                           const u16 *ram, u32 tpa, u32 tha)
{
    memset(st, 0, sizeof(*st));
    st->rom = rom;
    st->rom_mask = rom_mask;
    st->ram = ram;
    /* Keep 0x800000 — MAME selects ram vs rom from this bit. */
    st->tpa = tpa;
    st->tha = tha;
}

static void read_header(model2_tex_state_t *st, u32 attr, model2_tex_header_t *out)
{
    int tho;
    unsigned i;

    for (i = 0; i < 4u; i++)
        out->words[i] = tex_read_tha(st, i);
    out->valid = !(out->words[0] == 0xffffu
                   || (out->words[0] == 0 && out->words[2] == 0));
    tho = header_tho_words(attr);
    tex_advance_tha(st, tho * 4);
}

static void consume_uv_pairs(model2_tex_state_t *st, int count, u16 *pu, u16 *pv)
{
    int i;

    for (i = 0; i < count; i++) {
        pv[i] = tex_read_tpa(st);
        tex_advance_tpa(st, 1u);
        pu[i] = tex_read_tpa(st);
        tex_advance_tpa(st, 1u);
    }
}

static void uv_from_header(const model2_tex_header_t *h, u16 pu, u16 pv, float *u,
                           float *v)
{
    /*
     * Patch-local pixels (pu/8, pv/8). MAME fetch_bilinear_texel wraps with
     * (u>>8)&(tex_w-1) inside the patch before get_texel(base,…). Absolute
     * sheet UVs bleed neighboring atlas tiles (trees on road, sky on dirt).
     */
    *u = (float)pu / 8.f;
    *v = (float)pv / 8.f;
    (void)h;
}

/* MAME model2_v.cpp: poly luma is computed at parse (pre-focus). Keep it. */

void model2_mesh_apply_texture_state(model2_mesh_collector_t *mesh, model2_tex_state_t *st,
                                     const model2_geo_state_t *geo)
{
    unsigned i;

    if (!mesh || !st)
        return;
    (void)geo; /* luminance already baked at parse (MAME geo_parse_*) */
    /* Need ROM and/or RAM depending on tpa/tha bits (MAME). */
    if (!st->rom && !st->ram)
        return;

    for (i = 0; i < mesh->n_prims; i++) {
        model2_mesh_prim_t *p = &mesh->prims[i];
        int count = (p->attr & 1u) ? 4 : 3;
        u16 pu[4], pv[4];
        model2_tex_header_t hdr;
        int k;
        u8 renderer;
        u32 colorbase, lumabase;

        /* MAME reads tp/th before culling — always advance. */
        consume_uv_pairs(st, count, pu, pv);
        read_header(st, p->attr, &hdr);

        p->tex_valid = 0;
        p->tex_flags = 0;
        p->sheet = 0;
        p->colorbase = 0;
        p->lumabase = 0;
        p->patch_x = 0;
        p->patch_y = 0;
        p->patch_w = 32;
        p->patch_h = 32;
        for (k = 0; k < MODEL2_MESH_MAX_INDICES; k++) {
            p->u[k] = 0.f;
            p->v[k] = 0.f;
        }

        if (!hdr.valid) {
            /* MAME still consumed th; no header fields — color from attr. */
            p->colorbase = (u16)((p->attr >> 16) & 0x3ffu);
            p->tex_valid = 1;
            continue;
        }

        /*
         * Renderer/lumabase from texheader (MAME model2_3d_render). Colorbase:
         * header words[3]>>6 when non-zero; else polygon attr>>16 (srally solid
         * body/spoiler headers often store 0 there — Celica high-Y solids use
         * attr pens 276/148/…; header-only → palram[0x1000] black).
         * Renderer 0 = solid (not textured); do not force textured on those.
         */
        renderer = (u8)((hdr.words[0] >> 13) & 3u);
        lumabase = ((u32)(hdr.words[1] & 0xffu)) << 7;
        colorbase = (hdr.words[3] >> 6) & 0x3ffu;
        if (colorbase == 0u)
            colorbase = (p->attr >> 16) & 0x3ffu;

        p->colorbase = (u16)colorbase;
        p->lumabase = (u16)lumabase;
        p->sheet = (hdr.words[2] & 0x1000u) ? 1u : 0u;
        p->patch_w = (u16)(32u << (hdr.words[0] & 7u));
        p->patch_h = (u16)(32u << ((hdr.words[0] >> 3) & 7u));
        p->patch_x = (u16)((32 * (int)(hdr.words[2] & 0x3fu) - 2048) & 2047);
        p->patch_y = (u16)((32 * (int)((hdr.words[2] >> 6) & 0x1fu) - 1024) & 1023);
        p->tex_flags = 0;
        if (renderer & 2u)
            p->tex_flags |= MODEL2_GEO_TEX_TEXTURED;
        if (renderer & 1u)
            p->tex_flags |= MODEL2_GEO_TEX_CUTOUT;
        if ((hdr.words[0] >> 15) & 1u)
            p->tex_flags |= MODEL2_GEO_TEX_CHECKER;
        /* MAME: wrap disabled when mirror set. */
        if (((hdr.words[0] >> 8) & 1u) != 0)
            p->tex_flags |= MODEL2_GEO_TEX_MIRROR_X;
        else if (((hdr.words[0] >> 6) & 1u) != 0)
            p->tex_flags |= MODEL2_GEO_TEX_WRAP_X;
        if (((hdr.words[0] >> 9) & 1u) != 0)
            p->tex_flags |= MODEL2_GEO_TEX_MIRROR_Y;
        else if (((hdr.words[0] >> 7) & 1u) != 0)
            p->tex_flags |= MODEL2_GEO_TEX_WRAP_Y;

        if (p->tex_flags & MODEL2_GEO_TEX_TEXTURED) {
            for (k = 0; k < count; k++)
                uv_from_header(&hdr, pu[k], pv[k], &p->u[k], &p->v[k]);
        }
        p->tex_valid = 1;
    }
}

u16 model2_get_texel(const u32 *sheet, u32 base_x, u32 base_y, int x, int y)
{
    int x2 = (int)base_x + x;
    int y2 = (int)base_y + y;
    u32 offset;
    u32 texel;

    if (x2 >= 1024) {
        x2 -= 1024;
        y2 ^= 1024;
    }
    offset = ((u32)(y2 / 2) * 512u) + (u32)(x2 / 2);
    texel = sheet[offset >> 1];
    if (offset & 1u)
        texel >>= 16;
    if ((y & 1) == 0)
        texel >>= 8;
    if ((x & 1) == 0)
        texel >>= 4;
    return (u16)(texel & 0x0fu);
}

void model2_decode_sheet_indices(const u32 *sheet, u8 *out_r8)
{
    int y, x;

    if (!sheet || !out_r8)
        return;
    for (y = 0; y < MODEL2_GEO_SHEET_H; y++) {
        for (x = 0; x < MODEL2_GEO_SHEET_W; x++)
            out_r8[y * MODEL2_GEO_SHEET_W + x] =
                (u8)model2_get_texel(sheet, 0, 0, x, y);
    }
}

static void colorxlat_rgb(u32 color15, u32 luma_idx, u8 out_rgb[3])
{
    const model2_geo_hw_ops_t *hw = model2_geo_hw();
    const u16 *cx = (hw && hw->colorxlat) ? (const u16 *)hw->colorxlat() : NULL;
    u32 r_bank, g_bank, b_bank;

    if (!cx) {
        out_rgb[0] = out_rgb[1] = out_rgb[2] = 0;
        return;
    }
    color15 &= 0x7fffu;
    r_bank = ((color15 >> 0) & 0x1fu) << 8;
    g_bank = ((color15 >> 5) & 0x1fu) << 8;
    b_bank = ((color15 >> 10) & 0x1fu) << 8;
    /* Byte offsets 0x0000 / 0x4000 / 0x8000 → word offsets 0 / 0x2000 / 0x4000. */
    out_rgb[0] = (u8)(cx[0x0000u / 2u + r_bank + luma_idx] & 0xffu);
    out_rgb[1] = (u8)(cx[0x4000u / 2u + g_bank + luma_idx] & 0xffu);
    out_rgb[2] = (u8)(cx[0x8000u / 2u + b_bank + luma_idx] & 0xffu);
}

static u16 palram_colorbase(u32 colorbase)
{
    const model2_geo_hw_ops_t *hw = model2_geo_hw();
    const u16 *pal = (hw && hw->palram) ? (const u16 *)hw->palram() : NULL;
    if (!pal)
        return 0;
    return pal[(colorbase + 0x1000u) & 0x1fffu] & 0x7fffu;
}

void model2_palette_lookup_texel(u32 texel, u32 colorbase, u32 lumabase, u32 poly_luma,
                                 int translucent, u8 out_rgba[4])
{
    const model2_geo_hw_ops_t *hw = model2_geo_hw();
    const u8 *luma_ram = (hw && hw->lumaram) ? hw->lumaram() : NULL;
    u32 t = (texel & 0x0fu) << 4; /* nearest: match filtered scale */
    u32 luma;
    u8 rgb[3];

    /*
     * MAME model2rd.ipp: only the Translucent textured path discards texel 0xF
     * (<<4 → 0xF0). Opaque textured polys still index lumaram with t=0xF0.
     */
    if (translucent && (texel & 0x0fu) == 0x0fu) {
        out_rgba[0] = out_rgba[1] = out_rgba[2] = 0;
        out_rgba[3] = 0;
        return;
    }
    if (!luma_ram) {
        out_rgba[0] = out_rgba[1] = out_rgba[2] = 0;
        out_rgba[3] = 255;
        return;
    }
    /* MAME: lumaram[lumabase + (t >> 1)] * object.luma / 256 */
    luma = (u32)luma_ram[(lumabase + (t >> 1)) & (MODEL2_GEO_LUMARAM_SIZE - 1u)];
    luma = (luma * (poly_luma & 0xffu)) / 256u;
    if (luma > 0x3fu)
        luma = 0x3fu;
    colorxlat_rgb(palram_colorbase(colorbase), luma, rgb);
    out_rgba[0] = rgb[0];
    out_rgba[1] = rgb[1];
    out_rgba[2] = rgb[2];
    out_rgba[3] = 255;
}

void model2_palette_lookup_solid(u32 colorbase, u32 poly_luma, u8 out_rgb[3])
{
    u32 luma = (poly_luma & 0xffu) >> 2;
    if (luma > 0x3fu)
        luma = 0x3fu;
    colorxlat_rgb(palram_colorbase(colorbase), luma, out_rgb);
}

void model2_palette_build_texel_lut(u32 colorbase, u32 lumabase, u32 poly_luma,
                                    int translucent, u8 lut_rgba[16 * 4])
{
    u32 t;
    for (t = 0; t < 16u; t++)
        model2_palette_lookup_texel(t, colorbase, lumabase, poly_luma, translucent,
                                    &lut_rgba[t * 4u]);
}

static u32 g_sheets_dirty_gen;

void model2_tex_sheets_mark_dirty(void)
{
    g_sheets_dirty_gen++;
}

u32 model2_tex_sheets_dirty_gen(void)
{
    return g_sheets_dirty_gen;
}

const u32 *model2_tex_sheet_bank(unsigned sheet_index)
{
    static int seeded;
    const model2_geo_hw_ops_t *hw = model2_geo_hw();
    u8 *tex0 = (hw && hw->textureram0) ? hw->textureram0() : NULL;
    u8 *tex1 = (hw && hw->textureram1) ? hw->textureram1() : NULL;
    const u8 *md;
    unsigned i;
    int nonempty = 0;

    if (!tex0 || !tex1)
        return NULL;

    /* Fallback seed only when textureram is still empty (pre-bank-select). */
    if (!seeded) {
        for (i = 0; i < 256u; i++) {
            if (tex0[i] | tex1[i]) {
                nonempty = 1;
                break;
            }
        }
        if (!nonempty && hw->texture_sheet_rom) {
            md = hw->texture_sheet_rom(0);
            if (md)
                memcpy(tex0, md, MODEL2_GEO_TEXTURERAM_BANK_SIZE);
            md = hw->texture_sheet_rom(1);
            if (md)
                memcpy(tex1, md, MODEL2_GEO_TEXTURERAM_BANK_SIZE);
        }
        seeded = 1;
    }

    return (const u32 *)(sheet_index ? tex1 : tex0);
}

u32 model2_palette_state_sig(void)
{
    const model2_geo_hw_ops_t *hw = model2_geo_hw();
    const u16 *pal = (hw && hw->palram) ? (const u16 *)hw->palram() : NULL;
    const u16 *cx = (hw && hw->colorxlat) ? (const u16 *)hw->colorxlat() : NULL;
    const u8 *lu = (hw && hw->lumaram) ? hw->lumaram() : NULL;
    u32 sig = 0;
    unsigned i;

    if (pal) {
        /* Full colorbase region — desert env cbs are often ≥64 (e.g. 170/296/239). */
        for (i = 0; i < 0x400u; i++)
            sig = sig * 131u + (u32)pal[0x1000u + i];
        for (i = 0; i < 32u; i++)
            sig = sig * 131u + (u32)pal[i * 37u];
    }
    if (cx) {
        for (i = 0; i < 32u; i++)
            sig = sig * 131u + (u32)cx[i * 251u];
    }
    if (lu) {
        for (i = 0; i < 64u; i++)
            sig = sig * 131u + (u32)lu[i * 127u];
    }
    return sig;
}

void model2_palette_selftest(void)
{
    u8 a[4], b[4];
    u8 lut[16 * 4];
    u32 t;
    int mismatch = 0;

    /* Identity check: LUT entry t matches lookup_texel(t). */
    model2_palette_build_texel_lut(0, 0, 255, 0, lut);
    for (t = 0; t < 16u; t++) {
        model2_palette_lookup_texel(t, 0, 0, 255, 0, a);
        b[0] = lut[t * 4u + 0u];
        b[1] = lut[t * 4u + 1u];
        b[2] = lut[t * 4u + 2u];
        b[3] = lut[t * 4u + 3u];
        if (a[0] != b[0] || a[1] != b[1] || a[2] != b[2] || a[3] != b[3])
            mismatch++;
    }
    fprintf(stderr, "lift: palette LUT selftest mismatches=%d (cb0/lb0)\n", mismatch);
}
