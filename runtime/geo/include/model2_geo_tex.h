/* MAME-referenced texheader / texel / palette helpers for host OpenGL geo. */
#ifndef MODEL2_GEO_TEX_H
#define MODEL2_GEO_TEX_H

#include "model2_geo_parse.h"

enum {
    MODEL2_GEO_SHEET_W = 2048,
    MODEL2_GEO_SHEET_H = 1024,
    MODEL2_GEO_TEX_CUTOUT = 1u,
    MODEL2_GEO_TEX_CHECKER = 2u,
    MODEL2_GEO_TEX_TEXTURED = 4u,
    MODEL2_GEO_TEX_WRAP_X = 8u,
    MODEL2_GEO_TEX_WRAP_Y = 16u,
    MODEL2_GEO_TEX_MIRROR_X = 32u,
    MODEL2_GEO_TEX_MIRROR_Y = 64u
};

typedef struct {
    const u16 *rom;
    u32 rom_mask;
    /* MAME raster_state.texture_ram — used when tpa/tha bit 0x800000 set. */
    const u16 *ram;
    u32 tpa;
    u32 tha;
} model2_tex_state_t;

typedef struct {
    u16 words[4];
    int valid;
} model2_tex_header_t;

void model2_tex_state_init(model2_tex_state_t *st, const u16 *rom, u32 rom_mask,
                           const u16 *ram, u32 tpa, u32 tha);

/*
 * Advance tpa/tha for every prim (including non-exportable), fill tex fields.
 * geo supplies light / texture_parameters used at polygon parse for luminance
 * (MAME model2_v.cpp). apply_texture_state only fills tp/th UV + headers.
 */
void model2_mesh_apply_texture_state(model2_mesh_collector_t *mesh, model2_tex_state_t *st,
                                     const model2_geo_state_t *geo);

/* MAME model2rd.ipp get_texel — sheet is u32 words (textureram / main_data bank). */
u16 model2_get_texel(const u32 *sheet, u32 base_x, u32 base_y, int x, int y);

/* Decode logical 2048x1024 R8 indices (0..15) from a 2 MiB sheet bank. */
void model2_decode_sheet_indices(const u32 *sheet, u8 *out_r8 /* W*H */);

/*
 * MAME draw_scanline_tex color math (nearest, luma scale), no CRT gamma_table.
 * translucent: only then is texel 0xF discarded (MAME Translucent template).
 */
void model2_palette_lookup_texel(u32 texel, u32 colorbase, u32 lumabase, u32 poly_luma,
                                 int translucent, u8 out_rgba[4]);

/* Solid path: draw_scanline_solid (luma>>2), no CRT gamma. */
void model2_palette_lookup_solid(u32 colorbase, u32 poly_luma, u8 out_rgb[3]);

/* Build 16-entry RGBA LUT for one (colorbase, lumabase, luma, translucent). */
void model2_palette_build_texel_lut(u32 colorbase, u32 lumabase, u32 poly_luma,
                                    int translucent, u8 lut_rgba[16 * 4]);

/* Prefer textureram; if empty, seed from main_data sheet banks. */
const u32 *model2_tex_sheet_bank(unsigned sheet_index /* 0 or 1 */);

/* Bump when textureram contents change (texture_bank_select DMA pump). */
void model2_tex_sheets_mark_dirty(void);
u32 model2_tex_sheets_dirty_gen(void);

/* Cheap signature of palette RAM that feeds the texel LUT (for GL cache). */
u32 model2_palette_state_sig(void);

/* Optional: verify nearest LUT vs MAME formula on current lifted RAM. */
void model2_palette_selftest(void);

#endif

