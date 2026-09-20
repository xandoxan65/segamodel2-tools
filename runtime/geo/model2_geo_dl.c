/* C port of tools/model2_geo_dl.py — geo_process_command display-list runner. */

#include "model2_geo_dl.h"
#include "model2_geo_tex.h"
#include "model2_texture_rom.h"
#include "model2_host_aspect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { POLY_RAM_WORDS = 0x8000, TEX_RAM_WORDS = 0x10000, LOG_RAM_WORDS = 0x8000 };

void model2_geo_dl_ctx_init(model2_geo_dl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->polygon_ram0 = (u32 *)calloc(POLY_RAM_WORDS, sizeof(u32));
    ctx->polygon_ram1 = (u32 *)calloc(POLY_RAM_WORDS, sizeof(u32));
    ctx->texture_ram = (u16 *)calloc(TEX_RAM_WORDS, sizeof(u16));
    ctx->log_ram = (u32 *)calloc(LOG_RAM_WORDS, sizeof(u32));
}

void model2_geo_dl_ctx_free(model2_geo_dl_ctx_t *ctx)
{
    free(ctx->polygon_ram0);
    free(ctx->polygon_ram1);
    free(ctx->texture_ram);
    free(ctx->log_ram);
    memset(ctx, 0, sizeof(*ctx));
}

int model2_geo_dl_ctx_set_rom(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words)
{
    ctx->polygon_rom = words;
    ctx->polygon_rom_words = n_words;
    ctx->polygon_rom_mask = n_words ? (n_words - 1u) : 0u;
    return 0;
}

void model2_geo_dl_texture_data(model2_geo_dl_ctx_t *ctx, u32 address, u32 count,
                                const u32 *data)
{
    u32 i;

    if (!ctx || (count > 0u && !data))
        return;
    for (i = 0; i < count; i++) {
        u32 word = data[i];

        /* MAME raster path after geo_texture_data push — see DL cmd 0x04. */
        if (address & 0x800000u) {
            if (ctx->texture_ram)
                ctx->texture_ram[address & 0xffffu] = (u16)(word & 0xffffu);
        } else {
            if (ctx->log_ram)
                ctx->log_ram[address & 0x7fffu] = word;
        }
        address++;
    }
}

void model2_geo_dl_polygon_data(model2_geo_dl_ctx_t *ctx, u32 address, u32 count,
                                const u32 *data)
{
    u32 *dest;
    u32 addr;
    u32 i;

    if (!ctx || (count > 0u && !data))
        return;
    /* MAME model2_v.cpp geo_polygon_data */
    if (address & 0x01000000u) {
        dest = ctx->polygon_ram1;
        addr = address & 0x7FFFu;
    } else {
        dest = ctx->polygon_ram0;
        addr = address & 0x7FFFu;
    }
    if (!dest)
        return;
    if (addr >= POLY_RAM_WORDS)
        return;
    if (addr + count > POLY_RAM_WORDS)
        count = POLY_RAM_WORDS - addr;
    for (i = 0; i < count; i++)
        dest[addr + i] = data[i];
}

void model2_geo_dl_result_init(model2_geo_dl_result_t *r)
{
    memset(r, 0, sizeof(*r));
    model2_mesh_collector_init(&r->mesh);
}

void model2_geo_dl_result_free(model2_geo_dl_result_t *r)
{
    model2_mesh_collector_free(&r->mesh);
    free(r->objects);
    memset(r, 0, sizeof(*r));
}

/*
 * Raster command-buffer packing (MAME model2_v: push f2u>>8, read u2f(<<8)).
 * Polygon-ROM / geo_parse paths use model2_u2f on full IEEE words — not this.
 */
float model2_fixed24_to_float(u32 word)
{
    return model2_u2f((word & 0x00ffffffu) << 8);
}

int model2_is_polygon_rom_oba(u32 oba)
{
    if (oba & 0x01000000u)
        return 0;
    return (oba & 0xFF800000u) == 0x00800000u;
}

static int fail(model2_geo_dl_result_t *out, const char *msg)
{
    out->ok = 0;
    snprintf(out->error, sizeof(out->error), "%s", msg);
    return -1;
}

static int require(int index, int count, int end_limit)
{
    return index + count <= end_limit;
}

static int add_drawn(model2_geo_dl_result_t *out, int rom_offset, u32 oba, u32 obc,
                     unsigned vcount, int mode)
{
    if (out->objects_drawn >= out->objects_cap) {
        unsigned ncap = out->objects_cap ? out->objects_cap * 2u : 32u;
        model2_drawn_object_t *no =
            (model2_drawn_object_t *)realloc(out->objects, ncap * sizeof(*no));
        if (!no)
            return -1;
        out->objects = no;
        out->objects_cap = ncap;
    }
    out->objects[out->objects_drawn].rom_offset = rom_offset;
    out->objects[out->objects_drawn].oba = oba;
    out->objects[out->objects_drawn].obc = obc;
    out->objects[out->objects_drawn].vertex_count = vcount;
    out->objects[out->objects_drawn].mode = mode;
    out->objects_drawn++;
    return 0;
}

static int object_data(model2_geo_dl_ctx_t *ctx, model2_geo_state_t *geo, u32 opcode,
                       const u32 *words, int index, int end_limit,
                       model2_geo_dl_result_t *out)
{
    u32 tpa, tha, oba, obc;
    const u32 *rom;
    unsigned rom_n;
    u32 base;
    int count;
    int mode;
    model2_geo_state_t local_geo;
    model2_mesh_collector_t local;
    int rc;

    /*
     * MAME model2_3d_push(opcode>>23) then center_sel = (input>>6)&3.
     * Full opcode packs eye in bits 29..30 (geo_w: ((addr>>10)&3)<<29) —
     * Sega Rally car/course select bank poke @ 0x800010+(bank<<10).
     */
    geo->center_sel = (u16)((opcode >> 29) & 3u);
    /*
     * Encodings (MAME geo_object_data always reads 4 payload words):
     *   geo_w object opcode 0x00800000 + tpa,tha,oba,obc — catalog / pen with bank poke
     *   Legacy packed 0x008001xx|… as cmd+tpa, then tha,oba,obc — only if geo_w missing
     */
    if ((opcode & 0x007fffffu) == 0u) {
        if (!require(index, 4, end_limit))
            return fail(out, "object_data overflow");
        tpa = words[index];
        tha = words[index + 1];
        oba = words[index + 2];
        obc = words[index + 3];
        index += 4;
    } else {
        if (!require(index, 3, end_limit))
            return fail(out, "object_data overflow");
        tpa = opcode;
        tha = words[index];
        oba = words[index + 1];
        obc = words[index + 2];
        index += 3;
    }

    /*
     * MAME model2_v.cpp geo_object_data: RAM0 / RAM1 / ROM select, then
     *   if (obc == 0) obc = 0xfffff;  // rolls over — Virtual On & Gunblade NY
     * Host previously skipped RAM+obc==0; that dropped span_table / marker_burst
     * draws (texture_sync uploads into polygon RAM, emit with obc=0).
     */
    if (oba & 0x01000000u) {
        base = oba & 0x7FFFu;
        rom = ctx->polygon_ram1;
        rom_n = POLY_RAM_WORDS;
    } else if (oba & 0x00800000u) {
        base = oba & ctx->polygon_rom_mask;
        rom = ctx->polygon_rom;
        rom_n = ctx->polygon_rom_words;
    } else {
        base = oba & 0x7FFFu;
        rom = ctx->polygon_ram0;
        rom_n = POLY_RAM_WORDS;
    }

    if (!rom || rom_n == 0)
        return fail(out, "polygon ROM not loaded");

    count = (obc == 0) ? 0xFFFFF : (int)obc;
    mode = geo->mode & 3;
    model2_geo_state_copy(&local_geo, geo);
    model2_mesh_collector_init(&local);
    rc = model2_geo_parse_mode(&local_geo, mode, rom, rom_n, (int)base, count, &local);
    if (rc < 0 || local.n_verts == 0) {
        /*
         * MAME still consumes the object command; an empty/unparseable source
         * contributes no raster output. Do not abort the display list — that
         * would drop later catalog_span road draws after marker_burst.
         */
        if (!(oba & 0x00800000u)) {
            static unsigned s_ram_miss;

            if (s_ram_miss < 12u) {
                fprintf(stderr,
                        "lift: geo_object_data RAM miss oba=%#x obc=%#x base=%#x "
                        "mode=%d rc=%d verts=%u\n",
                        (unsigned)oba, (unsigned)obc, (unsigned)base, mode, rc,
                        local.n_verts);
                s_ram_miss++;
            }
        }
        model2_mesh_collector_free(&local);
        return index;
    }
    /*
     * Tach analog needle: catalog @ 0x02865130 → ROM 0x1a7a (obc=1). Drawn
     * after list_walk with T≈(−185,−127,128); world Z at the gauge hole is
     * closer, so a shared GL depth buffer hides it. Tag for overlay pass.
     */
    if (base == 0x1a7au && (oba & 0x00800000u)) {
        unsigned pi;
        static unsigned s_needle_log;

        for (pi = 0; pi < local.n_prims; pi++)
            local.prims[pi].hud_overlay = 1;
        if (s_needle_log < 4u) {
            fprintf(stderr,
                    "lift: tach needle obj base=%#x verts=%u prims=%u "
                    "T=(%.3g,%.3g,%.3g)\n",
                    (unsigned)base, local.n_verts, local.n_prims, geo->matrix[9],
                    geo->matrix[10], geo->matrix[11]);
            s_needle_log++;
        }
    }
    /*
     * Body-shell catalogs (BODY_SHELL_INDICES 96–99/106–107). Log several
     * draws: car-select is often identity R + T.z≈15; race/attract should
     * show view×pose (non-I R). vis≪export with identity R matches MAME
     * cull — not a cue to invent both-sides.
     */
    if ((oba & 0x00800000u) != 0) {
        static const unsigned body_bases[] = {
            /* Celica / liveries — catalog 96–99, 106–107 */
            0x1a8bu, 0x334cu, 0x4c0du, 0x64ceu, 0x85d9u, 0x9e9au,
            /* Delta — catalog 110–111, 118–119 (--practice Delta MT) */
            0xe8ddu, 0x1022au, 0x15599u, 0x1565eu
        };
        static unsigned s_body_logs;
        unsigned bi;

        for (bi = 0; bi < sizeof(body_bases) / sizeof(body_bases[0]); bi++) {
            int r_ident;
            unsigned vi, n_front = 0, n_vis = 0, n_exp = 0;

            if (base != body_bases[bi])
                continue;
            if (s_body_logs >= 12u)
                break;
            for (vi = 0; vi < local.n_prims; vi++) {
                const model2_mesh_prim_t *p = &local.prims[vi];

                if (!model2_mame_polygon_exportable(p->attr))
                    continue;
                n_exp++;
                if (p->front)
                    n_front++;
                if (model2_mame_polygon_visible(p->attr, p->front))
                    n_vis++;
            }
            r_ident = (geo->matrix[0] == 1.f && geo->matrix[4] == 1.f
                       && geo->matrix[8] == 1.f && geo->matrix[1] == 0.f
                       && geo->matrix[2] == 0.f && geo->matrix[3] == 0.f
                       && geo->matrix[5] == 0.f && geo->matrix[6] == 0.f
                       && geo->matrix[7] == 0.f);
            fprintf(stderr,
                    "lift: geo body-shell base=%#x export=%u front=%u vis=%u "
                    "mode=%d R=%s T=(%.4g,%.4g,%.4g) "
                    "c2=(%.3g,%.3g,%.3g)\n",
                    (unsigned)base, n_exp, n_front, n_vis, mode,
                    r_ident ? "I" : "non-I", geo->matrix[9], geo->matrix[10],
                    geo->matrix[11], geo->matrix[6], geo->matrix[7],
                    geo->matrix[8]);
            s_body_logs++;
            break;
        }
    }
    /* Attach UVs + palette ids — MAME texture_rom and/or texture_ram. */
    {
        const u16 *tex_rom = NULL;
        unsigned tex_n = 0;
        u32 tex_mask = 0;
        int need_rom = !(tpa & 0x800000u) || !(tha & 0x800000u);

        if (need_rom && model2_texture_rom_load_default() == 0) {
            tex_rom = model2_texture_rom_u16(&tex_n);
            tex_mask = model2_texture_rom_mask();
        }
        if ((tex_rom && tex_mask) || ctx->texture_ram) {
            model2_tex_state_t tex_st;
            model2_tex_state_init(&tex_st, tex_rom, tex_mask, ctx->texture_ram, tpa,
                                  tha);
            model2_mesh_apply_texture_state(&local, &tex_st, &local_geo);
        }
    }
    /*
     * Desert span_table / marker_burst poly-RAM objects (texture_sync slots).
     * Span emit is index-gated (@0x47920): slot3 when walk covers index 43
     * (forward span_a≈42–43 → emit_le; reverse wrap → emit_gt).
     * Slot3 (@0x7742, src 0x029e1f24): large roadside strip; all attrs
     * dside=0; stored normals anti-parallel to strip winding (~74/75).
     * Attract geo mode is NP_S (fifo_bootstrap → cmd 0x07 payload 1); MAME
     * face test uses stored n·p → vis≈0 from on-track cameras. Mode-3 NN
     * @ 0x32e0 has no call/bal xrefs — do not invent doubleside/NN. Slot4
     * is dside=1. Log gated — I960_GEO_RAM_LOG=1 / I960_GEO_SPAN_LOG=1.
     */
    if (!(oba & 0x00800000u)) {
        const char *ram_log = getenv("I960_GEO_RAM_LOG");

        if (ram_log && ram_log[0] && ram_log[0] != '0') {
            static unsigned s_ram_by_oba[8];
            unsigned slot_i = 0xffffu;
            unsigned vi;
            unsigned n_vis = 0, n_tex = 0, n_zok = 0, n_front = 0;

            if (base == 0x7c11u)
                slot_i = 0;
            else if (base == 0x7742u)
                slot_i = 3;
            else if (base == 0x76ffu)
                slot_i = 4;
            else if (base == 0x75b8u)
                slot_i = 5;
            else if (base == 0x7507u)
                slot_i = 6;
            else if (base == 0x74bau)
                slot_i = 7;
            if (slot_i < 8u)
                s_ram_by_oba[slot_i]++;
            for (vi = 0; vi < local.n_prims; vi++) {
                const model2_mesh_prim_t *p = &local.prims[vi];
                float pz = -1e30f;
                int k;

                if (p->front)
                    n_front++;
                if (model2_mame_polygon_visible(p->attr, p->front))
                    n_vis++;
                if (p->tex_valid)
                    n_tex++;
                for (k = 0; k < p->n_indices; k++) {
                    int ii = p->indices[k];
                    if (ii >= 0 && (unsigned)ii < local.n_verts
                        && local.verts[ii].z > pz)
                        pz = local.verts[ii].z;
                }
                if (pz > 0.f)
                    n_zok++;
            }
            if (slot_i < 8u && s_ram_by_oba[slot_i] <= 3u) {
                fprintf(stderr,
                        "lift: geo RAM slot=%u oba=%#x verts=%u prims=%u "
                        "front=%u vis=%u tex=%u zok=%u mtxT=(%.3g,%.3g,%.3g)\n",
                        slot_i, (unsigned)oba, local.n_verts, local.n_prims,
                        n_front, n_vis, n_tex, n_zok, geo->matrix[9],
                        geo->matrix[10], geo->matrix[11]);
            }
        }
    }
    /*
     * Car-select pose audit: per-object focal-space X after matrix+focus.
     * ROM @ 0x14820 has no per-slot TGP X — panel separation is baked in
     * the catalogs. Log once per process so we can see stacked vs L/C/R.
     */
    {
        static unsigned s_obj_span_log;
        unsigned vi;
        float xmin = local.verts[0].x, xmax = local.verts[0].x;
        float ymin = local.verts[0].y, ymax = local.verts[0].y;
        float zmin = local.verts[0].z, zmax = local.verts[0].z;
        float sx = 0.f;

        for (vi = 1; vi < local.n_verts; vi++) {
            float x = local.verts[vi].x, y = local.verts[vi].y,
                  z = local.verts[vi].z;
            if (x < xmin)
                xmin = x;
            if (x > xmax)
                xmax = x;
            if (y < ymin)
                ymin = y;
            if (y > ymax)
                ymax = y;
            if (z < zmin)
                zmin = z;
            if (z > zmax)
                zmax = z;
        }
        for (vi = 0; vi < local.n_verts; vi++)
            sx += local.verts[vi].x;
        sx /= (float)local.n_verts;
        /*
         * Always log car-select catalogs (disasm 0x14820): surrounds
         * 0x2e3ea/2f070/2e9c2, cars 0x2e13b/2ec1d/2e5b5, header 0x2e45c.
         * Otherwise the 24-slot attract cap hides the pose audit.
         */
        {
            int car_sel = (base == 0x2e3eau || base == 0x2f070u
                           || base == 0x2e9c2u || base == 0x2e13bu
                           || base == 0x2ec1du || base == 0x2e5b5u
                           || base == 0x2e45cu);
            if (car_sel || s_obj_span_log < 24u) {
                fprintf(stderr,
                        "lift: geo obj-span #%u base=%#x verts=%u "
                        "cx=%.4g x=(%.4g,%.4g) y=(%.4g,%.4g) z=(%.4g,%.4g) "
                        "T=(%.3g,%.3g,%.3g) eye=%u%s\n",
                        s_obj_span_log, base, local.n_verts, sx, xmin, xmax,
                        ymin, ymax, zmin, zmax, geo->matrix[9], geo->matrix[10],
                        geo->matrix[11], (unsigned)geo->center_sel,
                        car_sel ? " car_sel" : "");
                if (!car_sel)
                    s_obj_span_log++;
            }
        }
    }
    /* MAME center_sel vanishing point → bake into focal-space verts. */
    model2_geo_bake_center_sel(geo, &local);
    model2_mesh_collector_append(&out->mesh, &local);
    add_drawn(out, (int)base, oba, obc, local.n_verts, mode);
    model2_mesh_collector_free(&local);
    return index;
}

static int direct_data(model2_geo_state_t *geo, const u32 *words, int index, int end_limit,
                       model2_mesh_collector_t *collector, model2_geo_dl_result_t *out)
{
    int k;

    if (!require(index, 8, end_limit))
        return fail(out, "direct_data overflow");
    index += 2; /* tpa, tha */
    for (k = 0; k < 2; k++) {
        model2_poly_vertex_t p;
        /* Same as MAME geo_parse_* / model2_geo_parse: full IEEE floats. */
        p.x = model2_u2f(words[index]);
        p.y = model2_u2f(words[index + 1]);
        p.z = model2_u2f(words[index + 2]);
        index += 3;
        model2_transform_point(&p, geo->matrix);
        model2_apply_focus(geo, &p);
        model2_mesh_collector_add_vertex(collector, p.x, p.y, p.z);
    }

    while (index < end_limit) {
        u32 attr = words[index++];
        model2_poly_vertex_t p;
        if ((attr & 3u) == 0)
            break;
        if (!require(index, 5, end_limit))
            return fail(out, "direct_data link overflow");
        index += 2; /* luma, distance */
        p.x = model2_u2f(words[index]);
        p.y = model2_u2f(words[index + 1]);
        p.z = model2_u2f(words[index + 2]);
        index += 3;
        model2_transform_point(&p, geo->matrix);
        model2_apply_focus(geo, &p);
        model2_mesh_collector_add_vertex(collector, p.x, p.y, p.z);
        if (attr & 1u) {
            if (!require(index, 3, end_limit))
                return fail(out, "direct_data quad overflow");
            p.x = model2_u2f(words[index]);
            p.y = model2_u2f(words[index + 1]);
            p.z = model2_u2f(words[index + 2]);
            index += 3;
            model2_transform_point(&p, geo->matrix);
            model2_apply_focus(geo, &p);
            model2_mesh_collector_add_vertex(collector, p.x, p.y, p.z);
        }
    }
    return index;
}

static int dispatch(model2_geo_dl_ctx_t *ctx, int cmd, u32 opcode, model2_geo_state_t *geo,
                    const u32 *words, int index, int end_limit,
                    model2_geo_dl_result_t *out, int *done)
{
    *done = 0;
    switch (cmd) {
    case 0x01:
    case 0x11:
        return object_data(ctx, geo, opcode, words, index, end_limit, out);
    case 0x02:
    case 0x12:
        return direct_data(geo, words, index, end_limit, &out->mesh, out);
    case 0x03:
    case 0x13: {
        int i;
        int old_cx = 0, old_cy = 0, new_cx = 0, new_cy = 0;
        int had_eye = geo->window_valid;

        if (!require(index, 6, end_limit))
            return fail(out, "window_data overflow");
        if (had_eye)
            model2_geo_window_eye(geo, 0, &old_cx, &old_cy);
        for (i = 0; i < 6; i++)
            geo->window[i] = words[index + i];
        geo->window_valid = 1;
        model2_geo_window_eye(geo, 0, &new_cx, &new_cy);
        /*
         * Course select (0x15380): icons under bootstrap eyes (248,320), then
         * trapezoid 0x03 (≈100,256) for the spinner. GL publishes the final
         * eye0 — rebase earlier verts so sx = c0 + x/z still holds.
         */
        if (had_eye && out->mesh.n_verts > 0u
            && (old_cx != new_cx || old_cy != new_cy)) {
            static unsigned s_rebase_log;

            model2_geo_rebase_eye0(&out->mesh, old_cx, old_cy, new_cx, new_cy);
            if (s_rebase_log < 8u) {
                fprintf(stderr,
                        "lift: GEO 0x03 rebase eye0 (%d,%d)→(%d,%d) verts=%u\n",
                        old_cx, old_cy, new_cx, new_cy, out->mesh.n_verts);
                s_rebase_log++;
            }
        }
        return index + 6;
    }
    case 0x04: {
        /* MAME geo_texture_data → raster cmd 0x04 texture_ram / log_ram writes. */
        u32 address, count, i;
        if (!require(index, 2, end_limit))
            return fail(out, "texture_data overflow");
        address = words[index];
        count = words[index + 1];
        index += 2;
        if (!require(index, (int)count, end_limit))
            return fail(out, "texture_data body overflow");
        for (i = 0; i < count; i++) {
            u32 data = words[index + (int)i];
            if (address & 0x800000u) {
                if (ctx->texture_ram)
                    ctx->texture_ram[address & 0xffffu] = (u16)(data & 0xffffu);
            } else {
                if (ctx->log_ram)
                    ctx->log_ram[address & 0x7fffu] = data;
            }
            address++;
        }
        return index + (int)count;
    }
    case 0x05:
    case 0x15: {
        u32 address, count;
        u32 *dest;
        u32 addr;
        u32 i;
        if (!require(index, 2, end_limit))
            return fail(out, "polygon_data overflow");
        address = words[index];
        count = words[index + 1];
        index += 2;
        if (address & 0x01000000u) {
            dest = ctx->polygon_ram1;
            addr = address & 0x7FFFu;
        } else {
            dest = ctx->polygon_ram0;
            addr = address & 0x7FFFu;
        }
        if (!require(index, (int)count, end_limit))
            return fail(out, "polygon_data body overflow");
        if (addr + count > POLY_RAM_WORDS)
            return fail(out, "polygon_data write OOB");
        for (i = 0; i < count; i++)
            dest[addr + i] = words[index + (int)i];
        return index + (int)count;
    }
    case 0x06: {
        u32 tex_index, count, i;
        if (!require(index, 2, end_limit))
            return fail(out, "texture_parameters overflow");
        tex_index = words[index] >> 2;
        count = words[index + 1];
        index += 2;
        if (!require(index, (int)count * 2, end_limit))
            return fail(out, "texture_parameters body overflow");
        for (i = 0; i < count; i++) {
            u32 param = words[index++];
            geo->coef_table[tex_index & 0x1Fu] = model2_u2f(words[index++]);
            geo->texture_parameters[tex_index & 0x1Fu].diffuse = (float)(param & 0xFFu);
            geo->texture_parameters[tex_index & 0x1Fu].ambient =
                (float)((param >> 8) & 0xFFu);
            geo->texture_parameters[tex_index & 0x1Fu].specular_scale =
                (float)((param >> 16) & 0xFFu);
            geo->texture_parameters[tex_index & 0x1Fu].specular_control =
                (int)((param >> 24) & 0xFFu);
            tex_index = (tex_index + 1u) & 0x1Fu;
        }
        return index;
    }
    case 0x07:
    case 0x17:
        if (!require(index, 1, end_limit))
            return fail(out, "set_mode overflow");
        geo->mode = (int)words[index];
        return index + 1;
    case 0x08:
    case 0x18:
    case 0x10:
    case 0x1E:
        if (!require(index, 1, end_limit))
            return fail(out, "skip1 overflow");
        return index + 1;
    case 0x09:
    case 0x19:
        if (!require(index, 2, end_limit))
            return fail(out, "focal overflow");
        geo->focus.x = model2_u2f(words[index]);
        geo->focus.y = model2_u2f(words[index + 1]);
        model2_host_apply_fov_scale(&geo->focus.x, &geo->focus.y);
        return index + 2;
    case 0x0A:
    case 0x1A:
        if (!require(index, 3, end_limit))
            return fail(out, "light overflow");
        geo->light.x = model2_u2f(words[index]);
        geo->light.y = model2_u2f(words[index + 1]);
        geo->light.z = model2_u2f(words[index + 2]);
        return index + 3;
    case 0x0B:
    case 0x1B: {
        int i;
        if (!require(index, 12, end_limit))
            return fail(out, "matrix overflow");
        for (i = 0; i < 12; i++)
            geo->matrix[i] = model2_u2f(words[index + i]);
        return index + 12;
    }
    case 0x0C:
    case 0x1C:
        if (!require(index, 3, end_limit))
            return fail(out, "translate overflow");
        geo->matrix[9] = model2_u2f(words[index]);
        geo->matrix[10] = model2_u2f(words[index + 1]);
        geo->matrix[11] = model2_u2f(words[index + 2]);
        return index + 3;
    case 0x0D: {
        u32 count;
        if (!require(index, 2, end_limit))
            return fail(out, "data_mem_push overflow");
        count = words[index + 1];
        if (!require(index, 2 + (int)count, end_limit))
            return fail(out, "data_mem_push body overflow");
        return index + 2 + (int)count;
    }
    case 0x0E: {
        u32 blocks, b;
        if (!require(index, 34, end_limit))
            return fail(out, "geo_test overflow");
        index += 33;
        blocks = words[index++];
        for (b = 0; b < blocks; b++) {
            u32 count;
            if (!require(index, 3, end_limit))
                return fail(out, "geo_test block overflow");
            count = words[index + 1];
            index += 3;
            index += (int)count;
        }
        return index;
    }
    case 0x0F:
    case 0x1F:
        *done = 1;
        return index;
    case 0x14: {
        u32 count;
        if (!require(index, 2, end_limit))
            return fail(out, "log_data overflow");
        count = words[index + 1];
        if (!require(index, 2 + (int)count, end_limit))
            return fail(out, "log_data body overflow");
        return index + 2 + (int)count;
    }
    case 0x16:
        if (!require(index, 1, end_limit))
            return fail(out, "lod overflow");
        geo->lod = model2_u2f(words[index]);
        return index + 1;
    case 0x1D: {
        u32 count;
        if (!require(index, 2, end_limit))
            return fail(out, "code_upload overflow");
        count = words[index + 1];
        if (!require(index, 2 + (int)count * 3, end_limit))
            return fail(out, "code_upload body overflow");
        return index + 2 + (int)count * 3;
    }
    case 0x00:
        return index;
    default:
        snprintf(out->error, sizeof(out->error), "unknown geo command 0x%x", cmd);
        out->ok = 0;
        return -1;
    }
}

int model2_geo_dl_run(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                      int start, int require_end, unsigned max_ops,
                      model2_geo_dl_result_t *out)
{
    return model2_geo_dl_run_mtx(ctx, words, n_words, start, require_end, max_ops, NULL, out);
}

int model2_geo_dl_run_mtx(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                          int start, int require_end, unsigned max_ops,
                          const float *initial_matrix, model2_geo_dl_result_t *out)
{
    model2_geo_state_t geo;
    int index = start;
    int end_limit;
    unsigned ops = 0;
    int finished = 0;

    if (!out)
        return -1;
    model2_geo_dl_result_free(out);
    model2_geo_dl_result_init(out);
    out->start_word = start;

    if (!words || start < 0 || (unsigned)start >= n_words)
        return fail(out, "bad start");

    model2_geo_state_init(&geo);
    if (initial_matrix)
        memcpy(geo.matrix, initial_matrix, 12u * sizeof(float));
    if (max_ops == 0)
        max_ops = 0x8000u;
    end_limit = (int)n_words;
    if (end_limit > start + 0x8000)
        end_limit = start + 0x8000;

    while (index < end_limit && ops < max_ops && !finished) {
        u32 opcode = words[index++];
        int cmd;
        int done = 0;
        int next;

        ops++;
        if (opcode & 0x80000000u) {
            int jump = (int)((opcode & 0x1FFFFu) / 4u);
            if (jump < 0 || (unsigned)jump >= n_words)
                return fail(out, "jump out of range");
            index = jump;
            continue;
        }
        cmd = (int)((opcode >> 23) & 0x1Fu);
        next = dispatch(ctx, cmd, opcode, &geo, words, index, end_limit, out, &done);
        if (next < 0)
            return -1;
        index = next;
        if (done)
            finished = 1;
    }

    out->finished = finished;
    out->words_consumed = index - start;
    out->commands_executed = ops;
    if (require_end && !finished)
        return fail(out, "display list did not reach geo_end");
    out->ok = 1;
    return 0;
}

int model2_geo_dl_run_stream_state(model2_geo_dl_ctx_t *ctx, const u32 *words,
                                   unsigned n_words, const float *per_word_mtx,
                                   unsigned mtx_words, model2_geo_state_t *state,
                                   model2_geo_dl_result_t *out)
{
    model2_geo_state_t local_geo;
    model2_geo_state_t *geo = state ? state : &local_geo;
    int index = 0;
    int end_limit;
    unsigned ops = 0;
    int finished = 0;

    if (!out)
        return -1;
    model2_geo_dl_result_free(out);
    model2_geo_dl_result_init(out);
    out->start_word = 0;

    if (!words || n_words == 0)
        return fail(out, "empty stream");

    if (!state)
        model2_geo_state_init(geo);
    end_limit = (int)n_words;
    if (end_limit > 0x8000)
        end_limit = 0x8000;

    while (index < end_limit && ops < 0x8000u && !finished) {
        int op_index = index;
        u32 opcode = words[index++];
        int cmd;
        int done = 0;
        int next;

        ops++;
        if (opcode & 0x80000000u) {
            int jump = (int)((opcode & 0x1FFFFu) / 4u);
            if (jump < 0 || (unsigned)jump >= n_words)
                return fail(out, "jump out of range");
            index = jump;
            continue;
        }
        cmd = (int)((opcode >> 23) & 0x1Fu);
        /*
         * MAME geo_parse: object draws use geo->matrix from the last stream
         * command 0x0B (TGP 0x05 / 0x55 → geo_matrix_write). Do not overwrite
         * with the TGP working-matrix snapshot — 0x55 restores the view after
         * emit, so the snapshot at the following object opcode is the camera,
         * not the dust/object pose (dust landed at T≈−77k).
         */
        (void)per_word_mtx;
        (void)mtx_words;
        (void)op_index;

        next = dispatch(ctx, cmd, opcode, geo, words, index, end_limit, out, &done);
        if (next < 0) {
            /* Soft: stop at first hard failure rather than discard the mesh. */
            if (out->objects_drawn > 0) {
                out->ok = 1;
                out->finished = finished;
                out->words_consumed = index;
                out->commands_executed = ops;
                return 0;
            }
            return -1;
        }
        index = next;
        if (done)
            finished = 1;
    }

    out->finished = finished;
    out->words_consumed = index;
    out->commands_executed = ops;
    out->ok = 1;
    return 0;
}

int model2_geo_dl_run_stream(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                             const float *per_word_mtx, unsigned mtx_words,
                             model2_geo_dl_result_t *out, float focus_xy_out[2])
{
    model2_geo_state_t state;
    int rc;

    model2_geo_state_init(&state);
    rc = model2_geo_dl_run_stream_state(ctx, words, n_words, per_word_mtx, mtx_words,
                                       &state, out);
    if (focus_xy_out) {
        focus_xy_out[0] = state.focus.x;
        focus_xy_out[1] = state.focus.y;
    }
    return rc;
}
