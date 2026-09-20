/* C port of tools/model2_geo.py — MAME model2_v.cpp polygon parsers. */

#include "model2_geo_parse.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

void model2_identity_matrix(float m[12])
{
    m[0] = 1.f;
    m[1] = 0.f;
    m[2] = 0.f;
    m[3] = 0.f;
    m[4] = 1.f;
    m[5] = 0.f;
    m[6] = 0.f;
    m[7] = 0.f;
    m[8] = 1.f;
    m[9] = 0.f;
    m[10] = 0.f;
    m[11] = 0.f;
}

void model2_geo_state_init(model2_geo_state_t *geo)
{
    int i;

    memset(geo, 0, sizeof(*geo));
    model2_identity_matrix(geo->matrix);
    geo->focus.x = 1.f;
    geo->focus.y = 1.f;
    geo->focus.z = 0.f;
    geo->light.x = 0.f;
    geo->light.y = 0.f;
    geo->light.z = 1.f;
    geo->lod = 1.f;
    for (i = 0; i < 32; i++) {
        geo->texture_parameters[i].diffuse = 128.f;
        geo->texture_parameters[i].ambient = 0.f;
        geo->coef_table[i] = 1.f;
    }
}

void model2_geo_state_copy(model2_geo_state_t *dst, const model2_geo_state_t *src)
{
    *dst = *src;
}

void model2_mesh_collector_init(model2_mesh_collector_t *c)
{
    memset(c, 0, sizeof(*c));
}

void model2_mesh_collector_reset(model2_mesh_collector_t *c)
{
    c->n_verts = 0;
    c->n_prims = 0;
}

void model2_mesh_collector_free(model2_mesh_collector_t *c)
{
    free(c->verts);
    free(c->prims);
    memset(c, 0, sizeof(*c));
}

int model2_mesh_collector_add_vertex(model2_mesh_collector_t *c, float x, float y, float z)
{
    if (c->n_verts >= c->verts_cap) {
        unsigned ncap = c->verts_cap ? c->verts_cap * 2u : 256u;
        model2_poly_vertex_t *nv =
            (model2_poly_vertex_t *)realloc(c->verts, ncap * sizeof(*nv));
        if (!nv)
            return -1;
        c->verts = nv;
        c->verts_cap = ncap;
    }
    c->verts[c->n_verts].x = x;
    c->verts[c->n_verts].y = y;
    c->verts[c->n_verts].z = z;
    return (int)c->n_verts++;
}

int model2_mesh_collector_add_prim(model2_mesh_collector_t *c, u32 attr,
                                   const int *indices, int n_indices,
                                   float nx, float ny, float nz, int front,
                                   u8 poly_luma)
{
    model2_mesh_prim_t *p;
    int i;

    if (n_indices < 3 || n_indices > MODEL2_MESH_MAX_INDICES)
        return -1;
    if (c->n_prims >= c->prims_cap) {
        unsigned ncap = c->prims_cap ? c->prims_cap * 2u : 256u;
        model2_mesh_prim_t *np =
            (model2_mesh_prim_t *)realloc(c->prims, ncap * sizeof(*np));
        if (!np)
            return -1;
        c->prims = np;
        c->prims_cap = ncap;
    }
    p = &c->prims[c->n_prims++];
    memset(p, 0, sizeof(*p));
    p->n_indices = n_indices;
    for (i = 0; i < n_indices; i++)
        p->indices[i] = indices[i];
    p->attr = attr;
    p->nx = nx;
    p->ny = ny;
    p->nz = nz;
    p->front = front;
    p->poly_luma = poly_luma;
    return 0;
}

void model2_mesh_prim_copy_tex(model2_mesh_prim_t *dst, const model2_mesh_prim_t *src)
{
    int k;

    if (!dst || !src)
        return;
    dst->tex_valid = src->tex_valid;
    dst->colorbase = src->colorbase;
    dst->lumabase = src->lumabase;
    dst->patch_x = src->patch_x;
    dst->patch_y = src->patch_y;
    dst->patch_w = src->patch_w;
    dst->patch_h = src->patch_h;
    dst->sheet = src->sheet;
    dst->tex_flags = src->tex_flags;
    dst->poly_luma = src->poly_luma;
    dst->hud_overlay = src->hud_overlay;
    for (k = 0; k < MODEL2_MESH_MAX_INDICES; k++) {
        dst->u[k] = src->u[k];
        dst->v[k] = src->v[k];
    }
}

void model2_mesh_collector_append(model2_mesh_collector_t *dst,
                                  const model2_mesh_collector_t *src)
{
    unsigned base = dst->n_verts;
    unsigned i;

    for (i = 0; i < src->n_verts; i++)
        model2_mesh_collector_add_vertex(dst, src->verts[i].x, src->verts[i].y,
                                         src->verts[i].z);
    for (i = 0; i < src->n_prims; i++) {
        int idx[MODEL2_MESH_MAX_INDICES];
        int j;
        unsigned di;
        for (j = 0; j < src->prims[i].n_indices; j++)
            idx[j] = src->prims[i].indices[j] + (int)base;
        di = dst->n_prims;
        model2_mesh_collector_add_prim(dst, src->prims[i].attr, idx,
                                       src->prims[i].n_indices, src->prims[i].nx,
                                       src->prims[i].ny, src->prims[i].nz,
                                       src->prims[i].front, src->prims[i].poly_luma);
        if (dst->n_prims > di)
            model2_mesh_prim_copy_tex(&dst->prims[di], &src->prims[i]);
    }
}

void model2_transform_point(model2_poly_vertex_t *p, const float matrix[12])
{
    float x = p->x, y = p->y, z = p->z;
    p->x = (x * matrix[0]) + (y * matrix[3]) + (z * matrix[6]) + matrix[9];
    p->y = (x * matrix[1]) + (y * matrix[4]) + (z * matrix[7]) + matrix[10];
    p->z = (x * matrix[2]) + (y * matrix[5]) + (z * matrix[8]) + matrix[11];
}

void model2_transform_vector(model2_poly_vertex_t *v, const float matrix[12])
{
    float x = v->x, y = v->y, z = v->z;
    v->x = (x * matrix[0]) + (y * matrix[3]) + (z * matrix[6]);
    v->y = (x * matrix[1]) + (y * matrix[4]) + (z * matrix[7]);
    v->z = (x * matrix[2]) + (y * matrix[5]) + (z * matrix[8]);
}

void model2_normalize_vector(model2_poly_vertex_t *v)
{
    float n = sqrtf((v->x * v->x) + (v->y * v->y) + (v->z * v->z));
    if (n > 0.f) {
        float oon = 1.f / n;
        v->x *= oon;
        v->y *= oon;
        v->z *= oon;
    }
}

float model2_dot_product(const model2_poly_vertex_t *a, const model2_poly_vertex_t *b)
{
    return (a->x * b->x) + (a->y * b->y) + (a->z * b->z);
}

model2_poly_vertex_t model2_vector_cross3(const model2_poly_vertex_t *v0,
                                          const model2_poly_vertex_t *v1,
                                          const model2_poly_vertex_t *v2)
{
    float p1x = v1->x - v0->x, p1y = v1->y - v0->y, p1z = v1->z - v0->z;
    float p2x = v2->x - v0->x, p2y = v2->y - v0->y, p2z = v2->z - v0->z;
    model2_poly_vertex_t out;
    out.x = (p1y * p2z) - (p1z * p2y);
    out.y = (p1z * p2x) - (p1x * p2z);
    out.z = (p1x * p2y) - (p1y * p2x);
    return out;
}

void model2_apply_focus(const model2_geo_state_t *geo, model2_poly_vertex_t *p)
{
    p->x *= geo->focus.x;
    p->y *= geo->focus.y;
}

static int signed12_geo(u32 v)
{
    v &= 0xfffu;
    return (v & 0x800u) ? (int)v - 0x1000 : (int)v;
}

void model2_geo_window_eye(const model2_geo_state_t *geo, unsigned eye, int *cx,
                           int *cy)
{
    u32 w;

    if (!geo || !cx || !cy)
        return;
    *cx = 0;
    *cy = 0;
    if (!geo->window_valid || eye > 3u)
        return;
    /* GEO FIFO words 2..5 are vanishing points 0..3 (MAME geo_window_data). */
    w = geo->window[2u + eye];
    *cx = signed12_geo(w >> 16);
    *cy = signed12_geo(w);
}

void model2_geo_bake_center_sel(const model2_geo_state_t *geo,
                                model2_mesh_collector_t *mesh)
{
    int c0x, c0y, csx, csy;
    float dx, dy;
    unsigned i;

    if (!geo || !mesh || !geo->window_valid || mesh->n_verts == 0)
        return;
    model2_geo_window_eye(geo, 0, &c0x, &c0y);
    model2_geo_window_eye(geo, geo->center_sel & 3u, &csx, &csy);
    if (csx == c0x && csy == c0y)
        return;
    dx = (float)(csx - c0x);
    dy = (float)(csy - c0y);
    for (i = 0; i < mesh->n_verts; i++) {
        float z = mesh->verts[i].z;

        mesh->verts[i].x += dx * z;
        mesh->verts[i].y += dy * z;
    }
}

void model2_geo_rebase_eye0(model2_mesh_collector_t *mesh, int old_cx, int old_cy,
                            int new_cx, int new_cy)
{
    float dx, dy;
    unsigned i;

    if (!mesh || mesh->n_verts == 0)
        return;
    if (old_cx == new_cx && old_cy == new_cy)
        return;
    dx = (float)(old_cx - new_cx);
    dy = (float)(old_cy - new_cy);
    for (i = 0; i < mesh->n_verts; i++) {
        float z = mesh->verts[i].z;

        mesh->verts[i].x += dx * z;
        mesh->verts[i].y += dy * z;
    }
}

int model2_mame_polygon_visible(u32 attr, int front)
{
    if (((attr >> 8) & 3u) == 0)
        return 0;
    if (((attr >> 17) & 1u) == 0 && !front)
        return 0;
    return 1;
}

int model2_mame_polygon_exportable(u32 attr)
{
    return ((attr >> 8) & 3u) != 0;
}

static int read_point(const u32 *words, unsigned n_words, int index,
                      model2_poly_vertex_t *out)
{
    if (index + 2 >= (int)n_words)
        return -1;
    out->x = model2_u2f(words[index]);
    out->y = model2_u2f(words[index + 1]);
    out->z = model2_u2f(words[index + 2]);
    return index + 3;
}

static int reasonable_vertex(const model2_poly_vertex_t *p)
{
    /*
     * Track/world polygon coordinates legitimately exceed ±25k (confirmed
     * catalog objects 0x12144e/0x121862). Hardware clips after transform and
     * projection; magnitude is not a validity test.
     */
    return isfinite(p->x) && isfinite(p->y) && isfinite(p->z);
}

static int emit_point(model2_geo_state_t *geo, model2_mesh_collector_t *c,
                      model2_poly_vertex_t *point)
{
    model2_transform_point(point, geo->matrix);
    model2_apply_focus(geo, point);
    return model2_mesh_collector_add_vertex(c, point->x, point->y, point->z);
}

/*
 * MAME model2_v.cpp geo_parse_np_ns / np_s: luminance from pre-focus point.
 * object.luma = ((luma<<15)>>15)&0xff strips the face bit — store 0..255 only.
 */
static u8 mame_parse_poly_luma(const model2_geo_state_t *geo, u32 attr,
                               const model2_poly_vertex_t *normal,
                               const model2_poly_vertex_t *point_pre_focus)
{
    const model2_texture_param_t *tp =
        &geo->texture_parameters[(attr >> 18) & 0x1fu];
    float dotl = model2_dot_product(normal, &geo->light);
    float dotp = model2_dot_product(normal, point_pre_focus);
    float luminance;

    if ((dotl * dotp) < 0.f)
        luminance = 0.f;
    else
        luminance = fabsf(dotl);

    if ((geo->mode & 1) != 0) {
        /* NP_S / NN_S — model2_v.cpp specular path */
        float specular = ((2.f * dotl) * normal->z) - geo->light.z;

        if (specular < 0.f)
            specular = 0.f;
        if (tp->specular_control == 0)
            specular = 0.f;
        if ((tp->specular_control >> 1) != 0)
            specular *= specular;
        if ((tp->specular_control >> 2) != 0)
            specular *= specular;
        if (((tp->specular_control + 1) >> 3) != 0)
            specular *= specular;
        specular *= tp->specular_scale;
        luminance = (luminance * tp->diffuse) + tp->ambient + specular;
    } else {
        luminance = (luminance * tp->diffuse) + tp->ambient;
    }
    if (luminance < 0.f)
        luminance = 0.f;
    if (luminance > 255.f)
        luminance = 255.f;
    return (u8)luminance;
}

static int emit_link_point(model2_geo_state_t *geo, model2_mesh_collector_t *c,
                           model2_poly_vertex_t *point,
                           const model2_poly_vertex_t *normal, int *is_front,
                           u8 *poly_luma, u32 attr)
{
    model2_transform_point(point, geo->matrix);
    *is_front = model2_dot_product(normal, point) >= 0.f;
    *poly_luma = mame_parse_poly_luma(geo, attr, normal, point);
    model2_apply_focus(geo, point);
    return model2_mesh_collector_add_vertex(c, point->x, point->y, point->z);
}

int model2_geo_parse_np_ns(model2_geo_state_t *geo, const u32 *words, unsigned n_words,
                           int start, int count, model2_mesh_collector_t *c)
{
    int index = start;
    model2_poly_vertex_t point, normal;
    int v_p0_prev, v_p1_prev, v_p0, v_p1;
    int is_front;
    int i;

    index = read_point(words, n_words, index, &point);
    if (index < 0 || !reasonable_vertex(&point))
        return -1;
    v_p0_prev = emit_point(geo, c, &point);
    if (v_p0_prev < 0)
        return -1;

    index = read_point(words, n_words, index, &point);
    if (index < 0 || !reasonable_vertex(&point))
        return -1;
    v_p1_prev = emit_point(geo, c, &point);
    if (v_p1_prev < 0)
        return -1;

    for (i = 0; i < count; i++) {
        u32 attr;
        int link;
        int idx[4];
        u8 poly_luma;

        if (index >= (int)n_words)
            break;
        attr = words[index++];
        if ((attr & 3u) == 0)
            break;

        index = read_point(words, n_words, index, &normal);
        if (index < 0)
            return -1;
        /* MAME model2_v.cpp link path: transform only — no normalize here. */
        model2_transform_vector(&normal, geo->matrix);

        index = read_point(words, n_words, index, &point);
        if (index < 0 || !reasonable_vertex(&point))
            return -1;
        v_p0 = emit_link_point(geo, c, &point, &normal, &is_front, &poly_luma, attr);
        if (v_p0 < 0)
            return -1;

        if (attr & 1u) {
            index = read_point(words, n_words, index, &point);
            if (index < 0 || !reasonable_vertex(&point))
                return -1;
            model2_transform_point(&point, geo->matrix);
            model2_apply_focus(geo, &point);
            v_p1 = model2_mesh_collector_add_vertex(c, point.x, point.y, point.z);
            if (v_p1 < 0)
                return -1;
            idx[0] = v_p1_prev;
            idx[1] = v_p0_prev;
            idx[2] = v_p0;
            idx[3] = v_p1;
            model2_mesh_collector_add_prim(c, attr, idx, 4, normal.x, normal.y, normal.z,
                                           is_front, poly_luma);
        } else {
            index += 3;
            v_p1 = v_p0;
            idx[0] = v_p1_prev;
            idx[1] = v_p0_prev;
            idx[2] = v_p0;
            model2_mesh_collector_add_prim(c, attr, idx, 3, normal.x, normal.y, normal.z,
                                           is_front, poly_luma);
        }

        link = (int)((attr >> 8) & 3u);
        if (link == 0 || link == 2) {
            v_p0_prev = v_p0;
            v_p1_prev = v_p1;
        } else if (link == 1) {
            v_p1_prev = v_p0;
        } else if (link == 3) {
            v_p0_prev = v_p1;
        }
    }
    return index;
}

int model2_geo_parse_nn_ns(model2_geo_state_t *geo, const u32 *words, unsigned n_words,
                           int start, int count, model2_mesh_collector_t *c)
{
    int index = start;
    model2_poly_vertex_t point, p0, p1, p2, p3, normal;
    int v0, v1, v2, v3;
    int i;

    index = read_point(words, n_words, index, &point);
    if (index < 0 || !reasonable_vertex(&point))
        return -1;
    model2_transform_point(&point, geo->matrix);
    p0 = point;
    model2_apply_focus(geo, &point);
    v0 = model2_mesh_collector_add_vertex(c, point.x, point.y, point.z);
    if (v0 < 0)
        return -1;

    index = read_point(words, n_words, index, &point);
    if (index < 0 || !reasonable_vertex(&point))
        return -1;
    model2_transform_point(&point, geo->matrix);
    p1 = point;
    model2_apply_focus(geo, &point);
    v1 = model2_mesh_collector_add_vertex(c, point.x, point.y, point.z);
    if (v1 < 0)
        return -1;

    for (i = 0; i < count; i++) {
        u32 attr;
        int link;
        int is_front;
        int idx[4];

        if (index >= (int)n_words)
            break;
        attr = words[index++];
        if ((attr & 3u) == 0)
            break;

        index += 3; /* skip stored normal slot */

        index = read_point(words, n_words, index, &point);
        if (index < 0 || !reasonable_vertex(&point))
            return -1;
        model2_transform_point(&point, geo->matrix);
        p2 = point;
        normal = model2_vector_cross3(&p0, &p1, &p2);
        model2_normalize_vector(&normal);
        is_front = model2_dot_product(&normal, &point) >= 0.f;
        {
            u8 poly_luma = mame_parse_poly_luma(geo, attr, &normal, &point);

            model2_apply_focus(geo, &point);
            v2 = model2_mesh_collector_add_vertex(c, point.x, point.y, point.z);
            if (v2 < 0)
                return -1;

            if (attr & 1u) {
                index = read_point(words, n_words, index, &point);
                if (index < 0 || !reasonable_vertex(&point))
                    return -1;
                model2_transform_point(&point, geo->matrix);
                p3 = point;
                model2_apply_focus(geo, &point);
                v3 = model2_mesh_collector_add_vertex(c, point.x, point.y, point.z);
                if (v3 < 0)
                    return -1;
                idx[0] = v0;
                idx[1] = v1;
                idx[2] = v2;
                idx[3] = v3;
                model2_mesh_collector_add_prim(c, attr, idx, 4, normal.x, normal.y,
                                               normal.z, is_front, poly_luma);
            } else {
                index += 3;
                p3 = p2;
                v3 = v2;
                idx[0] = v0;
                idx[1] = v1;
                idx[2] = v2;
                model2_mesh_collector_add_prim(c, attr, idx, 3, normal.x, normal.y,
                                               normal.z, is_front, poly_luma);
            }
        }

        link = (int)((attr >> 8) & 3u);
        if (link == 0 || link == 2) {
            p0 = p2;
            p1 = p3;
            v0 = v2;
            v1 = v3;
        } else if (link == 1) {
            p1 = p2;
            v1 = v2;
        } else if (link == 3) {
            p0 = p3;
            v0 = v3;
        }
    }
    return index;
}

int model2_geo_parse_mode(model2_geo_state_t *geo, int mode, const u32 *words,
                          unsigned n_words, int start, int count,
                          model2_mesh_collector_t *c)
{
    geo->mode = mode & 3;
    switch (geo->mode) {
    case MODEL2_GEO_MODE_NP_NS:
    case MODEL2_GEO_MODE_NP_S:
        return model2_geo_parse_np_ns(geo, words, n_words, start, count, c);
    case MODEL2_GEO_MODE_NN_NS:
    case MODEL2_GEO_MODE_NN_S:
        return model2_geo_parse_nn_ns(geo, words, n_words, start, count, c);
    default:
        return -1;
    }
}
