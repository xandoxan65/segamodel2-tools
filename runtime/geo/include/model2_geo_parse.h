/* Model 2 polygon stream parsers — C port of tools/model2_geo.py (MAME model2_v.cpp). */
#ifndef MODEL2_GEO_PARSE_H
#define MODEL2_GEO_PARSE_H

#include "model2_geo_types.h"

enum {
    MODEL2_GEO_MODE_NP_NS = 0,
    MODEL2_GEO_MODE_NP_S = 1,
    MODEL2_GEO_MODE_NN_NS = 2,
    MODEL2_GEO_MODE_NN_S = 3
};

typedef struct {
    float x, y, z;
} model2_poly_vertex_t;

typedef struct {
    float diffuse;
    float ambient;
    int specular_control;
    float specular_scale;
} model2_texture_param_t;

typedef struct {
    int mode;
    float matrix[12];
    model2_poly_vertex_t focus;
    model2_poly_vertex_t light;
    float lod;
    /* Last command 03/13 window payload; persistent GEO/raster state. */
    u32 window[6];
    int window_valid;
    /*
     * MAME raster_state.center_sel — from object opcode bits 29..30
     * (geo_w eye mode: ((addr>>10)&3)<<29). Selects vanishing point
     * center[sel] from the four GEO 0x03 eye words.
     */
    u16 center_sel;
    model2_texture_param_t texture_parameters[32];
    float coef_table[32];
} model2_geo_state_t;

enum { MODEL2_MESH_MAX_INDICES = 4 };

typedef struct {
    int n_indices;
    int indices[MODEL2_MESH_MAX_INDICES];
    u32 attr;
    float nx, ny, nz;
    int front;
    /* Parse-time MAME luminance (pre-focus dotp); tex fields filled later. */
    u8 poly_luma;
    int tex_valid;
    /* Patch-local pixels (pu/8, pv/8) — MAME wraps inside patch before get_texel. */
    float u[MODEL2_MESH_MAX_INDICES];
    float v[MODEL2_MESH_MAX_INDICES];
    u16 colorbase;
    u16 lumabase;
    u16 patch_x;
    u16 patch_y;
    u16 patch_w;
    u16 patch_h;
    u8 sheet;
    u8 tex_flags; /* MODEL2_GEO_TEX_* */
    /* Race tach needle @ catalog 0x02865130 / ROM 0x1a7a: identity HUD pose. */
    u8 hud_overlay;
} model2_mesh_prim_t;

/* Copy texture fields after add_prim (append / filtered merge). */
void model2_mesh_prim_copy_tex(model2_mesh_prim_t *dst, const model2_mesh_prim_t *src);

typedef struct {
    model2_poly_vertex_t *verts;
    unsigned n_verts;
    unsigned verts_cap;
    model2_mesh_prim_t *prims;
    unsigned n_prims;
    unsigned prims_cap;
} model2_mesh_collector_t;

void model2_geo_state_init(model2_geo_state_t *geo);
void model2_geo_state_copy(model2_geo_state_t *dst, const model2_geo_state_t *src);

void model2_mesh_collector_init(model2_mesh_collector_t *c);
void model2_mesh_collector_reset(model2_mesh_collector_t *c);
void model2_mesh_collector_free(model2_mesh_collector_t *c);
int model2_mesh_collector_add_vertex(model2_mesh_collector_t *c, float x, float y, float z);
int model2_mesh_collector_add_prim(model2_mesh_collector_t *c, u32 attr,
                                   const int *indices, int n_indices,
                                   float nx, float ny, float nz, int front,
                                   u8 poly_luma);
void model2_mesh_collector_append(model2_mesh_collector_t *dst,
                                  const model2_mesh_collector_t *src);

static inline float model2_u2f(u32 bits)
{
    union {
        u32 u;
        float f;
    } v;
    v.u = bits;
    return v.f;
}

void model2_identity_matrix(float m[12]);
void model2_transform_point(model2_poly_vertex_t *p, const float matrix[12]);
void model2_transform_vector(model2_poly_vertex_t *v, const float matrix[12]);
void model2_normalize_vector(model2_poly_vertex_t *v);
float model2_dot_product(const model2_poly_vertex_t *a, const model2_poly_vertex_t *b);
model2_poly_vertex_t model2_vector_cross3(const model2_poly_vertex_t *v0,
                                          const model2_poly_vertex_t *v1,
                                          const model2_poly_vertex_t *v2);
void model2_apply_focus(const model2_geo_state_t *geo, model2_poly_vertex_t *p);

/* MAME geo_window_data / raster 0x03 — signed 12-bit eye center from raw GEO word. */
void model2_geo_window_eye(const model2_geo_state_t *geo, unsigned eye, int *cx, int *cy);

/*
 * Bake MAME per-object vanishing point into focal-space verts so a single GL
 * matrix (eye0) matches model2_3d_project with center_sel:
 *   sx = c_sel + x/z  ⇒  x' = x + (c_sel − c0)·z
 */
void model2_geo_bake_center_sel(const model2_geo_state_t *geo,
                                model2_mesh_collector_t *mesh);

/*
 * When GEO 0x03 replaces eye0 mid-stream (course select: bootstrap →
 * trapezoid), rebase already-emitted verts so they still project correctly
 * under the new eye0: x' = x + (old_c0 − new_c0)·z.
 */
void model2_geo_rebase_eye0(model2_mesh_collector_t *mesh, int old_cx, int old_cy,
                            int new_cx, int new_cy);

int model2_mame_polygon_visible(u32 attr, int front);
int model2_mame_polygon_exportable(u32 attr);

/* Returns next word index, or -1 on parse error. */
int model2_geo_parse_np_ns(model2_geo_state_t *geo, const u32 *words, unsigned n_words,
                           int start, int count, model2_mesh_collector_t *c);
int model2_geo_parse_nn_ns(model2_geo_state_t *geo, const u32 *words, unsigned n_words,
                           int start, int count, model2_mesh_collector_t *c);
int model2_geo_parse_mode(model2_geo_state_t *geo, int mode, const u32 *words,
                          unsigned n_words, int start, int count,
                          model2_mesh_collector_t *c);

#endif
