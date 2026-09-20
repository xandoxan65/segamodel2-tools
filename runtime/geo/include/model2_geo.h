/* Host geo rendering library — simple API for attract/race 3D.
 *
 * Decode path: PRG FIFO words (+ optional per-word matrices) → mesh → GL.
 * The lift runtime supplies FIFO/latch via model2_geo_fifo_ops_t; this lib
 * does not own MMIO or vsync.
 */
#ifndef MODEL2_GEO_H
#define MODEL2_GEO_H

#include "model2_geo_types.h"
#include "model2_geo_hw.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Projection / draw types ---- */

typedef struct {
    float focal_x;
    float focal_y;
    int viewport[4]; /* left, top, right, bottom */
    int center[2];   /* eye-0 vanishing point (GL matrix); other eyes baked */
    int valid;
} model2_geo_projection_t;

typedef struct {
    u16 colorbase;
    u16 lumabase;
    u16 patch_x;
    u16 patch_y;
    u16 patch_w;
    u16 patch_h;
    u8 sheet;
    u8 flags;
    u8 luma;
    u8 pad;
    float z_sort;
} model2_geo_tri_mat_t;

/*
 * Frame/FIFO input from the lift runtime (model2_hw). Pass to
 * model2_geo_init(); NULL ops → offline file decode only.
 */
typedef struct model2_geo_fifo_ops {
    unsigned (*prg_total)(void);
    unsigned (*copro_total)(void);
    unsigned (*display_gen)(void);
    void (*display_range)(unsigned *start, unsigned *end);
    unsigned (*copy_prg_range)(unsigned start, unsigned end, u32 *dst, unsigned cap);
    unsigned (*copy_mtx_range)(unsigned start, unsigned end, float *dst, unsigned cap);
    unsigned (*copy_prg)(u32 *dst, unsigned cap);
    unsigned (*copy_mtx)(float *dst, unsigned cap);
    unsigned (*copy_copro_range)(unsigned start, unsigned end, u32 *dst, unsigned cap);
    int (*projection)(float focus_out[2], u32 window_out[6]);
    int (*shading)(float light_out[3], int *mode_out, u32 tex_param_out[32],
                   float coef_out[32]);
    void (*set_notify)(void (*fn)(void));
} model2_geo_fifo_ops_t;

/* ---- Lifecycle ---- */

/* Bind FIFO ops (may be NULL for offline) and start the decode worker.
 * Call model2_geo_bind_hw() first when textured draw needs palette/sheets. */
int model2_geo_init(const model2_geo_fifo_ops_t *fifo);
void model2_geo_shutdown(void);

/* Wake background decode (also the FIFO notify callback when ops->set_notify). */
void model2_geo_kick(void);

/* Drop published mesh (splash / scene change). */
void model2_geo_clear(void);

/* ---- Decode ---- */

/* Sync: drain FIFO into the published mesh (waits for worker catch-up). */
int model2_geo_decode(void);

/* Offline: decode a little-endian u32 PRG dump as a display list. */
int model2_geo_decode_file(const char *path, int require_end);

/* GEO RAM uploads from lift (cmds 0x04 / 0x05 / 0x15). */
void model2_geo_upload_texture(u32 address, u32 count, const u32 *data);
void model2_geo_upload_polygon(u32 address, u32 count, const u32 *data);
int model2_geo_peek_polygon_ram0(u32 addr, u32 *out);

/* ---- Queries / draw snapshots ---- */

unsigned model2_geo_vertex_count(void);
unsigned model2_geo_triangle_count(void);
int model2_geo_projection(model2_geo_projection_t *out);

int model2_geo_copy_buffers(float **out_pos, unsigned *out_npos,
                            unsigned **out_idx, unsigned *out_nidx);
int model2_geo_copy_textured(float **out_xyzuv, unsigned *out_nverts,
                             model2_geo_tri_mat_t **out_mats, unsigned *out_ntris);
int model2_geo_lock_textured(const float **out_xyzuv, unsigned *out_nverts,
                             const model2_geo_tri_mat_t **out_mats, unsigned *out_ntris);
void model2_geo_unlock(void);

/* ---- GL / texture sheets ---- */

void model2_geo_draw_gl(void);
void model2_geo_draw_textured(const float *xyzuv, unsigned nverts,
                              const model2_geo_tri_mat_t *mats, unsigned ntris);
void model2_geo_sheets_mark_dirty(void);

int model2_geo_dump_summary(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_GEO_H */
