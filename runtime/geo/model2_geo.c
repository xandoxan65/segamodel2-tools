/* Public geo lib facade — wraps parse/dl/render/tex/gl behind model2_geo.h. */

#include "model2_geo.h"
#include "model2_geo_render.h"
#include "model2_geo_gl.h"
#include "model2_geo_tex.h"

#include <string.h>

int model2_geo_init(const model2_geo_fifo_ops_t *fifo)
{
    model2_geo_render_bind_fifo(fifo);
    return model2_geo_render_init();
}

void model2_geo_shutdown(void)
{
    model2_geo_gl_tex_shutdown();
    model2_geo_render_shutdown();
}

void model2_geo_kick(void)
{
    model2_geo_render_kick();
}

void model2_geo_clear(void)
{
    model2_geo_render_clear_draw();
}

int model2_geo_decode(void)
{
    return model2_geo_render_decode_fifos();
}

int model2_geo_decode_file(const char *path, int require_end)
{
    return model2_geo_render_decode_prg_file(path, require_end);
}

void model2_geo_upload_texture(u32 address, u32 count, const u32 *data)
{
    model2_geo_render_texture_data(address, count, data);
}

void model2_geo_upload_polygon(u32 address, u32 count, const u32 *data)
{
    model2_geo_render_polygon_data(address, count, data);
}

int model2_geo_peek_polygon_ram0(u32 addr, u32 *out)
{
    return model2_geo_render_polygon_ram0_peek(addr, out);
}

unsigned model2_geo_vertex_count(void)
{
    return model2_geo_render_vertex_count();
}

unsigned model2_geo_triangle_count(void)
{
    return model2_geo_render_triangle_count();
}

int model2_geo_projection(model2_geo_projection_t *out)
{
    return model2_geo_render_projection(out);
}

int model2_geo_copy_buffers(float **out_pos, unsigned *out_npos,
                            unsigned **out_idx, unsigned *out_nidx)
{
    return model2_geo_render_copy_draw_buffers(out_pos, out_npos, out_idx, out_nidx);
}

int model2_geo_copy_textured(float **out_xyzuv, unsigned *out_nverts,
                             model2_geo_tri_mat_t **out_mats, unsigned *out_ntris)
{
    return model2_geo_render_copy_draw_textured(out_xyzuv, out_nverts, out_mats,
                                                out_ntris);
}

int model2_geo_lock_textured(const float **out_xyzuv, unsigned *out_nverts,
                             const model2_geo_tri_mat_t **out_mats, unsigned *out_ntris)
{
    return model2_geo_render_lock_draw_textured(out_xyzuv, out_nverts, out_mats,
                                                out_ntris);
}

void model2_geo_unlock(void)
{
    model2_geo_render_unlock_draw();
}

void model2_geo_draw_gl(void)
{
    model2_geo_render_draw_gl();
}

void model2_geo_draw_textured(const float *xyzuv, unsigned nverts,
                              const model2_geo_tri_mat_t *mats, unsigned ntris)
{
    model2_geo_gl_draw_textured(xyzuv, nverts, mats, ntris);
}

void model2_geo_sheets_mark_dirty(void)
{
    model2_tex_sheets_mark_dirty();
}

int model2_geo_dump_summary(const char *path)
{
    return model2_geo_render_dump_summary(path);
}
