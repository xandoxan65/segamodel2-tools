/* Host OpenGL textured geo draw — index sheet + 16-entry palette LUT.
 * Same entry for attract and race (course_view_bind / copro_submit latch). */
#ifndef MODEL2_GEO_GL_H
#define MODEL2_GEO_GL_H

#include "model2_geo.h"

#ifdef I960_HOST_HAVE_GL
void model2_geo_gl_tex_init(void);
void model2_geo_gl_tex_shutdown(void);
/* Attract + race publish into the same latch; this draws it. */
void model2_geo_gl_draw_textured(const float *xyzuv, unsigned nverts,
                                 const model2_geo_tri_mat_t *mats, unsigned ntris);
/* I960_GEO_FLAT=1: gray lit tris (transform debug). Default 0 = full colour. */
void model2_geo_gl_set_flat(int on);
int model2_geo_gl_want_flat(void);
#else
static inline void model2_geo_gl_tex_init(void) {}
static inline void model2_geo_gl_tex_shutdown(void) {}
static inline void model2_geo_gl_draw_textured(const float *xyzuv, unsigned nverts,
                                              const model2_geo_tri_mat_t *mats,
                                              unsigned ntris)
{
    (void)xyzuv;
    (void)nverts;
    (void)mats;
    (void)ntris;
}
static inline void model2_geo_gl_set_flat(int on) { (void)on; }
static inline int model2_geo_gl_want_flat(void) { return 0; }
#endif

#endif
