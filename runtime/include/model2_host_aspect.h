/* Host display aspect + GEO focal scale (widescreen override).
 *
 * I960_HOST_ASPECT=4:3 (default) | 16:9
 *   16:9 → anamorphic focal_x *= (4/3)/(16/9)=0.75 so HFOV widens; HUD stays
 *   true Sys24 4:3 (centered, unstretched) while 3D fills the 16:9 viewport.
 * Optional I960_GEO_FOV_SCALE=<float> multiplies both axes (0.25..4).
 */
#ifndef MODEL2_HOST_ASPECT_H
#define MODEL2_HOST_ASPECT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int model2_host_aspect_is_widescreen(void)
{
    const char *s = getenv("I960_HOST_ASPECT");

    if (!s || !*s)
        return 0;
    if (strcmp(s, "16:9") == 0 || strcmp(s, "16x9") == 0
        || strcmp(s, "widescreen") == 0 || strcmp(s, "wide") == 0)
        return 1;
    return 0;
}

/* Outer / geo letterbox aspect. */
static inline float model2_host_geo_aspect(void)
{
    if (model2_host_aspect_is_widescreen())
        return 16.f / 9.f;
    /* Match Sys24 raster (496×384), not exact 4:3. */
    return 496.f / 384.f;
}

/* HUD / tile letterbox — always arcade Sys24 proportions. */
static inline float model2_host_hud_aspect(void)
{
    return 496.f / 384.f;
}

static inline void model2_host_fov_scale(float *sx, float *sy)
{
    const char *u = getenv("I960_GEO_FOV_SCALE");
    float ux = 1.f;
    float uy = 1.f;

    if (model2_host_aspect_is_widescreen()) {
        /* (4/3) / (16/9) — keep VFOV, widen HFOV for 16:9 geo viewport. */
        ux = 0.75f;
        uy = 1.f;
    }
    if (u && *u) {
        float v = (float)atof(u);

        if (v >= 0.25f && v <= 4.f) {
            ux *= v;
            uy *= v;
        }
    }
    if (sx)
        *sx = ux;
    if (sy)
        *sy = uy;
}

/* Scale latched GEO 0x09 focal in place. Logs once when scale ≠ identity. */
static inline void model2_host_apply_fov_scale(float *fx, float *fy)
{
    float sx, sy;
    static int logged;

    model2_host_fov_scale(&sx, &sy);
    if ((!fx || sx == 1.f) && (!fy || sy == 1.f))
        return;
    if (!logged) {
        fprintf(stderr,
                "lift: host FOV scale (%.4g,%.4g) aspect=%s raw_focal=(%.4g,%.4g)\n",
                sx, sy,
                model2_host_aspect_is_widescreen() ? "16:9" : "4:3",
                fx ? *fx : 0.f, fy ? *fy : 0.f);
        logged = 1;
    }
    if (fx)
        *fx *= sx;
    if (fy)
        *fy *= sy;
}

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_HOST_ASPECT_H */
