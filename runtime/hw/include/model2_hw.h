/* Model 2 GEO MMIO + vsync hardware simulation (stand-alone).
 *
 * Owns GEO PRG FIFO, geo_w / projection / uploads, videoctl/render_mode, and
 * vsync pacing. TGP/copro HLE is in libmodel2_tgp; MMIO 0x00884000..0x00887FFF
 * and model2_hw_copro_* / view_* APIs are thin locked wrappers.
 * Board RAM / display / geo mesh uploads are injected via model2_hw_bind_host().
 * Does not contain uplifted game ROM code.
 */
#ifndef MODEL2_HW_H
#define MODEL2_HW_H

#include "model2_hw_types.h"
#include "model2_hw_host.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Lifecycle / MMIO ---- */

void model2_hw_reset(void);
void model2_hw_mmio_write(u32 offset, u32 value);
u32 model2_hw_mmio_read(u32 offset);

/* videoctl @ 0x98000c — timer/SDL toggles bit 2; geo_vsync_wait blocks on edge. */
int model2_hw_vsync_realtime(void);
void model2_hw_vsync_hw_reset(void);
void model2_hw_vsync_hw_shutdown(void);
u32 model2_hw_video_ctl_read(void);
void model2_hw_video_ctl_write(u32 value);
/* render_mode MMIO @ 0x10000000 (geo_renderer_init stos 4 @ 0x372C). */
void model2_hw_render_mode_write(u32 value);
void model2_hw_vsync_wait_bit2_toggle(unsigned latched_bit2);

/* After geo_vsync_wait edge: latch completed PRG frame for mesh decode. */
void model2_hw_latch_prg_frame(void);
void model2_hw_vsync_frame_done(void);

void model2_hw_dump(const char *path);
void model2_hw_dump_copro(const char *path);
void model2_hw_fifo_reset_counts(void);

/*
 * When 0, PRG FIFO words are not retained for the mesh display ring
 * (geo_reg_texture_sync upload body). Upload side effects still apply.
 */
void model2_hw_prg_mesh_enable(int enable);

/* Optional notify when prg/copro FIFOs accept a word (geo decode worker). */
void model2_hw_set_fifo_notify(void (*fn)(void));

/* ---- PRG FIFO ---- */

unsigned model2_hw_prg_count(void);
unsigned model2_hw_prg_total(void);
const u32 *model2_hw_prg_words(unsigned *out_count);
unsigned model2_hw_prg_copy(u32 *dst, unsigned dst_cap);

unsigned model2_hw_prg_display_gen(void);
void model2_hw_prg_display_range(unsigned *out_start, unsigned *out_end);
void model2_hw_prg_best_range(unsigned *out_start, unsigned *out_end);
void model2_hw_prg_publish_best(void);

unsigned model2_hw_prg_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                                  unsigned dst_cap);
unsigned model2_hw_prg_matrix_copy_range(unsigned start_abs, unsigned end_abs,
                                         float *dst, unsigned dst_cap_words);
unsigned model2_hw_prg_matrix_copy(float *dst, unsigned dst_cap_words);

/* ---- GEO latches (projection / shading) ---- */

int model2_hw_geo_projection(float focus_out[2], u32 window_out[6]);
int model2_hw_geo_shading(float light_out[3], int *mode_out, u32 tex_param_out[32],
                          float coef_out[32]);

/* ---- TGP / view ---- */

void model2_hw_copro_matrix(float out[12]);
int model2_hw_matrix_is_identity(void);
void model2_hw_latch_view_matrix(void);
/* Put the latched cam view back on the TGP working matrix (race_frame:
 * object_pen_walk / unlifted leaves can dirty TGP before course 0x05). */
int model2_hw_restore_latched_view_matrix(void);
int model2_hw_view_matrix(float out[12]);
int model2_hw_view_camera(float eye_out[3], float focus_out[3], float *pitch_seed,
                          float *seed_a, float *seed_b);

/* ---- Copro FIFO ---- */

unsigned model2_hw_copro_count(void);
unsigned model2_hw_copro_total(void);
const u32 *model2_hw_copro_words(unsigned *out_count);
unsigned model2_hw_copro_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                                    unsigned dst_cap);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_HW_H */
