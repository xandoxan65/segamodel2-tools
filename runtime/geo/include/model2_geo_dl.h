/* Model 2 geo display-list runner — C port of tools/model2_geo_dl.py. */
#ifndef MODEL2_GEO_DL_H
#define MODEL2_GEO_DL_H

#include "model2_geo_parse.h"

typedef struct {
    const u32 *polygon_rom;
    unsigned polygon_rom_words;
    u32 polygon_rom_mask;
    u32 *polygon_ram0; /* 0x8000 words */
    u32 *polygon_ram1;
    /* MAME raster_state.texture_ram / log_ram — GEO cmd 0x04. */
    u16 *texture_ram; /* 0x10000 u16 */
    u32 *log_ram;     /* 0x8000 u32 */
} model2_geo_dl_ctx_t;

typedef struct {
    int rom_offset;
    u32 oba;
    u32 obc;
    unsigned vertex_count;
    int mode;
} model2_drawn_object_t;

typedef struct {
    int ok;
    int finished; /* reached geo_end */
    int start_word;
    int words_consumed;
    unsigned commands_executed;
    unsigned objects_drawn;
    model2_mesh_collector_t mesh;
    model2_drawn_object_t *objects;
    unsigned objects_cap;
    char error[128];
} model2_geo_dl_result_t;

void model2_geo_dl_ctx_init(model2_geo_dl_ctx_t *ctx);
void model2_geo_dl_ctx_free(model2_geo_dl_ctx_t *ctx);
int model2_geo_dl_ctx_set_rom(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words);

void model2_geo_dl_result_init(model2_geo_dl_result_t *r);
void model2_geo_dl_result_free(model2_geo_dl_result_t *r);

/*
 * Execute a display list starting at words[start].
 * require_end: if non-zero, fail when geo_end is not reached (Python default).
 * Soft mode (require_end=0) stops at geo_end or buffer end — used for truncated FIFO.
 * initial_matrix: optional 12-float 3×4 (MAME column layout; T at 9,10,11);
 * NULL → identity.
 */
int model2_geo_dl_run(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                      int start, int require_end, unsigned max_ops,
                      model2_geo_dl_result_t *out);
int model2_geo_dl_run_mtx(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                          int start, int require_end, unsigned max_ops,
                          const float *initial_matrix, model2_geo_dl_result_t *out);
/*
 * MAME geo_parse-style: one geo_state across the whole frame. Object/direct
 * commands take their transform from per_word_mtx[op_index] when provided
 * (TGP snapshot at that PRG write — attract catalog path).
 * focus_xy_out: optional final geo.focus.x/y after the run.
 */
int model2_geo_dl_run_stream(model2_geo_dl_ctx_t *ctx, const u32 *words, unsigned n_words,
                             const float *per_word_mtx, unsigned mtx_words,
                             model2_geo_dl_result_t *out, float focus_xy_out[2]);
int model2_geo_dl_run_stream_state(model2_geo_dl_ctx_t *ctx, const u32 *words,
                                   unsigned n_words, const float *per_word_mtx,
                                   unsigned mtx_words, model2_geo_state_t *state,
                                   model2_geo_dl_result_t *out);

float model2_fixed24_to_float(u32 word);
int model2_is_polygon_rom_oba(u32 oba);

/*
 * MAME geo_texture_data / geo_polygon_data side effects into ctx RAM.
 * Used when geo_reg_texture_sync suppresses PRG mesh retention but still
 * issues 0x800040 / 0x800050 + FIFO body (same as hardware bufferram parse).
 */
void model2_geo_dl_texture_data(model2_geo_dl_ctx_t *ctx, u32 address, u32 count,
                                const u32 *data);
void model2_geo_dl_polygon_data(model2_geo_dl_ctx_t *ctx, u32 address, u32 count,
                                const u32 *data);

#endif
