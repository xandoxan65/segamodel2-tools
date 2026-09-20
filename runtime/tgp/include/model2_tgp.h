/* Model 2 TGP (MB86234 / copro FIFO) HLE — stand-alone.
 *
 * Not internally locked: callers that share FIFO/MMIO (model2_hw) must hold
 * their own mutex around fifo_write/read and matrix/view accessors.
 * Board RAM and GEO PRG emit are injected via model2_tgp_bind_host().
 */
#ifndef MODEL2_TGP_H
#define MODEL2_TGP_H

#include "model2_tgp_types.h"
#include "model2_tgp_host.h"

#ifdef __cplusplus
extern "C" {
#endif

void model2_tgp_reset(void);
void model2_tgp_fifo_reset_counts(void);

/*
 * table_index_a @ 0x2ABC0 operands. Firmware 0x07 (PC 0x16D) loads *( $125 );
 * 0x52 (PC 0x58A) loads the nine-word block at that cursor. After
 * course_view_bind the host cursor at 0x20a290 can be a GEO wr_ptr leftover,
 * so HLE would first-match handle 0 → course 2 @ 0x5dcad8. Arm the words the
 * i960 already computed; CRC @ 0x29840 must not call these (unmatched → 0).
 */
void model2_tgp_arm_course_handle(u32 handle);
void model2_tgp_arm_52_block(const u32 words[9]);

/* Process one COPRO FIFO write (log ring + HLE). */
void model2_tgp_fifo_write(u32 value);
/* Pop one HLE output word (0 if empty). */
u32 model2_tgp_fifo_read(void);

void model2_tgp_matrix(float out[12]);
int model2_tgp_matrix_is_identity(void);

void model2_tgp_latch_view_matrix(void);
int model2_tgp_restore_latched_view_matrix(void);
int model2_tgp_view_matrix(float out[12]);
int model2_tgp_view_camera(float eye_out[3], float focus_out[3], float *pitch_seed,
                           float *seed_a, float *seed_b);

/* Input log ring (words written to the FIFO). */
unsigned model2_tgp_count(void);
unsigned model2_tgp_total(void);
const u32 *model2_tgp_words(unsigned *out_count);
unsigned model2_tgp_copy_range(unsigned start_abs, unsigned end_abs, u32 *dst,
                               unsigned dst_cap);
void model2_tgp_dump(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_TGP_H */
