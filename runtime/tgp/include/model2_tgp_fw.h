/* TGP firmware-backed helpers (MB86234 program @ 0x5F9E94). */
#ifndef MODEL2_TGP_FW_H
#define MODEL2_TGP_FW_H

#include "model2_tgp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void model2_tgp_fw_reset(void);

/* Bind deinterleaved copro_data (word array). Owns nothing unless load_default. */
void model2_tgp_fw_bind_copro_data(const u32 *words, u32 nwords);
int model2_tgp_fw_load_copro_data_default(void);

/* 0x52 @ 0x58A: walk copro_data → slot. Returns 1 on hit. */
int model2_tgp_fw_run_52(const u32 words[9]);

/* 0x52 result → slot used by 0x53 (arg = i960 arg2<<1). */
void model2_tgp_fw_slot_store(u32 arg_shifted, u32 flag, const u32 floats16[16]);
void model2_tgp_fw_slot_clear(u32 arg_shifted);

/*
 * Emit 0x53 FIFO readback from a prior slot_store / run_52.
 * Returns 1 if handled (including miss→17×0); 0 if no push fn.
 */
int model2_tgp_fw_emit_53(u32 arg_shifted, void (*out_push)(u32));

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_TGP_FW_H */
