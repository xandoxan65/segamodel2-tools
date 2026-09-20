/* Injected host callbacks for TGP HLE (workram + GEO matrix emit). */
#ifndef MODEL2_TGP_HOST_H
#define MODEL2_TGP_HOST_H

#include "model2_tgp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct model2_tgp_host_ops {
    /* Workram u32 load by absolute vaddr (0x55 eye.y, view latch, road). NULL → 0. */
    u32 (*workram_ld_u32)(u32 vaddr);

    /* TGP 0x05 / 0x55 → GEO 0x0B + 12 floats. Called under caller's fifo lock. */
    void (*emit_geo_matrix)(const float m[12]);
} model2_tgp_host_ops_t;

void model2_tgp_bind_host(const model2_tgp_host_ops_t *ops);
const model2_tgp_host_ops_t *model2_tgp_host(void);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_TGP_HOST_H */
