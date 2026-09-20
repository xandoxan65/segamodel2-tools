/* Host ops storage for model2_hw. Also wires model2_tgp host (workram + GEO emit). */

#include "model2_hw_host.h"
#include "model2_tgp_host.h"

#include <string.h>

/* Implemented in model2_hw_fifo.c — TGP 0x05/0x55 → PRG 0x0B under g_fifo_mtx. */
void model2_hw_tgp_emit_geo_matrix(const float m[12]);

static model2_hw_host_ops_t g_host;

void model2_hw_bind_host(const model2_hw_host_ops_t *ops)
{
    model2_tgp_host_ops_t tgp;

    if (ops)
        g_host = *ops;
    else
        memset(&g_host, 0, sizeof(g_host));

    memset(&tgp, 0, sizeof(tgp));
    if (ops) {
        tgp.workram_ld_u32 = ops->workram_ld_u32;
        tgp.emit_geo_matrix = model2_hw_tgp_emit_geo_matrix;
        model2_tgp_bind_host(&tgp);
    } else {
        model2_tgp_bind_host(NULL);
    }
}

const model2_hw_host_ops_t *model2_hw_host(void)
{
    return &g_host;
}
