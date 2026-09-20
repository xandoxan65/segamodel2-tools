/* Host ops storage for model2_tgp. */

#include "model2_tgp_host.h"

#include <string.h>

static model2_tgp_host_ops_t g_host;

void model2_tgp_bind_host(const model2_tgp_host_ops_t *ops)
{
    if (ops)
        g_host = *ops;
    else
        memset(&g_host, 0, sizeof(g_host));
}

const model2_tgp_host_ops_t *model2_tgp_host(void)
{
    return &g_host;
}
