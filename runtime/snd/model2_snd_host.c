/* Host ops storage for model2_snd. */

#include "model2_snd_host.h"

#include <string.h>

static model2_snd_host_ops_t g_host;

void model2_snd_bind_host(const model2_snd_host_ops_t *ops)
{
    if (ops)
        g_host = *ops;
    else
        memset(&g_host, 0, sizeof(g_host));
}

const model2_snd_host_ops_t *model2_snd_host(void)
{
    return &g_host;
}
