/* Injected host RAM / ROM windows for palette + texture sheets. */

#include "model2_geo_hw.h"

#include <string.h>

static model2_geo_hw_ops_t g_hw;

void model2_geo_bind_hw(const model2_geo_hw_ops_t *hw)
{
    if (hw)
        g_hw = *hw;
    else
        memset(&g_hw, 0, sizeof(g_hw));
}

const model2_geo_hw_ops_t *model2_geo_hw(void)
{
    return &g_hw;
}
