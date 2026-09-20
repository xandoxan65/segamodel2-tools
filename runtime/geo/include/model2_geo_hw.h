/* Host hardware windows the geo lib reads for sheets / palette (injected).
 * Lift binds these to model2_rom RAM; offline decode may leave them NULL. */
#ifndef MODEL2_GEO_HW_H
#define MODEL2_GEO_HW_H

#include "model2_geo_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes matching Model 2A map (same as model2_memory / model2_rom). */
enum {
    MODEL2_GEO_LUMARAM_SIZE = 0x8000,
    MODEL2_GEO_TEXTURERAM_BANK_SIZE = 0x200000
};

typedef struct model2_geo_hw_ops {
    const u8 *(*palram)(void);
    const u8 *(*colorxlat)(void);
    const u8 *(*lumaram)(void);
    /* Writable 2 MiB banks (sheet 0 / sheet 1). */
    u8 *(*textureram0)(void);
    u8 *(*textureram1)(void);
    /* Optional seed source when textureram is empty (main_data sheet banks). */
    const u8 *(*texture_sheet_rom)(unsigned bank /* 0 or 1 */);
} model2_geo_hw_ops_t;

void model2_geo_bind_hw(const model2_geo_hw_ops_t *hw);
const model2_geo_hw_ops_t *model2_geo_hw(void);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_GEO_HW_H */
