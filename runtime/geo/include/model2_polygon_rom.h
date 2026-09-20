/* Host load of interleaved polygon ROM (SRALLY polygons region). */
#ifndef MODEL2_POLYGON_ROM_H
#define MODEL2_POLYGON_ROM_H

#include "model2_geo_types.h"

/* Load from SEGAMOD2_ROM_DIR / DECOMP_ROM_DIR. Returns 0 on success. */
int model2_polygon_rom_load_default(void);

const u32 *model2_polygon_rom_words(unsigned *out_count);
u32 model2_polygon_rom_mask(void);

void model2_polygon_rom_shutdown(void);

#endif
