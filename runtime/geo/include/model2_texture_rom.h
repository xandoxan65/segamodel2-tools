/* Host load of interleaved textures ROM (tp/th metadata pool, not texel sheets). */
#ifndef MODEL2_TEXTURE_ROM_H
#define MODEL2_TEXTURE_ROM_H

#include "model2_geo_types.h"

/* Load from SEGAMOD2_ROM_DIR / DECOMP_ROM_DIR. Returns 0 on success. */
int model2_texture_rom_load_default(void);

/* u16 pool as used by MAME raster_state.texture_rom. */
const u16 *model2_texture_rom_u16(unsigned *out_count);
u32 model2_texture_rom_mask(void);

void model2_texture_rom_shutdown(void);

#endif
