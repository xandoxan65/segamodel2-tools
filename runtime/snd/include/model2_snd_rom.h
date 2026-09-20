#ifndef MODEL2_SND_ROM_H
#define MODEL2_SND_ROM_H

#include "model2_snd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MODEL2_SND_68K_ROM_SIZE     0x40000u
#define MODEL2_SND_SAMPLE_ROM_SIZE  0x800000u
#define MODEL2_SND_SOUNDRAM_SIZE    0x80000u

int model2_snd_rom_load(const char *rom_dir);
void model2_snd_rom_unload(void);
int model2_snd_rom_loaded(void);

const u8 *model2_snd_68k_rom(void);
const u8 *model2_snd_sample_rom(void);

#ifdef __cplusplus
}
#endif

#endif
