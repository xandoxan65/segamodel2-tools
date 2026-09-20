#ifndef MODEL2_SND_M68K_H
#define MODEL2_SND_M68K_H

#include "model2_snd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void model2_snd_m68k_reset(void);
void model2_snd_m68k_run(unsigned insns);
/* One 68000 insn (or exception stack). Returns MC68000UM cycles. */
unsigned model2_snd_m68k_exec(void);
int model2_snd_m68k_alive(void);
u32 model2_snd_m68k_pc(void);
u16 model2_snd_m68k_sr(void);
u32 model2_snd_m68k_areg(unsigned n);

#ifdef __cplusplus
}
#endif

#endif
