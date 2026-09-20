#ifndef I960_HOST_STAGING_H
#define I960_HOST_STAGING_H

#include "i960_lift.h"
#include "model2_memory.h"

/* maincpu_reset_entry copies ROM 0x1000 → workram 0x5A0000 (98304 words). */
#define MODEL2_ROM_STAGING_SRC       0x00001000u
#define MODEL2_WORKRAM_STAGING_VADDR 0x005a0000u
#define MODEL2_WORKRAM_STAGING_SIZE  0x00060000u

/* Map call/callx target (ROM or relocated workram) to canonical ROM PC. */
u32 i960_host_resolve_call_target(u32 vaddr);

/* True when vaddr lies in the staged workram window. */
int i960_host_is_staged_workram(u32 vaddr);

/* callx / mode-table targets with direct lifted calls when documented. */
int i960_host_staging_call_lifted(u32 workram_or_rom_pc);
void i960_host_staging_call_mode_slot(u32 mode_index);

#endif
