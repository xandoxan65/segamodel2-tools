/* Space-tagged memory access for lifted i960 C (no full RAM model required).
 *
 * Loads/stores name the address space and leave register effects explicit in
 * the caller. Default stubs in i960_mem.c are no-ops / zero — link a real
 * backend only when simulating.
 */
#ifndef I960_MEM_H
#define I960_MEM_H

#include "i960_lift.h"

typedef enum {
    I960_REG = 0,       /* address in a register (g*, r*, fp, sp) */
    I960_ROM = 1,       /* maincpu ROM / main_data image */
    I960_WORKRAM = 2,   /* workram window */
    I960_MMIO = 3,      /* geo fifo and other MMIO */
    I960_ABS = 4,       /* absolute address literal */
    I960_FP = 5,        /* frame-relative (fp + offset) */
} i960_space;

/* Absolute pointers: use model2_rom.h (I960_MAINCPU_ROM, model2_workram, …). */

static inline uintptr_t i960_fp_slot(u32 offset)
{
    return fp + offset;
}

u32 i960_ld_u8(i960_space space, u32 base, u32 offset);
u32 i960_ld_u16(i960_space space, u32 base, u32 offset);
u32 i960_ld_u32(i960_space space, u32 base, u32 offset);
u64 i960_ld_u64(i960_space space, u32 base, u32 offset);

void i960_st_u8(i960_space space, u32 base, u32 offset, u8 value);
void i960_st_u16(i960_space space, u32 base, u32 offset, u16 value);
void i960_st_u32(i960_space space, u32 base, u32 offset, u32 value);
void i960_st_u64(i960_space space, u32 base, u32 offset, u64 value);

void i960_mmio_write_u32(u32 offset, u32 value);
void i960_mmio_write_u8(u32 offset, u8 value);
u32 i960_mmio_read_u8(u32 offset);
u32 i960_mmio_read_u32(u32 offset);

void i960_synmov(uintptr_t src, uintptr_t dst);
void i960_synmovq(uintptr_t src, uintptr_t dst);

/* Optional: attach maincpu deinterleaved image for I960_ROM loads (see out/i960/). */
void i960_mem_attach_rom(const unsigned char *data, unsigned long len);

#endif
