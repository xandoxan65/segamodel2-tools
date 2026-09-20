/* Shared types and Model 2 lifted i960 register file (not tier-3 byte-matched).
 *
 * g0–g15 and r0–r15 are extern shared CPU state across all lifted functions.
 * fp/sp are frame pointers; g14 is the link register for call/return.
 *
 * Host registers are uintptr_t so ROM/RAM pointers survive on 64-bit hosts.
 * Leaf bx functions save g14 into a specific register (g*, r*, …) on entry
 * and return via bx(link_reg). Lifted C preserves those register names.
 */
#ifndef I960_LIFT_H
#define I960_LIFT_H

/* Share integer typedefs with stand-alone model2_geo when that header is first. */
#ifndef MODEL2_GEO_TYPES_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;
#endif
typedef char *gptr;
typedef unsigned long uintptr_t;

typedef u32 i960_u32;

extern uintptr_t g0;
extern uintptr_t g1;
extern uintptr_t g2;
extern uintptr_t g3;
extern uintptr_t g4;
extern uintptr_t g5;
extern uintptr_t g6;
extern uintptr_t g7;
extern uintptr_t g8;
extern uintptr_t g9;
extern uintptr_t g10;
extern uintptr_t g11;
extern uintptr_t g12;
extern uintptr_t g13;
extern uintptr_t g14;
extern uintptr_t g15;

extern uintptr_t r0;
extern uintptr_t r1;
extern uintptr_t r2;
extern uintptr_t r3;
extern uintptr_t r4;
extern uintptr_t r5;
extern uintptr_t r6;
extern uintptr_t r7;
extern uintptr_t r8;
extern uintptr_t r9;
extern uintptr_t r10;
extern uintptr_t r11;
extern uintptr_t r12;
extern uintptr_t r13;
extern uintptr_t r14;
extern uintptr_t r15;

extern uintptr_t fp;
extern uintptr_t sp;
extern uintptr_t pfp;

extern double fp0, fp1, fp2, fp3;

void i960_call_rom(uintptr_t addr);
void i960_call_indirect(uintptr_t target);

/* Prefer direct C calls (see include/lift_syms.h). i960_call_rom is for unknown callees only. */

#endif
