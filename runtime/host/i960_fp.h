/* i960 floating-point helpers for lifted semantic C (MAME rif/rifl semantics).
 * Include after i960_lift.h (uses u32/u64/uintptr_t from there). */
#ifndef I960_FP_H
#define I960_FP_H

#include <math.h>

extern double fp0, fp1, fp2, fp3;

/* movr / rif: 32-bit IEEE float bits in a general register. */
static inline double i960_u32_to_f64(uintptr_t bits)
{
    union {
        u32 u;
        float f;
    } v;
    v.u = (u32)bits;
    return (double)v.f;
}

static inline uintptr_t i960_f64_to_u32(double value)
{
    union {
        u32 u;
        float f;
    } v;
    v.f = (float)value;
    return (uintptr_t)v.u;
}

/* movrl / rifl: 64-bit IEEE double in an even/odd register pair. */
static inline double i960_rifl_read(uintptr_t even, uintptr_t odd)
{
    union {
        u64 u;
        double d;
    } v;
    v.u = (u64)(u32)even | ((u64)(u32)odd << 32);
    return v.d;
}

static inline void i960_rifl_write(uintptr_t *even, uintptr_t *odd, double value)
{
    union {
        u64 u;
        double d;
    } v;
    v.d = value;
    *even = (uintptr_t)(u32)v.u;
    *odd = (uintptr_t)(v.u >> 32);
}

/* i960 lda + movrl (even=0): high word encodes an IEEE double constant (not a RAM pointer).
 * 0x406FE000 → 255.0, 0x404F8000 → 63.0, etc. */

#endif
