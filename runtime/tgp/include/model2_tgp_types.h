/* Integer types for the stand-alone model2_tgp library (no lift dependency). */
#ifndef MODEL2_TGP_TYPES_H
#define MODEL2_TGP_TYPES_H

/* If i960_lift.h / geo / hw types were included first, reuse their typedefs. */
#ifndef I960_LIFT_H
#ifndef MODEL2_GEO_TYPES_H
#ifndef MODEL2_HW_TYPES_H
#ifndef MODEL2_SND_TYPES_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;
#endif
#endif
#endif
#endif

#endif /* MODEL2_TGP_TYPES_H */
