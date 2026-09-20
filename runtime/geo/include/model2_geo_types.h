/* Integer types for the stand-alone model2_geo library (no lift dependency). */
#ifndef MODEL2_GEO_TYPES_H
#define MODEL2_GEO_TYPES_H

/* If i960_lift.h was included first, reuse its typedefs. */
#ifndef I960_LIFT_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;
#endif

#endif /* MODEL2_GEO_TYPES_H */
