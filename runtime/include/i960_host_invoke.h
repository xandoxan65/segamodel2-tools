#ifndef I960_HOST_INVOKE_H
#define I960_HOST_INVOKE_H

#include "i960_lift.h"

/* Call lifted C for ROM PC if available. Returns 1 when handled. */
int i960_host_invoke_lifted(u32 rom_addr);
int i960_host_invoke(u32 rom_addr);

#endif
