#include "i960_host_staging.h"

u32 i960_host_resolve_call_target(u32 vaddr)
{
    if (vaddr >= MODEL2_WORKRAM_STAGING_VADDR
        && vaddr < MODEL2_WORKRAM_STAGING_VADDR + MODEL2_WORKRAM_STAGING_SIZE) {
        return MODEL2_ROM_STAGING_SRC + (vaddr - MODEL2_WORKRAM_STAGING_VADDR);
    }
    /* libc printf jump-table targets: staged VA @ 0x005Fxxxx → ROM @ 0x005Dxxxx */
    if (vaddr >= 0x005f0000u && vaddr < 0x00600000u)
        return vaddr - 0x0059f000u;
    return vaddr;
}

int i960_host_is_staged_workram(u32 vaddr)
{
    return vaddr >= MODEL2_WORKRAM_STAGING_VADDR
        && vaddr < MODEL2_WORKRAM_STAGING_VADDR + MODEL2_WORKRAM_STAGING_SIZE;
}
