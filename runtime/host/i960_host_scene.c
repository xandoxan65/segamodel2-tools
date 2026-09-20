#include "i960_host_scene.h"
#include "i960_mem.h"
#include "model2_memory.h"

#include <stdlib.h>

static int g_scene_seeded;

void i960_host_seed_scene_draw(void)
{
    const char *off;
    const char *boot;

    if (g_scene_seeded)
        return;

    boot = getenv("I960_HOST_BOOT_SCREEN");
    if (boot && boot[0] && boot[0] != '0')
        return;

    off = getenv("I960_HOST_GEO_DRAW");
    if (off && off[0] == '0')
        return;

    /*
     * game_mode_apply → mode 4 when gate @ 0x202074 bit 0 or flags @ 0x202064 bit 2.
     * Mode table 0x5A2110[4]=0x5A4830 → geo_scene_mode_dispatch.
     * Mode table 0x5A2110[6]=0x5A3DD0 → geo_submode_dispatch → geo_draw_frame_entry.
     */
    i960_st_u32(I960_WORKRAM, 0x202074, 0, 1);
    i960_st_u8(I960_WORKRAM, 0x202064, 0, (u8)(i960_ld_u8(I960_WORKRAM, 0x202064, 0) | 4u));

    /* Mode 4 → geo_scene_mode_dispatch @ staged 0x5A4830 (game_mode_apply promotes here). */
    i960_st_u32(I960_WORKRAM, 0x202098, 0, 4);
    i960_st_u32(I960_WORKRAM, 0x20209c, 0, 3);

    /* Desert course placement segment @ track_report placement_start=9, count=101. */
    i960_st_u32(I960_WORKRAM, 0x20c954, 0, 101);
    i960_st_u32(I960_WORKRAM, PLACEMENT_CURSOR, 0, 9);
    i960_st_u32(I960_WORKRAM, 0x20a2ec, 0, 9);
    i960_st_u32(I960_WORKRAM, 0x20c950, 0, 9);

    g_scene_seeded = 1;
}

int i960_host_scene_seeded(void)
{
    return g_scene_seeded;
}
