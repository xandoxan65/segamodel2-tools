/* Injected host callbacks — board RAM, display, geo RAM uploads.
 * Reusable across Model 2 titles; lift fills these from ROM map + viewer. */
#ifndef MODEL2_HW_HOST_H
#define MODEL2_HW_HOST_H

#include "model2_hw_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct model2_hw_host_ops {
    /* Workram u32 load by absolute vaddr (TGP 0x55 eye.y, view latch). NULL → 0. */
    u32 (*workram_ld_u32)(u32 vaddr);

    /* GEO cmd 0x04 / 0x05 / 0x15 side effects → geo render RAM. */
    void (*upload_texture)(u32 address, u32 count, const u32 *data);
    void (*upload_polygon)(u32 address, u32 count, const u32 *data);

    /* Vsync / live display (all optional). */
    double (*vsync_hz)(void);     /* default 57.524 if NULL */
    int (*display_wanted)(void);  /* nonzero → SDL/present pacing */
    int (*display_flip)(void);    /* present one frame; nonzero → quit */
    void (*boot_vblank)(void);    /* pre-flip tile/splash sync */
    void (*request_halt)(void);   /* display closed / halt dispatch */
} model2_hw_host_ops_t;

void model2_hw_bind_host(const model2_hw_host_ops_t *ops);
const model2_hw_host_ops_t *model2_hw_host(void);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_HW_HOST_H */
