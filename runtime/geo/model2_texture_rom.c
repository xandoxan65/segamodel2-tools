/* Load Model 2 textures ROM (ROM_LOAD32_WORD) — u16 tp/th pool. */

#include "model2_texture_rom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u16 *g_u16;
static unsigned g_n_u16;
static u32 g_mask;

static int read_file(const char *path, u8 **out, size_t *out_len)
{
    FILE *fp;
    long sz;
    u8 *buf;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    buf = (u8 *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int find_rom(const char *dir, const char *name, char *path, size_t path_sz)
{
    snprintf(path, path_sz, "%s/%s", dir, name);
    {
        FILE *fp = fopen(path, "rb");
        if (fp) {
            fclose(fp);
            return 0;
        }
    }
    return -1;
}

/*
 * MAME ROM_LOAD32_WORD: even bytes from low ROM, odd from high.
 * textures: mpr-17753.25 (low) + mpr-17752.24 (high).
 */
static int load32_word_to_u16(const char *dir, const char *low_name, const char *high_name,
                              u16 **out, unsigned *out_n)
{
    char low_path[512], high_path[512];
    u8 *low = NULL, *high = NULL;
    size_t low_len = 0, high_len = 0;
    size_t i, n_u16;
    u16 *dst;

    if (find_rom(dir, low_name, low_path, sizeof(low_path)) != 0)
        return -1;
    if (find_rom(dir, high_name, high_path, sizeof(high_path)) != 0)
        return -1;
    if (read_file(low_path, &low, &low_len) != 0)
        return -1;
    if (read_file(high_path, &high, &high_len) != 0) {
        free(low);
        return -1;
    }
    if (low_len != high_len || (low_len % 2u) != 0) {
        free(low);
        free(high);
        return -1;
    }
    /* Each pair of ROMs yields low_len/2 u32s = low_len u16s. */
    n_u16 = low_len;
    dst = (u16 *)malloc(n_u16 * sizeof(u16));
    if (!dst) {
        free(low);
        free(high);
        return -1;
    }
    for (i = 0; i < low_len; i += 2u) {
        size_t wi = i / 2u;
        /* Even u16 from low ROM word; odd u16 from high ROM word. */
        dst[wi * 2u] = (u16)(low[i] | ((u16)low[i + 1u] << 8));
        dst[wi * 2u + 1u] = (u16)(high[i] | ((u16)high[i + 1u] << 8));
    }
    free(low);
    free(high);
    *out = dst;
    *out_n = (unsigned)n_u16;
    return 0;
}

int model2_texture_rom_load_default(void)
{
    const char *dir;

    if (g_u16)
        return 0;

    dir = getenv("SEGAMOD2_ROM_DIR");
    if (!dir || !*dir)
        dir = getenv("DECOMP_ROM_DIR");
    if (!dir || !*dir)
        dir = "../ROMS/srallyc-b";

    if (load32_word_to_u16(dir, "mpr-17753.25", "mpr-17752.24", &g_u16, &g_n_u16) != 0) {
        fprintf(stderr, "lift: textures ROM load failed from %s\n", dir);
        return -1;
    }
    g_mask = g_n_u16 ? (g_n_u16 - 1u) : 0u;
    fprintf(stderr, "lift: textures ROM loaded %u u16 (mask 0x%x)\n", g_n_u16, g_mask);
    return 0;
}

const u16 *model2_texture_rom_u16(unsigned *out_count)
{
    if (out_count)
        *out_count = g_n_u16;
    return g_u16;
}

u32 model2_texture_rom_mask(void)
{
    return g_mask;
}

void model2_texture_rom_shutdown(void)
{
    free(g_u16);
    g_u16 = NULL;
    g_n_u16 = 0;
    g_mask = 0;
}
