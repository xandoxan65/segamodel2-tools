/* Load Model 2 polygon ROM (ROM_LOAD32_WORD pairs) for geo DL object draws. */

#include "model2_polygon_rom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *low;
    const char *high;
} poly_pair_t;

static const poly_pair_t POLY_PAIRS[] = {
    { "mpr-17748.16", "mpr-17750.20" },
    { "mpr-17749.17", "mpr-17751.21" },
};

static u32 *g_words;
static unsigned g_n_words;
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

static int load32_word_interleave(const char *dir, const char *low_name,
                                  const char *high_name, u8 **out, size_t *out_len)
{
    char low_path[512], high_path[512];
    u8 *low = NULL, *high = NULL;
    size_t low_len = 0, high_len = 0;
    size_t i, n_words;
    u8 *dst;

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
    n_words = low_len / 2u;
    dst = (u8 *)malloc(n_words * 4u);
    if (!dst) {
        free(low);
        free(high);
        return -1;
    }
    for (i = 0; i < low_len; i += 2u) {
        size_t wi = i / 2u;
        dst[wi * 4u + 0u] = low[i];
        dst[wi * 4u + 1u] = low[i + 1u];
        dst[wi * 4u + 2u] = high[i];
        dst[wi * 4u + 3u] = high[i + 1u];
    }
    free(low);
    free(high);
    *out = dst;
    *out_len = n_words * 4u;
    return 0;
}

int model2_polygon_rom_load_default(void)
{
    const char *dir;
    u8 *chunks[2];
    size_t lens[2];
    size_t total = 0;
    unsigned i;
    u8 *merged;
    size_t off;

    if (g_words)
        return 0;

    dir = getenv("SEGAMOD2_ROM_DIR");
    if (!dir || !*dir)
        dir = getenv("DECOMP_ROM_DIR");
    if (!dir || !*dir)
        dir = "../ROMS/srallyc-b";

    for (i = 0; i < 2; i++) {
        if (load32_word_interleave(dir, POLY_PAIRS[i].low, POLY_PAIRS[i].high,
                                   &chunks[i], &lens[i]) != 0) {
            fprintf(stderr, "lift: polygon ROM load failed (%s / %s) from %s\n",
                    POLY_PAIRS[i].low, POLY_PAIRS[i].high, dir);
            while (i > 0) {
                i--;
                free(chunks[i]);
            }
            return -1;
        }
        total += lens[i];
    }

    merged = (u8 *)malloc(total);
    if (!merged) {
        free(chunks[0]);
        free(chunks[1]);
        return -1;
    }
    off = 0;
    for (i = 0; i < 2; i++) {
        memcpy(merged + off, chunks[i], lens[i]);
        off += lens[i];
        free(chunks[i]);
    }

    g_n_words = (unsigned)(total / 4u);
    g_words = (u32 *)merged;
    g_mask = g_n_words ? (g_n_words - 1u) : 0u;
    fprintf(stderr, "lift: polygon ROM loaded %u words (mask 0x%x)\n", g_n_words, g_mask);
    return 0;
}

const u32 *model2_polygon_rom_words(unsigned *out_count)
{
    if (out_count)
        *out_count = g_n_words;
    return g_words;
}

u32 model2_polygon_rom_mask(void)
{
    return g_mask;
}

void model2_polygon_rom_shutdown(void)
{
    free(g_words);
    g_words = NULL;
    g_n_words = 0;
    g_mask = 0;
}
