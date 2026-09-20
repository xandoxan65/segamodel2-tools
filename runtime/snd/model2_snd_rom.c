#include "model2_snd_rom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u8 *g_68k;
static u8 *g_samples;

static int read_file(const char *path, u8 **out, size_t want)
{
    FILE *fp;
    u8 *buf;
    size_t n;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    buf = (u8 *)malloc(want);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    n = fread(buf, 1, want, fp);
    fclose(fp);
    if (n != want) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

static void word_swap(u8 *p, size_t n)
{
    size_t i;
    u8 t;

    for (i = 0; i + 1u < n; i += 2u) {
        t = p[i];
        p[i] = p[i + 1u];
        p[i + 1u] = t;
    }
}

static int try_path(char *dst, size_t dst_sz, const char *dir, const char *name)
{
    FILE *fp;

    snprintf(dst, dst_sz, "%s/%s", dir, name);
    fp = fopen(dst, "rb");
    if (!fp)
        return -1;
    fclose(fp);
    return 0;
}

int model2_snd_rom_load(const char *rom_dir)
{
    char path[512];
    const char *dir = rom_dir && rom_dir[0] ? rom_dir : "../ROMS/srallyc-b";
    u8 *s0 = NULL, *s1 = NULL, *s2 = NULL, *s3 = NULL;

    model2_snd_rom_unload();

    if (try_path(path, sizeof(path), dir, "epr-17890a.30") != 0
        && try_path(path, sizeof(path), dir, "epr-17890.30") != 0)
        return -1;
    if (read_file(path, &g_68k, MODEL2_SND_68K_ROM_SIZE) != 0)
        return -1;
    word_swap(g_68k, MODEL2_SND_68K_ROM_SIZE);

    if (try_path(path, sizeof(path), dir, "mpr-17756.31") != 0)
        goto fail;
    if (read_file(path, &s0, 0x200000u) != 0)
        goto fail;
    if (try_path(path, sizeof(path), dir, "mpr-17757.32") != 0)
        goto fail;
    if (read_file(path, &s1, 0x200000u) != 0)
        goto fail;
    if (try_path(path, sizeof(path), dir, "mpr-17886.36") != 0)
        goto fail;
    if (read_file(path, &s2, 0x200000u) != 0)
        goto fail;
    if (try_path(path, sizeof(path), dir, "mpr-17887.37") != 0)
        goto fail;
    if (read_file(path, &s3, 0x200000u) != 0)
        goto fail;

    g_samples = (u8 *)malloc(MODEL2_SND_SAMPLE_ROM_SIZE);
    if (!g_samples)
        goto fail;
    memcpy(g_samples + 0x000000u, s0, 0x200000u);
    memcpy(g_samples + 0x200000u, s1, 0x200000u);
    memcpy(g_samples + 0x400000u, s2, 0x200000u);
    memcpy(g_samples + 0x600000u, s3, 0x200000u);
    /* ROM_LOAD16_WORD_SWAP — SCSP fetches 16-bit BE. */
    word_swap(g_samples, MODEL2_SND_SAMPLE_ROM_SIZE);
    free(s0);
    free(s1);
    free(s2);
    free(s3);
    return 0;

fail:
    free(s0);
    free(s1);
    free(s2);
    free(s3);
    model2_snd_rom_unload();
    return -1;
}

void model2_snd_rom_unload(void)
{
    free(g_68k);
    g_68k = NULL;
    free(g_samples);
    g_samples = NULL;
}

int model2_snd_rom_loaded(void)
{
    return g_68k && g_samples;
}

const u8 *model2_snd_68k_rom(void)
{
    return g_68k;
}

const u8 *model2_snd_sample_rom(void)
{
    return g_samples;
}
