/* Hand port of libc_strcpy @ 0x05cdc8 — use register args with I960_GCC_FLAGS (-O2 -mkb). */
typedef char *gptr;

gptr libc_strcpy(register gptr dst, register gptr src)
{
    register gptr d;
    register char c;

    if (dst == (gptr)0)
        return (gptr)0;
    if (*src == '\0')
        return (gptr)0;

    d = dst + -1;
    do {
        c = *src;
        src = src + 1;
        d = d + 1;
        *d = c;
    } while (c != '\0');

    return dst;
}
