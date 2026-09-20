#include "model2_snd_midi.h"

static u8 g_status;
static u8 g_need;
static u8 g_got;
static u8 g_d1;

void model2_snd_midi_reset(void)
{
    g_status = 0;
    g_need = 0;
    g_got = 0;
    g_d1 = 0;
}

static u8 data_bytes(u8 status)
{
    u8 hi = status & 0xf0u;

    if (hi == 0xc0u || hi == 0xd0u)
        return 1u;
    if (hi >= 0x80u && hi <= 0xe0u)
        return 2u;
    return 0;
}

int model2_snd_midi_push(u8 byte, model2_snd_midi_msg_t *out)
{
    if (!out)
        return 0;

    if (byte >= 0xf0u)
        return 0; /* system / 0xFF empty — ISR bcc @ 0x600596 */

    if (byte & 0x80u) {
        g_status = byte;
        g_need = data_bytes(byte);
        g_got = 0;
        return 0;
    }

    if (g_need == 0u)
        return 0;

    if (g_got == 0u && g_need == 2u) {
        g_d1 = byte;
        g_got = 1;
        return 0;
    }

    out->status = g_status;
    if (g_need == 1u) {
        out->data1 = byte;
        out->data2 = 0;
        out->nbytes = 2;
    } else {
        out->data1 = g_d1;
        out->data2 = byte;
        out->nbytes = 3;
    }
    g_got = 0;
    return 1;
}
