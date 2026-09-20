/* MIDI assembler matching epr-17890a.30 ISR @ 0x600582 (SCSP MIBUF). */
#ifndef MODEL2_SND_MIDI_H
#define MODEL2_SND_MIDI_H

#include "model2_snd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct model2_snd_midi_msg {
    u8 status;
    u8 data1;
    u8 data2;
    u8 nbytes; /* 2 = program/pressure; 3 = note/cc/poly */
} model2_snd_midi_msg_t;

void model2_snd_midi_reset(void);
/* Returns 1 and fills *out when a complete message is assembled. */
int model2_snd_midi_push(u8 byte, model2_snd_midi_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_SND_MIDI_H */
