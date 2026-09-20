/* Injected host callbacks for sound UART / MIDI HLE.
 * Audio backends (SDL, later 68k+SCSP) bind here; the lib does not own DAC. */
#ifndef MODEL2_SND_HOST_H
#define MODEL2_SND_HOST_H

#include "model2_snd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct model2_snd_host_ops {
    /* One MIDI byte that left UART Tx (SCSP midi_in on hardware). NULL → log only. */
    void (*on_midi_byte)(u8 byte);
} model2_snd_host_ops_t;

void model2_snd_bind_host(const model2_snd_host_ops_t *ops);
const model2_snd_host_ops_t *model2_snd_host(void);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_SND_HOST_H */
