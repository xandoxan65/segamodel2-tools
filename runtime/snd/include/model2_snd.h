/* Model 2A sound-board UART (i8251 / uPD71051C) HLE — stand-alone.
 *
 * Replaces i960 MMIO at 0x01C80000 (data) / 0x01C80002 (status/command).
 * Hardware sends those bytes as MIDI @ 31.25 kHz into the 68k+SCSP board
 * thread; this lib logs the stream and keeps TxRDY set so lifted timer0
 * drain proceeds. Does not contain uplifted game ROM code or a GM sequencer.
 */
#ifndef MODEL2_SND_H
#define MODEL2_SND_H

#include "model2_snd_types.h"
#include "model2_snd_host.h"

#ifdef __cplusplus
extern "C" {
#endif

void model2_snd_reset(void);

/* stderr 3-byte MIDI / command logging (--log-sound / I960_SND_LOG). */
void model2_snd_set_log(int enable);
int model2_snd_log_enabled(void);
void model2_snd_log_cmd(u32 index, u8 b0, u8 b1, u8 b2);

/* i8251 window: data @ 0x01C80000, status/command @ 0x01C80002. */
void model2_snd_mmio_write(u32 offset, u32 value);
u32 model2_snd_mmio_read(u32 offset);

/* Same as a data-port write. Queues a byte for the board thread (non-blocking). */
void model2_snd_midi_in(u8 byte);

/* Load 68k program + 8 MiB SCSP samples. 0 on success. */
int model2_snd_load_roms(const char *rom_dir);

/* Mix stereo s16le @ 44100. Pulls a ring filled by the 68k+SCSP thread. */
void model2_snd_render(signed short *stereo, unsigned frames);

/* Input log ring (bytes written to UART data). */
unsigned model2_snd_count(void);
unsigned model2_snd_total(void);
const u8 *model2_snd_bytes(unsigned *out_count);
unsigned model2_snd_copy_range(unsigned start_abs, unsigned end_abs, u8 *dst,
                               unsigned dst_cap);
void model2_snd_dump(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* MODEL2_SND_H */
