#ifndef MODEL2_SND_SCSP_H
#define MODEL2_SND_SCSP_H

#include "model2_snd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void model2_snd_scsp_reset(void);
void model2_snd_scsp_midi_in(u8 byte);
int model2_snd_scsp_midi_pending(void);
u8 model2_snd_scsp_midi_pop(void); /* 0xFF if empty — ISR cmpi #$FF */

int model2_snd_scsp_timer_a_pending(void);
void model2_snd_scsp_timer_a_ack(void);
void model2_snd_scsp_cpu_cycles(unsigned insns);
/* 0 = TIMA from sample/thread ticks only (live). 1 = insn divider (headless boot). */
void model2_snd_scsp_tima_from_insns(int enable);
void model2_snd_scsp_tima_raise(void);
/* SCIEB bit 6 — 68k writes SCIEB=$00C8 during boot (0x60026E). */
int model2_snd_scsp_tima_armed(void);
/* Sample period from TACTL/TIMA: pris × (255 − TIMA). 0 = timer idle. */
unsigned model2_snd_scsp_tima_period_samples(void);
int model2_snd_scsp_midi_irq_armed(void);

u8 model2_snd_scsp_read8(u32 addr);
u16 model2_snd_scsp_read16(u32 addr);
void model2_snd_scsp_write8(u32 addr, u8 value);
void model2_snd_scsp_write16(u32 addr, u16 value);

void model2_snd_scsp_render(i16 *stereo, unsigned frames);
unsigned model2_snd_scsp_keyon_count(void);

u8 *model2_snd_soundram(void);

#ifdef __cplusplus
}
#endif

#endif
