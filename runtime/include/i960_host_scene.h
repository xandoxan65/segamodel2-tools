#ifndef I960_HOST_SCENE_H
#define I960_HOST_SCENE_H

/* Seed workram scene/draw state once after cold boot (static RE tables). */
void i960_host_seed_scene_draw(void);

/* Non-zero after i960_host_seed_scene_draw(). */
int i960_host_scene_seeded(void);

#endif
