/* Direct dispatch for RE-documented workram function-pointer tables.
 * See symbols/staging_tables.yaml — prefer direct calls in lifted C when the
 * target symbol is known at compile time; use these helpers for callx/indirect. */

#include "i960_host_staging.h"
#include "i960_host_invoke.h"
#include "lift_syms.h"
#include "model2_rom.h"
#include "i960_mem.h"

#include <stdio.h>

#define GAME_MODE_DISPATCH_BASE 0x005a2110u

int i960_host_staging_call_lifted(u32 workram_or_rom_pc)
{
    u32 rom;

    if (!workram_or_rom_pc)
        return 0;

    rom = i960_host_resolve_call_target(workram_or_rom_pc);
    switch (rom) {
    case 0x00003150u:
        game_dispatch_main((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001aa30u:
        game_inner_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000cc70u:
        tile_attract_mode_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000c5d0u:
        tile_attract_phase_comm((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000c750u:
        tile_attract_phase_slave((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000c840u:
        tile_attract_phase_network((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000c990u:
        tile_attract_phase_node((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000cbf0u:
        tile_attract_phase_finalize((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000fa00u:
        comm_attract_board_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000f840u:
        comm_attract_inner_0((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00012b70u:
        comm_attract_scene_alloc((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00012cc0u:
        comm_attract_scene_hud((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00012d90u:
        comm_attract_scene_hud_alt((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00013340u:
        comm_attract_hud_scroll_step((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000134a0u:
        comm_attract_hud_post_rank((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00014440u:
        game_start_mode_select((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00013ce0u:
        game_start_mode_select_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001abb0u:
        game_start_flags_init((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001b4d0u:
        game_start_phase_0((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00014160u:
        game_start_display_setup((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000144f0u:
        game_start_catalog_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00014788u:
        g0 = scene_lookup_fn((u32)g0, (u32)g1);
        return 1;
    case 0x0001b8c0u:
        attract_mode3_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c090u:
        game_start_champ_enter((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c0e0u:
        attract_scene_slot_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c140u:
        game_start_practice_enter((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c1a0u:
        game_start_practice_slot_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00015fd0u:
        game_start_course_display((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000162e0u:
        game_start_course_select((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00015380u:
        game_start_course_select_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00014d60u:
        game_start_car_display((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00015200u:
        game_start_car_select((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00014820u:
        game_start_car_select_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00015030u:
        g0 = game_start_select_confirm((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001bba0u:
        game_start_race_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c9c0u:
        game_start_race_sub_reset((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001ca30u:
        game_start_race_sub_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001ca70u:
        game_start_race_slot0((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001cd20u:
        game_start_race_slot1((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001ce30u:
        game_start_race_slot2((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001d160u:
        game_start_race_slot3((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001bf50u:
        game_start_race_timer_arm((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c808u:
        game_start_race_aea8_set((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001c8b8u:
        game_start_race_lap_tick((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000211f0u:
        game_start_race_countdown_prg((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00022768u:
        game_start_race_gate_bind((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000227b0u:
        game_start_race_gate_walk((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00022850u:
        game_start_race_obj_span_test((u32)g0, (void *)g1, (u32)g2);
        return 1;
    case 0x00022940u:
        game_start_race_obj_scan((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0003f9a0u:
        geo_countdown_object_step((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0003f4d0u:
        geo_countdown_keyframe_copy((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0003f550u:
        geo_countdown_keyframe_eval((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00034f40u:
        geo_view_scene_frame((void *)(uintptr_t)g0, (void *)(uintptr_t)g1,
                             (void *)(uintptr_t)g2);
        return 1;
    case 0x00020310u:
        game_start_race_cam_bind((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001f0d0u:
        game_start_race_cam_boot((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001dad0u:
        game_start_race_cgm_batch_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001e498u:
        game_start_race_hud_row_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001dc00u:
        game_start_race_hud_string_draw((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00047330u:
        game_start_race_rank_list_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001dd30u:
        game_start_race_cgm_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001e1d0u:
        game_start_race_hud_layers((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001e500u:
        game_start_race_hud_tach((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001e610u:
        game_start_race_hud_lap_time((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001ecc0u:
        game_start_race_hud_position((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001df40u:
        game_start_race_hud_speed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001edb0u:
        game_start_race_hud_progress((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001f1d0u:
        game_start_race_cam_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001fa20u:
        game_start_race_cam_desert((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002b580u:
        game_start_race_course_obj_init_4((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002b420u:
        game_start_race_course_obj_draw_4((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002bb80u:
        game_start_race_course_obj_init_21((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002bb50u:
        game_start_race_course_obj_draw_21((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00043790u:
        game_start_race_desert_node_init((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000427a0u:
        game_start_race_desert_node_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00041b78u:
        g0 = game_start_race_desert_table_pick((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00046470u:
        g0 = game_start_race_desert_slot_flag((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00041f80u:
        g0 = game_start_race_desert_near_pick((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000422b0u:
        game_start_race_desert_pose_step((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00041ca0u:
        game_start_race_desert_tgp55_walk((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00042190u:
        game_start_race_desert_obj_near_flag((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00041be0u:
        game_start_race_desert_rng_jitter((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000206e0u:
        game_start_race_cam_init((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001fdc0u:
        game_start_race_cam_chase((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002bcf0u:
        game_start_race_obj_car_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002cce0u:
        game_start_race_obj_car_integrate((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002f3c0u:
        game_start_race_obj_car_yaw_step((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0002f8a0u:
        g0 = game_start_race_obj_car_contact_solve(
            (u32)g0, (void *)(uintptr_t)g1, (void *)(uintptr_t)g2);
        return 1;
    case 0x000304f0u:
        game_start_race_obj_car_motion((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00030e00u:
        game_start_race_obj_car_velocity_step((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00023110u:
        game_start_race_obj_bind((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00022e20u:
        game_start_race_obj_list((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000219c0u:
        game_start_race_obj_seed((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00021918u:
        game_start_race_obj_seed_practice((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00020390u:
        game_start_race_cam_matrix((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000203d0u:
        game_start_race_cam_matrix_long((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00020740u:
        game_start_race_hud_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00021330u:
        game_start_race_geo_prg_thunk((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00021340u:
        game_start_race_geo_prg_hud_go((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00021370u:
        game_start_race_geo_prg_slot((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0003be30u:
        geo_attract_course_view_bind((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0001b940u:
        attract_hud_setup((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00032f70u:
        attract_logo_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000f4d0u:
        attract_credit_hud_init((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000f5f0u:
        attract_credit_hud_frame((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000bee0u:
        attract_credit_stamp_empty((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000bfa0u:
        attract_credit_stamp_paid((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00005830u:
        geo_scene_mode_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00004dd0u:
        geo_submode_dispatch((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00007fd0u:
        g0 = test_menu_exit((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00006400u:
        g0 = test_menu_input((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x000061e0u:
        test_menu_input_draw((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00006f80u:
        g0 = test_menu_game_assign((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00008840u:
        g0 = test_menu_memory((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00008b00u:
        g0 = test_menu_sound((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00006a20u:
        g0 = test_menu_crt((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000be30u:
        g0 = test_menu_coin((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00007670u:
        g0 = test_menu_output((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00007d80u:
        g0 = test_menu_drive((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x0000a3d0u:
        g0 = test_menu_bookkeeping((u32)g0, (u32)g1, (u32)g2);
        return 1;
    case 0x00007910u:
        g0 = test_menu_backup((u32)g0, (u32)g1, (u32)g2);
        return 1;
    default:
        return i960_host_invoke_lifted(rom);
    }
}

void i960_host_staging_call_mode_slot(u32 mode_index)
{
    u32 staged;

    staged = i960_ld_u32(I960_WORKRAM, GAME_MODE_DISPATCH_BASE, (mode_index & 15u) << 2);
    if (!staged)
        return;
    if (!i960_host_staging_call_lifted(staged))
        fprintf(stderr, "lift: unknown mode slot %u → 0x%08x (rom 0x%08x)\n",
                (unsigned)(mode_index & 15u), staged,
                i960_host_resolve_call_target(staged));
}
