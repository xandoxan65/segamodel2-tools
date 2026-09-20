"""Known maincpu symbol anchors (ported from segamod2 section map)."""

from __future__ import annotations

ROM_ANCHORS: tuple[tuple[int, str, str, str], ...] = (
    (0x0000B0, "boot_prcb", "high", "rodata"),
    (0x000420, "maincpu_reset_entry", "high", "code"),
    (0x003C00, "math_thunk_palette", "high", "code"),
    (0x004BA8, "placement_cursor_reset", "high", "code"),
    (0x012D00, "scene_setup_init", "high", "code"),
    (0x0146A8, "scene_classifier", "high", "code"),
    (0x014760, "scene_root_table", "high", "rodata"),
    (0x014788, "scene_lookup_fn", "high", "code"),
    (0x015524, "scene_descriptor_loader", "high", "code"),
    (0x016164, "scene_matrix_init", "high", "code"),
    (0x023CC8, "placement_geo_feeder", "high", "code"),
    (0x0282D0, "copy_catalog_index_table", "high", "code"),
    (0x029C10, "draw_scene_dispatch", "high", "code"),
    (0x029EB0, "catalog_draw_setup", "high", "code"),
    (0x0322F0, "placement_float_adjust", "high", "code"),
    (0x034E40, "vehicle_assembly_catalog", "high", "rodata"),
    (0x034E88, "vehicle_draw_list", "high", "rodata"),
    (0x03EF70, "catalog_draw_variant", "medium", "code"),
    (0x03F040, "object_name_strings", "high", "rodata"),
    (0x044F00, "draw_car_primary", "high", "code"),
    (0x05CDC8, "libc_strcpy", "high", "code"),
    (0x05CEC0, "libc_printf", "high", "code"),
    (0x05CF50, "libc_printf_dispatch", "high", "code"),
    (0x05DAA0, "libc_memcpy", "high", "code"),
    (0x009B70, "ui_course_strings", "high", "rodata"),
    (0x083600, "late_code_island", "low", "code"),
)
