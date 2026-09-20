#!/usr/bin/env python3
"""Disasm-only provenance matrix for desert ``0x1111`` / ``D`` palette upload.

Every entry cites a ROM address and instruction effect from ``decomp/disasm/``.
No MAME captures. Hypotheses and Python replay modes are labeled separately.

  python3 -m tools.decomp.palette_disasm_provenance
  python3 -m tools.decomp.palette_disasm_provenance --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.model2_cgm_g13_table import g13_mask_for_slot

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Proven from static disasm (source of truth) -----------------------------

PROVEN_INSTRUCTIONS: tuple[dict, ...] = (
    {
        "id": "d_handler_setbit",
        "rom": "0x05D3DC",
        "disasm": "maincpu_05cf50_a00.asm",
        "effect": "``D`` format char: ``setbit 0,r9``; optional ``r13`` from ``-4(fp)[idx]``; ``g6=10`` → ``0x05D7E8``",
    },
    {
        "id": "template_copy_5d7e8",
        "rom": "0x05D7E8",
        "disasm": "maincpu_05cf50_a00.asm",
        "effect": (
            "Copy ``repeat % 10`` bytes from ``0x005FBF10`` template rows into emit "
            "buffer @ ``0x19c(fp)`` (growing ``r6``); ``r7`` = outer repeat"
        ),
    },
    {
        "id": "emit_5d860",
        "rom": "0x05D860",
        "disasm": "maincpu_05cf50_a00.asm",
        "effect": (
            "Loop ``bal 0x027008`` for ``r10`` iterations; link bytecode chain via "
            "``lda 0x1(r11),r11``; ``r9`` bit 0 preserved into emit metadata"
        ),
    },
    {
        "id": "compile_5cf50_state",
        "rom": "0x05CF50",
        "disasm": "maincpu_05cf50_a00.asm",
        "effect": (
            "``r5``=arena frame ``(r5)``/``+4(r5)``; ``r12``=format scan; ``r11``=bytecode "
            "chain; ``r9``=format flags; ``g8``=``0x005FBF10``; char dispatch via "
            "``0x005FBFD0[g4*4]``"
        ),
    },
    {
        "id": "slot_routing_29f7c",
        "rom": "0x029F7C",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "When ``0x20C954 <= 0x1FF`` (@ ``0x029FCC``) **and** ``0x05CE18`` matched "
            "(``0x029EF0`` path): per inner count ``r4``, fill ``0x20B950[row]`` and "
            "``bal 0x02A0F8``. Desert @ ``0x012E3C``: ROM mirror template ``CGM 1.0 ``, "
            "gate → matched stream (not ``0x02A01C``). Slot 477 tier-B decode inside "
            "stream still OPEN"
        ),
    },
    {
        "id": "overflow_compile_29ed8",
        "rom": "0x029ED8",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "When ``0x20C954 > 0x1FF`` at record **entry**: ``0x02A004`` → compile ROM-mirror "
            "string ``Color Group Full !! [%08x]`` (@ ``0x005C8E70``) → ``0x029958`` — "
            "diagnostic path, not ``0x1111`` payload"
        ),
    },
    {
        "id": "span_wrap_compile_29f24",
        "rom": "0x029F24",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "When ``0x20C950 + span > 0xFFFF`` during matched walk → ``0x02A004`` "
            "(u16 wrap guard — **not** slot>511 check)"
        ),
    },
    {
        "id": "1111_record_dispatch",
        "rom": "0x029EB0",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "Per inner record at overflow (@ ``0x029FD0``): ``g5 = r11 & 7``; "
            "``cmpibl 3,g5,0x29ffc`` → if ``(entry_g4 & 7) < 3`` skip ``0x029C10`` "
            "(``0x029FFC`` ret); else ``call 0x029C10``"
        ),
    },
    {
        "id": "5ce18_stream_gate",
        "rom": "0x05CE18",
        "disasm": "maincpu_05ce18_300.asm",
        "effect": (
            "8-byte lexicographic compare: chain @ ``g0`` (block ``lda 0(g2)``) vs "
            "template @ ``0x005C8E60``. ``g0==0`` → ``0x029EF0`` stream walk; else "
            "``0x02A01C`` mismatch compile"
        ),
    },
    {
        "id": "1111_compile_run",
        "rom": "0x02A034",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "``call 0x05CEC0`` then ``bal 0x029958`` — on ``0x02A004`` (``0x20C954>0x1FF``) "
            "or ``0x02A01C`` (``0x05CE18`` mismatch); both skip ``0x29EF0`` stream walk"
        ),
    },
    {
        "id": "post_compile_run_29958",
        "rom": "0x029958",
        "disasm": "maincpu_029900_300.asm",
        "effect": (
            "After ``0x05CEC0``/``0x05CF50`` compile: ``bx (0x005C8964)`` — runs patched "
            "bytecode; desert ``0x029EB0`` mismatch path @ ``0x02A038``"
        ),
    },
    {
        "id": "palette_init_upload_sweeps",
        "rom": "0x012E60",
        "disasm": "maincpu_012d00_200.asm",
        "effect": (
            "Five ``call 0x029C10`` sweeps with ``g2=0x20A79C`` after alpine+desert "
            "``0x029EB0`` compile; ``g4=2`` → ``g2<0`` compile+run routing"
        ),
    },
    {
        "id": "staging_bootstrap_27260",
        "rom": "0x027260",
        "disasm": "maincpu_027260_200.asm",
        "effect": (
            "Pre-compile chain patch: ``stos g14,(g5)`` × ``g2`` per row; rows linked "
            "via ``+0x80``; base ``0x01000000 + (g1<<7) + 2*g0`` (@ ``0x012DE4``/``0x012DF8``)"
        ),
    },
    {
        "id": "palette_init_20b914_seed",
        "rom": "0x012DB0",
        "disasm": "maincpu_012d00_200.asm",
        "effect": "``stos 0xC000,0x20B914`` — u16 stream head (``0x026980`` source if invoked)",
    },
    {
        "id": "record_indirect_2a0f8",
        "rom": "0x02A0F8",
        "disasm": "maincpu_02a0f8_400.asm",
        "effect": (
            "``ldis 0x10(g0),g4``; ``ldis 0x12(g0),g5``; ``mulo g4,g5,g4``; "
            "``lda 0x14(g0)[g4*2],g0``; ``bx (g1)`` — on ``0x029F7C`` path ``g1=g14`` "
            "(``bal`` return @ ``0x29FA0``) → immediate return; handler word not branched"
        ),
    },
    {
        "id": "span_materialize_2a050",
        "rom": "0x02A050",
        "disasm": "maincpu_02a050_150.asm",
        "effect": (
            "Matched stream only (@ ``0x29F34``): span copy ``ldos`` → ``0x1080000`` "
            "bus, ``ldq``/``stq`` 32-byte nodes, ``bal 0x026918`` scratch flush; "
            "``st r5,(g9)`` cursor writeback"
        ),
    },
    {
        "id": "bind_stream_index_26f44",
        "rom": "0x026F44",
        "disasm": "maincpu_026e18_200.asm",
        "effect": (
            "``0x026F40`` loads LE halfword from bytecode stream; ``0x026F44`` indexes "
            "``0x20B1C0[g4*4]``. Slot-477 D bytecode ``[0x20,0x00,…]`` → index ``0x0020`` "
            "(32), **not** descriptor-bus word ``0x8420`` @ ``0x01000000``"
        ),
    },
    {
        "id": "29c10_matched_fifo_add",
        "rom": "0x29CFC",
        "disasm": "maincpu_029c10_300.asm",
        "effect": (
            "Matched ``0x29FF8`` tail: ``ldos (g7),g4`` @ ``0x29CF8`` then ``addo g13,g4,g4`` "
            "— **ADD** into ``0x01000000`` staging; not ``0x02A258`` XOR; not ``xor_table``"
        ),
    },
    {
        "id": "desert_stream_node_plus_08",
        "rom": "0x29F0C",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "Static desert ``block+0x08``: span=0x10, inner=0xFFFF, link @ ``+0x0C`` = "
            "``0x22F77C00`` (unique in main_data); byte1 ``0x7C`` == offset to ``block+0x7C``"
        ),
    },
    {
        "id": "fp_plus_40_block_head",
        "rom": "0x029ED4",
        "disasm": "maincpu_029eb0_600.asm",
        "effect": (
            "``fp+0x40`` = ``lda 0(g2)`` block dword; gate match via identical pointer "
            "``0x204D4743`` both chains; **no** ROM ``st`` to ``0x028CCAF8`` (``lda`` refs only @ ``0x012E2C``)"
        ),
    },
    {
        "id": "xor_batch_2a258",
        "rom": "0x02A258",
        "disasm": "maincpu_02a0f8_400.asm",
        "effect": (
            "``xor g4,g13,g4`` inside ``0x02A200`` only when ``cmpi g3,0`` / ``ble 0x2A27C`` "
            "fails — ``#`` batch path with ``g3>0``"
        ),
    },
    {
        "id": "legacy_add_29cfc",
        "rom": "0x29CFC",
        "disasm": "maincpu_029c10_300.asm",
        "effect": (
            "``addo g13,g4,g4`` then ``stos g4,(g6)`` — legacy path when ``0x029C10`` "
            "runs (``(entry_g4 & 7) >= 3`` at ``0x29FE4``); bypassed for desert ``0x1111`` "
            "inner records with low ``g4`` tag"
        ),
    },
    {
        "id": "g13_table_formula_2a3ac",
        "rom": "0x02A3AC",
        "disasm": "maincpu_02a0f8_400.asm",
        "effect": (
            "Per-slot table fill: ``lda 0x8000(g5)[g0],g5`` after ``addo g13,g5,g5`` "
            "(``g4==0`` branch @ ``0x2A39C``) — builds bus table from ``0x20C958`` seed"
        ),
    },
    {
        "id": "fifo_runner_merge_gate",
        "rom": "0x02A61C",
        "disasm": "maincpu_02a5a0_2b0.asm",
        "effect": (
            "``bbc 0,r5,0x2A630`` — when saved ``g5`` bit 0 set: ``call 0x02A4E0`` with "
            "``g0=r10``, ``g1=r9``, ``g2=r14`` (original entry ``g4``)"
        ),
    },
    {
        "id": "wrapper_2a6d0",
        "rom": "0x02A6D0",
        "disasm": "maincpu_02a5a0_2b0.asm",
        "effect": (
            "First ``call 0x02A5A0``: ``g2=orig g0``; saves ``g4→r6``; subsequent calls "
            "vary ``g0``/``g1``/``g3`` — ``g4`` restored from ``r6`` each time"
        ),
    },
    {
        "id": "clone_26800_node",
        "rom": "0x026800",
        "disasm": "maincpu_026700_300.asm",
        "effect": (
            "List @ ``0x20B600``: ``g0=*(node+0)``; ``r5=*(node+4)``; ``g1=*r5``; "
            "``g2=*(node+8)``; ``call 0x5DAA0``; ``next node=*(node+0xC)``; ``r5+=12``"
        ),
    },
    {
        "id": "palram_commit_26918",
        "rom": "0x026918",
        "disasm": "maincpu_026700_300.asm",
        "effect": "Scratch flush entry — ``bx`` through ``0x005C5974`` trampoline",
    },
)

OPEN_GAPS: tuple[dict, ...] = (
    {
        "id": "1111_single_d_decode",
        "status": "open",
        "note": (
            "No ``xor g13`` / ``addo g13`` between FIFO consumption and ``0x02A62C`` merge "
            "on the ``0x1111`` compile path. ``0x02A258`` XOR is ``#``-batch only. "
            "``0x29CFC`` ADD is ``0x029C10`` legacy only."
        ),
    },
    {
        "id": "1111_runtime_driver_negative",
        "status": "open",
        "note": (
            "``palette_1111_driver_negative_re`` + ``palette_20b910_dispatch_re``: zero static "
            "``call 0x026980``; ``+0x22`` chain hits ``0x1111`` @ block ``+0x4C`` but matched "
            "init never replays payload to slot 477; ``0x20B910`` dispatch is runtime-only"
        ),
    },
    {
        "id": "20b910_single_static_st",
        "status": "proven",
        "note": (
            "``palette_20b910_dispatch_re``: only ``st g14,0x20B910`` @ ``0x026704``; "
            "``0x0269C4`` ``callx`` gated on nonzero — no static ROM path sets handler entry"
        ),
    },
    {
        "id": "1638c_course_hook_no_bootstrap",
        "status": "proven",
        "note": (
            "``palette_20b910_dispatch_re`` + ``palette_indirect_dispatch_re``: "
            "``0x01638C`` ``stos`` ``0x20B914`` only; ``0x0162E0`` orphan (zero callers/refs)"
        ),
    },
    {
        "id": "5b36xx_runtime_dispatch_tables",
        "status": "proven",
        "note": (
            "``palette_indirect_dispatch_re``: ``0x005B3690``/``0x005B36DC``/``0x005B375C`` "
            "zero in static ROM — ``0x014788``/``0x0146A8`` indirect ``bx`` needs runtime fill"
        ),
    },
    {
        "id": "14530_static_upload_analogue",
        "status": "proven",
        "note": (
            "``palette_course_pointer_cluster_re``: ``0x014530`` via ``0x20A8B4`` "
            "(``0x029EB0`` **return** @ ``0x014518``, block ``0x0208E9E4``) — not desert ``0x1111``"
        ),
    },
    {
        "id": "20a8b4_29eb0_return_not_block",
        "status": "proven",
        "note": (
            "``palette_course_pointer_cluster_re``: sole ``st`` @ ``0x014518`` stores "
            "``0x029EB0`` return; ``0x20A7B4`` @ ``0x012C04`` from ``0x0286A980`` — not desert"
        ),
    },
    {
        "id": "pre_palette_29eb0_no_desert",
        "status": "proven",
        "note": (
            "``palette_pre_palette_29eb0_re``: six ``0x029EB0`` @ ``0x012B80``–``0x012C58`` "
            "on non-desert blocks; static ``call 0x012B70`` @ ``0x0137D4``; early "
            "``0x029C10`` @ ``0x012C90`` (helper entry ``0x012C70``)"
        ),
    },
    {
        "id": "12d90_indirect_entry_only",
        "status": "proven",
        "note": (
            "``palette_12d90_indirect_entry_re``: full-ROM scan — **zero** static ``call``/``bal`` "
            "to ``0x012D90``; **zero** ROM dwords ``0x00012D90``; ``0x014788`` ``bx`` analogue only"
        ),
    },
    {
        "id": "12d9c_mode3_skips_desert_compile",
        "status": "proven",
        "note": (
            "``palette_12d90_indirect_entry_re``: ``0x20A530==3`` @ ``0x012D9C`` → ``ret`` @ ``0x12DA0`` "
            "before ``0x012E3C`` desert ``0x029EB0``"
        ),
    },
    {
        "id": "00fb58_pre_palette_orchestrator",
        "status": "proven",
        "note": (
            "``palette_12d90_indirect_entry_re``: ``0x00FB58`` → ``0x0137D0`` "
            "(``0x016B70``/``0x012B70``/``0x016B40``); **zero** static entry to ``0x00FB00`` band"
        ),
    },
    {
        "id": "20a530_c674_dispatch_hub",
        "status": "proven",
        "note": (
            "``palette_20a530_dispatch_re``: ``0x00C674`` ``st g14,0x20A530`` + ``bx`` on "
            "``0x20201B`` via mirror table ``0x00C68C``; **no** static ``mov 3`` store"
        ),
    },
    {
        "id": "1320c_tail_calls_12c70",
        "status": "proven",
        "note": (
            "``palette_12d90_indirect_entry_re``: ``0x01320C`` ``call 0x012C70`` from "
            "``0x012D90`` exit tail — **not** an entry edge to ``0x012D90``"
        ),
    },
    {
        "id": "5b375c_mirror_embedded_scaffold",
        "status": "proven",
        "note": (
            "``palette_20a530_dispatch_re``: ``0x005B375C`` ROM mirror @ ``0x01475C`` "
            "aliases embedded ``0x014760`` range-table ptrs (not zero-filled)"
        ),
    },
    {
        "id": "c674_hub_cabinet_not_cgm",
        "status": "proven",
        "note": (
            "``palette_20a530_dispatch_re``: ``0x00C674`` ``bx`` table prints "
            "``THIS IS MASTER/SLAVE/RELAY MACHINE`` — cabinet routing, not ``0x1111``"
        ),
    },
    {
        "id": "14530_no_desert_1111_catalog",
        "status": "proven",
        "note": (
            "``palette_pre_palette_29eb0_re``: ``0x0208E9E4`` (``0x0144F0``) has zero ``0x1111``; "
            "only ``0x028CCAF8``/``0x02ACCAF8`` in CGM catalog — ``0x014530`` cannot bind desert format"
        ),
    },
    {
        "id": "14530_g4_zero_compile_not_add",
        "status": "proven",
        "note": (
            "``palette_pre_palette_29eb0_re``: ``0x014530`` ``g4=0`` → ``0x29D84``/``0x29C34`` "
            "compile+run — not tier-A ``0x29CFC`` ADD; max slot ≪ 477"
        ),
    },
    {
        "id": "1111_payload_not_29f_stream",
        "status": "open",
        "note": (
            "``palette_1111_stream_walk_re``: ``0x1111`` body is marker/FIFO binary, not "
            "``0x29F0C`` node stream; ``0x8843`` @ FIFO ``0x3A6`` (chunk 87) ≠ payload "
            "direct hits ``0x4A3``/``0x53F``"
        ),
    },
    {
        "id": "inner_tail_29fd0_skips_29c10",
        "status": "proven",
        "note": (
            "``palette_29fe4_g4_gate_re``: desert ``g4=4`` → ``0x29FE4`` skips ``0x29C10``; "
            "``0x29F7C`` fills ``0x20B950`` rows only. Slot 477 needs ``0x1111`` body driver "
            "(``palette_1111_driver_negative_re`` — no static replay path)"
        ),
    },
    {
        "id": "20c950_vs_20c954",
        "status": "proven",
        "note": (
            "``palette_slot477_counter_axes_re``: replay slot 477 = ``0x20C950`` cursor; "
            "``0x20C954`` is group-table index @ ``0x029F7C`` — different namespace. "
            "Static prefix walk max ``20C950=30``; ``0x02A120`` has zero static refs."
        ),
    },
    {
        "id": "record_plus14_not_static_pointer",
        "status": "proven",
        "note": (
            "``palette_record_plus14_fifo_re``: desert block ``+0x14`` = ``0x03FF3231`` (not a pointer); "
            "``0x29F9C`` stores block dword ``0x204D4743`` to row ``+4``; ``0x29CDC`` FIFO cursor "
            "requires runtime fixup. ``D`` path skips ``0x05DE00`` ``+0x14`` fill."
        ),
    },
    {
        "id": "slot477_fifo_read_index",
        "status": "proven",
        "note": (
            "``palette_record_plus14_fifo_re``: replay slot 477 ``0x8843`` @ FIFO ``0x3A6`` "
            "after **463** prior u16 reads (format-walk order) — not ``0x29CC4`` group index."
        ),
    },
    {
        "id": "8964_static_ret_no_st",
        "status": "proven",
        "note": (
            "``palette_slot477_dual_path_re``: ROM mirror @ ``0x005C8964`` is ``ret``; "
            "**zero** ROM ``st`` immediate sites — ``0x02A038`` ``bx`` returns unless "
            "runtime-patched. Desert matched init **never** calls ``0x029958``."
        ),
    },
    {
        "id": "slot477_fifo_3a6",
        "status": "proven",
        "note": (
            "``palette_slot477_dual_path_re`` + replay: ``0x8843`` @ FIFO ``0x3A6`` "
            "(chunk 87); oracle ``0x6683``; payload direct hits ``0x4A3``/``0x53F`` differ."
        ),
    },
    {
        "id": "handler_template_26690_palram_pack",
        "status": "proven",
        "note": (
            "``palette_handler_template_26690_re`` + MAME ``maincpu_026670_120.asm``: "
            "``0x26690`` template packs bitmap via ``0x26B94``/``0x26C44`` into "
            "``0x01080000`` rows — **no** CGM FIFO ``ldos``, **no** ``xor g13``; "
            "does **not** call upload ``0x02A4E0``/``0x02A6D0``."
        ),
    },
    {
        "id": "workram_mirror_handler_template",
        "status": "proven",
        "note": (
            "``palette_workram_thunk_mirror_re``: ROM mirror @ ``0x26690`` (list ``0x005C5670``) "
            "contains handler code touching ``0x01040000``/``0x01080000`` — **no** ``xor g13`` in "
            "``0x26200``–``0x27300`` band. Upload cluster: **0** static ROM word refs."
        ),
    },
    {
        "id": "upload_cluster_no_fifo",
        "status": "proven",
        "note": (
            "``palette_d_merge_wrapper_re``: ROM ``0x02A200``–``0x02A740`` has no parameter-FIFO "
            "``ldos``; ``xor g13`` only @ ``0x02A258`` (# batch). ``0x02A62C`` merge ``g2=r14`` "
            "= wrapper ``g4``, not raw FIFO. D path skips ``0x05DE00`` / ``record+0x14`` table."
        ),
    },
    {
        "id": "29c10_tier_ab_branch",
        "status": "proven",
        "note": (
            "``palette_29c10_tier_b_re``: ``(g4&7)>=3`` → tier-A ``0x20B950`` FIFO+``0x29CFC`` ADD; "
            "alternate ``0x20B954`` tier-B @ ``0x29E48`` subtract-index. Desert ``g4=4`` → tier-A. "
            "Lone ``D`` uses ``0x02A4E0`` merge — not ``0x29CFC``."
        ),
    },
    {
        "id": "disasm_decode_matrix",
        "status": "proven",
        "note": (
            "``palette_disasm_decode_re``: ``D``→merge OPEN, ``U``→``0x29CFC`` ADD, ``#``→``0x02A258`` XOR. "
            "278 tier-B geometry slots; 254 diverge under ADD replay vs xor_table oracle."
        ),
    },
    {
        "id": "compiled_thunk_body",
        "status": "open",
        "note": (
            "``0x005C8964`` / ``0x20B1C0[0x20]`` handler bodies are workram-only in "
            "static ROM. Bind index ``0x0020`` from D bytecode chain is proven; "
            "cloned record contents and ``0x005C8964`` runner body remain OPEN."
        ),
    },
    {
        "id": "merge_bus_coords",
        "status": "open",
        "note": (
            "``0x02A4E0`` expects ``g0``/``g1`` from ``0x02A2E0`` globals (``0x20C95C``–"
            "``0x20C968``). Wrapper ``r10``/``r9`` source for tier-B slot 477 not traced "
            "from static ROM alone."
        ),
    },
    {
        "id": "template_row_5fbf10",
        "status": "proven",
        "note": (
            "``palette_5fbf10_template_re``: workram ``0x005FBF10`` mirrors ROM @ ``0x05CF10`` "
            "(``0123456789`` row0 …). ``0x012DE4`` ``0x027260`` is a **separate** boot stub batch."
        ),
    },
    {
        "id": "8964_runner_not_desert_matched",
        "status": "open",
        "note": (
            "``palette_8964_runner_mirror_re``: runner image **is** in ROM mirror @ ``0x029964`` "
            "(``%-11s:%-8d`` / ``CgmPut ERROR`` formats); desert @ ``0x012E3C`` gate match "
            "→ ``0x029EF0`` ret — **no** ``bal 0x029958``. Slot 477 tier-B (>127) uses "
            "``0x29C10``/``0x02A4E0`` paths, not printf harness"
        ),
    },
    {
        "id": "workram_rom_mirror_59f000",
        "status": "proven",
        "note": (
            "``rom = workram - 0x0059F000``: slab template ``CGM 1.0 ``, format handlers "
            "@ ``0x005FCxxx`` ↔ ``0x0005Dxxx``, ``0x005C8964`` mirror = ``ret`` @ ``0x00029964``"
        ),
    },
    {
        "id": "26e18_counter_seed",
        "status": "proven",
        "note": (
            "``bal 0x026E18`` @ ``0x02A024`` before ``lda 0x005C8E90`` only seeds "
            "``0x20B1A8``/``0x20B1AC`` — **not** arena slab population"
        ),
    },
    {
        "id": "embedded_format_5cf10",
        "status": "proven",
        "note": (
            "Format digit rows @ ``0x005CF10``/``0x005CF30`` embedded in ``0x05CF50`` "
            "table — zero ROM word xrefs; ``0x005C8E90`` must hold runtime pointer"
        ),
    },
    {
        "id": "20b1c0_no_rom_stores",
        "status": "proven",
        "note": (
            "Zero ROM ``st``/``stq`` to ``0x20B100``–``0x20BFFF``; ``0x20B1C0`` only "
            "``lda`` @ ``0x026F44``/``0x026F94``. ``0x026980`` clone has **no** static callers"
        ),
    },
    {
        "id": "2a6d0_merge_wrapper",
        "status": "partial",
        "note": (
            "``0x02A6D0`` saves ``g0..g4``, calls ``0x02A5A0``; merge @ ``0x02A62C`` when "
            "``r5`` bit 0 with ``g2=r14`` (entry ``g4``). Caller from ``0x005C8964`` OPEN"
        ),
    },
    {
        "id": "29fa0_no_xor",
        "status": "proven",
        "note": (
            "``palette_29fa0_2a0f8_re``: ``0x29FA0`` ``bal 0x02A0F8`` returns @ ``0x02A114`` "
            "before ``0x02A200`` XOR body — matched stream cannot hit ``0x02A258``"
        ),
    },
    {
        "id": "27260_g14_return_link",
        "status": "proven",
        "note": (
            "``0x027260`` ``stos g14`` @ ``0x012DE4`` boot: ``g14`` = ``call`` return address "
            "(``0x012DE8``), not stub mirror / not zero (contrast ``0x0271D0``)"
        ),
    },
    {
        "id": "desert_matched_path_29ff8",
        "status": "proven",
        "note": (
            "``palette_desert_path_split_re``: ``0x012E3C`` gate match → ``0x29EF0`` stream → "
            "``0x29F7C`` inner — **not** mismatch ``0x02A038`` ``bal 0x029958``"
        ),
    },
    {
        "id": "29fe4_skips_29c10_desert_g4",
        "status": "proven",
        "note": (
            "``palette_29fe4_g4_gate_re``: ``0x29FE4`` ``cmpibl 3,(g4&7)`` — desert ``g4=4`` "
            "**skips** ``0x29FF8`` ``call 0x029C10``; prior ``>=3`` tier-A tail notes were wrong"
        ),
    },
    {
        "id": "fp40_stream_root_math",
        "status": "proven",
        "note": (
            "``palette_fp40_stream_root_re``: ``0x29ED4`` stores head dword ``0x204D4743``; "
            "``ld (r5)`` needs ``*r5`` = ``block_vaddr-8`` so ``*r5+8`` → node @ ``block+0x08``. "
            "Static block+0 ≠ required outer — runtime fixup OPEN; gate byte-compare still selects match"
        ),
    },
    {
        "id": "hash_compile_xor_unreachable_matched",
        "status": "proven",
        "note": (
            "``palette_hash_compile_xor_re``: ``#`` @ ``0x05D1C8`` → emit @ ``0x05D860``; "
            "zero static refs to ``0x02A200``; desert matched init never ``0x05CEC0`` compile. "
            "Slot 477 fragment has no ``#`` — ``0x6683`` xor oracle not on ``#`` batch for that frag"
        ),
    },
    {
        "id": "self_pointer_block_word0",
        "status": "proven",
        "note": (
            "``palette_self_pointer_fixup_re``: ``block+0 = block_vaddr`` unifies "
            "``0x05CE18`` ``ldob (g0)`` + ``0x29EF4`` ``*r5+8`` → ``block+0x08`` node; "
            "static ``0x204D4743`` fails both pointer models"
        ),
    },
    {
        "id": "single_29eb0_no_slot477",
        "status": "proven",
        "note": (
            "``palette_self_pointer_fixup_re``: one ``0x029EB0`` record adds one span "
            "(desert ``20C950=30``); ``0x29F7C`` inner loop does not advance ``20C950``; "
            "``0x012E3C`` single call cannot reach replay slot 477"
        ),
    },
    {
        "id": "271d0_zero_fill",
        "status": "proven",
        "note": (
            "``0x0271D0``/``0x027160``: ``mov 0,g14`` then ``stos g14`` — **zero-fill** link "
            "halfwords; ``0x005C6250`` is ``bx (g1)`` return only, not stored into bus"
        ),
    },
    {
        "id": "desert_20a7b0_consumer",
        "status": "proven",
        "note": (
            "``palette_self_pointer_fixup_re``: ``0x012E48`` ``st g0,0x20A7B0`` after desert "
            "``0x029EB0`` — **zero** static ``ld`` refs; upload sweeps @ ``0x012E60`` use "
            "``0x20A79C`` (alpine) only — dead store in static model"
        ),
    },
)

PYTHON_REPLAY: tuple[dict, ...] = (
    {
        "mode": "xor_table",
        "code": "``decode_d_u16`` / ``decode_rom_u16_xor``",
        "formula": "``color15 = (raw_u16 ^ g13_mask_for_slot(0x20C958 seed, slot)) & 0x7FFF``",
        "g13_formula_rom": "0x02A3AC table fill (proven); XOR **application** for lone ``D`` (unproven)",
        "geometry_oracle": "``palette_d_path_compare``: xor_table 0 diffs vs exported desert geometry",
        "hardware_equivalence": "not proven — Python replay convenience only",
    },
)


def tier_b_snapshot(*, slot: int, raw_u16: int, g13_seed: int = 0x0700) -> dict:
    raw = int(raw_u16) & 0xFFFF
    mask = g13_mask_for_slot(g13_seed, slot) & 0xFFFF
    decoded = (raw ^ mask) & 0x7FFF
    return {
        "slot": slot,
        "raw_u16": f"0x{raw:04x}",
        "g13_seed": f"0x{g13_seed:04x}",
        "g13_table": f"0x{mask:04x}",
        "python_xor_color15": f"0x{decoded:04x}",
        "python_xor_formula": f"0x{raw:04x} ^ 0x{mask:04x} = 0x{decoded:04x}",
        "hardware_decode": "unproven in disasm for 0x1111 lone D",
        "disasm_path_proven": (
            "Desert @ 0x012E3C: 0x05CE18 match (ROM mirror CGM 1.0 ) → 0x029EF0 stream walk. "
            "0x02A01C → 0x05CEC0 → 0x029958 only on gate mismatch. "
            "0x029F7C → 0x02A0F8 on matched path; tier-B 477 decode insn still OPEN. "
            "Post-init 0x012E60: 0x029C10 sweeps g2=0x20A79C (max slot ~45)"
        ),
    }


def build_report(*, slot: int | None = None, raw_u16: int | None = None) -> dict:
    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM only — no MAME workram captures",
        "proven_instructions": list(PROVEN_INSTRUCTIONS),
        "open_gaps": list(OPEN_GAPS),
        "python_replay": list(PYTHON_REPLAY),
        "matrix": {
            "d_setbit_r9": {"proven": True, "rom": "0x05D3DC"},
            "1111_bypasses_29c10_add": {
                "proven": True,
                "rom": "0x29FE4",
                "note": "Desert g4=4: 3 < (g4&7) → skip 0x29C10 at 0x29FF8",
            },
            "desert_slot477_via_29f7c": {
                "proven": True,
                "rom": "0x029EF0",
                "note": (
                    "ROM mirror template ``CGM 1.0 `` → ``0x05CE18`` match @ ``0x012E3C``; "
                    "``0x02A01C``/``0x005C8964`` only if template zero or head mismatch. "
                    "Slot 477 tier-B decode path inside ``0x1111`` stream still OPEN"
                ),
            },
            "2a258_xor_single_d": {"proven": False, "reason": "g3>0 batch gate @ 0x2A228"},
            "29cfc_add_on_1111": {"proven": False, "reason": "29C10 skipped when (g4&7)<3"},
            "g13_table_build_2a3ac": {"proven": True, "rom": "0x02A3AC"},
            "g13_xor_before_merge_1111": {"proven": False, "reason": "no matching insn on compile path"},
            "merge_g2_is_entry_g4": {"proven": True, "rom": "0x02A628"},
            "xor_table_python_oracle": {"proven": False, "note": "replay matches geometry; not hardware proof"},
        },
    }
    if slot is not None and raw_u16 is not None:
        report["tier_b_snapshot"] = tier_b_snapshot(slot=slot, raw_u16=raw_u16)
    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Disasm-only palette provenance matrix")
    parser.add_argument("--slot", type=int, default=None)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=None)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_disasm_provenance.json",
    )
    args = parser.parse_args()

    slot = args.slot
    raw = args.raw
    if (slot is None) ^ (raw is None):
        parser.error("--slot and --raw must be given together")

    report = build_report(slot=slot, raw_u16=raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["matrix"].values() if v.get("proven"))
    total = len(report["matrix"])
    print(f"\nProvenance matrix: {proven}/{total} items marked proven in disasm")
    for gap in OPEN_GAPS:
        print(f"  OPEN: {gap['id']}")


if __name__ == "__main__":
    main()
