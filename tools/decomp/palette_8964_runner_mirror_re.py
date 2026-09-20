#!/usr/bin/env python3
"""ROM-mirror disasm: ``0x005C8964`` runner slab (@ ``maincpu_029900_300.asm``).

The workram runner is **not** zero — it mirrors from maincpu ROM @ ``0x029964``.
Documents thunk table, embedded ``0x027130`` prewalk, format strings, and why
desert matched-path init (@ ``0x012E3C``) **does not** ``bal 0x029958``.

  python3 -m tools.decomp.palette_8964_runner_mirror_re
  python3 -m tools.decomp.palette_8964_runner_mirror_re --slot 477
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_bind_stream_re import _slot477_d_bytecode
from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKRAM_ROM_MIRROR = 0x0059F000
RUNNER_ENTRY = 0x005C8964
DISASM_SLICE = "maincpu_029900_300.asm"

# Thunks in ROM mirror (workram vaddr → role from static disasm).
RUNNER_THUNKS: tuple[dict[str, Any], ...] = (
    {
        "workram": "0x005C8964",
        "rom": "0x029964",
        "role": "``0x029958`` ``bx`` entry — saves ``g0/g1`` @ ``0x20B934/938``, ``bx 0x005C89A4``",
    },
    {
        "workram": "0x005C89A4",
        "rom": "0x0299C0",
        "role": (
            "Compile iteration: ``bal 0x026FD8`` (tag), ``bal 0x026E18`` (counters), "
            "``call 0x05CEC0`` with ``g0=0x005C89B0``"
        ),
        "format_ascii": "11-% (partial @ ``0x0299B0``)",
    },
    {
        "workram": "0x005C89B0",
        "rom": "0x0299FC",
        "role": "Format string ``%-11s:%-8d`` passed to ``0x05CEC0``/``0x05CF50`` scan",
    },
    {
        "workram": "0x005C8A30",
        "rom": "0x029A30",
        "role": (
            "**Prewalk+run**: ``bal 0x026E18`` → ``bal 0x026FD8`` → ``call 0x027130`` → "
            "``bal 0x029958`` (re-enter runner)"
        ),
    },
    {
        "workram": "0x005C8A90",
        "rom": "0x029A60",
        "role": "Init palette cursors: ``0x20C950=9``, ``0x20C954=0``, ``0x20C958=0``",
    },
    {
        "workram": "0x005C8AD0",
        "rom": "0x029AA0",
        "role": (
            "Slot clamp: ``cmpibg g0,0x7F`` — slots **>127** return ``g0=-1`` (@ ``0x029AC8``); "
            "else store ``0x20C950``"
        ),
        "tier_b_boundary": 128,
    },
    {
        "workram": "0x005C8AE0",
        "rom": "0x029AE0",
        "role": (
            "``0x29AE8`` slot clamp helper: ``g0+=g1``; lookup ``0x20B954[g0*8]`` group row "
            "(used from ``0x029C10`` negative-``g2`` path @ ``0x029C50``)"
        ),
    },
    {
        "workram": "0x005C8B18",
        "rom": "0x029B18",
        "role": "Load ``0x20B954[g0*8]`` dispatch pointer",
    },
    {
        "workram": "0x005C8B3C",
        "rom": "0x029B3C",
        "role": "Return ``0x20C954``",
    },
    {
        "workram": "0x005C8B5C",
        "rom": "0x029B5C",
        "role": "Return ``0x20C950``",
    },
    {
        "workram": "0x005C8BA0",
        "rom": "0x029B60",
        "role": (
            "Indexed staging: ``ldos 0x20B950[g0*8]`` → ``lda 0x1800000(g0)`` "
            "(palram bus pointer from group row)"
        ),
    },
    {
        "workram": "0x005C8BE4",
        "rom": "0x029BB0",
        "role": "``ldob 0x20B952[g0*8]`` — per-slot byte from group row",
    },
    {
        "workram": "0x005C8BF0",
        "rom": "0x029C58",
        "role": "``0x029C10`` negative-``g2`` compile format: ``CgmPut ERROR [%s]:[%d]``",
    },
)

CALLERS_29958: tuple[dict[str, Any], ...] = (
    {
        "rom": "0x02A038",
        "when": "``0x029EB0`` **mismatch** (@ ``0x02A01C``) or **entry overflow** (@ ``0x02A004``) only",
        "desert_012e3c": False,
        "note": "Matched gate → ``0x029EF0`` → ``ret`` @ ``0x02A000`` — **skips** this site",
    },
    {
        "rom": "0x029C68",
        "when": "``0x029C10`` when ``g2<0`` — ``call 0x05CEC0`` @ ``0x005C8BF0`` then run",
        "desert_012e3c": False,
    },
    {
        "rom": "0x029A50",
        "when": "Internal runner thunk after ``call 0x027130`` (@ ``0x029A4C``)",
        "desert_012e3c": False,
    },
)

MERGE_UPLOAD_CLUSTER = (
    {"rom": "0x026F10", "effect": "Bind stream halfword → ``0x20B1C0[index*4]`` (@ ``0x026F44``)"},
    {"rom": "0x027130", "effect": "Replay ``0x027008`` over bytecode bytes (counter refresh)"},
    {"rom": "0x027160", "effect": "Patch ``0x005C61C8`` stub into descriptor chain"},
    {"rom": "0x02A6D0", "effect": "Wrapper → repeated ``call 0x02A5A0``"},
    {
        "rom": "0x02A628",
        "effect": (
            "Merge gate: ``call 0x02A4E0`` with ``g0=r10``, ``g1=r9``, ``g2=r14`` "
            "(entry ``g4``) when ``r5`` bit 0"
        ),
    },
    {
        "rom": "0x02A4E0",
        "effect": (
            "Identity merge into ``0x01080000`` staging using ``0x20C95C``–``0x20C968`` "
            "window globals — **no XOR** in this routine"
        ),
    },
)

OPEN_GAPS = (
    "Desert matched init never ``bal 0x029958`` — slot 477 not via ``0x005C8964`` printf harness",
    "``0x005C89B0`` / ``0x005C8BF0`` formats are libc/debug strings — not ``0x1111`` marker-split body",
    "Tier-B slot 477 (>127): ``0x005C8AD0`` clamp + ``0x29AE8`` path — tie to ``0x29C10`` / ``0x02A4E0`` OPEN",
    "Bind index ``0x0020`` proven; handler record @ ``0x20B1C0[0x20]`` runtime clone still OPEN",
    "``record+0x14`` FIFO cursor for ``0x29CFC`` ADD vs replay fifo+0x3A6 ``0x8843`` OPEN",
)


def _mirror_ascii(words: list[int], vaddr: int, n: int = 32) -> str:
    rom = vaddr - WORKRAM_ROM_MIRROR
    blob = b"".join(
        struct.pack("<I", words[(rom + i) // 4])
        for i in range(0, n, 4)
        if 0 <= (rom + i) // 4 < len(words)
    )
    return "".join(chr(b) if 32 <= b < 127 else "." for b in blob)


def _runner_image_facts(words: list[int]) -> dict[str, Any]:
    rom = RUNNER_ENTRY - WORKRAM_ROM_MIRROR
    first_words = [words[rom // 4 + i] for i in range(4)]
    refs = find_word_refs(words, RUNNER_ENTRY)
    return {
        "workram_entry": f"0x{RUNNER_ENTRY:08X}",
        "rom_mirror": f"0x{rom:06X}",
        "disasm_slice": DISASM_SLICE,
        "first_insns": [f"0x{w:08X}" for w in first_words],
        "starts_with_ret_then_code": first_words[0] == 0x0A000000,
        "rom_lda_ref_count": len(refs),
        "rom_lda_sites": [f"0x{r:06X}" for r in refs],
        "image_is_rom_mirror_not_zero": any(w != 0 for w in first_words[1:]),
    }


def _desert_init_path(main_data: bytes) -> dict[str, Any]:
    facts = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    cmp = facts["compare_vs_rom_mirror_template"]
    matched = cmp["g0"] == 0
    return {
        "init_rom": "0x012E3C",
        "gate_g0": cmp["g0"],
        "path": "matched_stream_29EF0" if matched else "mismatch_compile_2A01C",
        "calls_29958": not matched,
        "calls_8964_runner": not matched,
        "return_stored": "0x012E48 ``st g0,0x20A7B0`` — on matched path ``g0=r7=0x20C954`` @ ``0x029FFC``",
        "slot_477_via_runner": False,
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    _, words = load_maincpu_words(rom_dir)
    d_sim = _slot477_d_bytecode(main_data)

    thunks = []
    for t in RUNNER_THUNKS:
        va = int(t["workram"], 16)
        thunks.append({**t, "mirror_ascii": _mirror_ascii(words, va, 24)})

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm ROM mirror — no MAME, no XOR inference",
        "focus_slot": slot,
        "runner_image": _runner_image_facts(words),
        "correction": (
            "Prior notes claiming ``0x005C8964`` body is **zero** in static ROM were wrong: "
            "the image lives in maincpu ROM @ ``0x029964`` (mirror rule ``-0x0059F000``). "
            "It is still **not** invoked on desert matched-path init."
        ),
        "runner_thunks": thunks,
        "callers_29958": list(CALLERS_29958),
        "merge_upload_cluster": list(MERGE_UPLOAD_CLUSTER),
        "desert_init_path": _desert_init_path(main_data),
        "slot477_bind_bytecode": d_sim,
        "tier_b_note": (
            f"Slot {slot} > 127: ``0x005C8AD0`` (@ ``0x029AA0``) rejects with ``g0=-1``; "
            "tier-B upload must use ``0x29C10`` ADD tail, ``0x29AE8`` clamp path, or ``0x02A4E0`` merge — "
            "not the low-slot ``0x20C950`` store thunk alone"
        ),
        "open_gaps": list(OPEN_GAPS),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="8964 runner ROM mirror RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_8964_runner_mirror_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    desert = report["desert_init_path"]
    img = report["runner_image"]
    print(f"Runner mirror @ {img['rom_mirror']} (ret+code: {img['starts_with_ret_then_code']})")
    print(f"Desert init: {desert['path']} → 29958={desert['calls_29958']}")
    sim = report.get("slot477_bind_bytecode") or {}
    if "bind_stream_halfwords" in sim:
        hw = sim["bind_stream_halfwords"][0]
        print(f"Slot {args.slot} D bind index: {hw['halfword']}")


if __name__ == "__main__":
    main()
