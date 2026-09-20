#!/usr/bin/env python3
"""Disasm RE: ``0x005FBF10`` template rows are **ROM-embedded**, not runtime zeros.

The workram address ``0x005FBF10`` mirrors maincpu ROM @ ``0x05CF10`` (inside
``0x05CF50`` blob): rows ``0123456789``, ``abcdef..%``, etc.  Documents
``0x05D7E8`` copy (@ ``g6=10``), ``0x012DE4`` ``0x027260`` boot patches, handler
record layout (@ ``0x026F94``), and slot-477 last-``D`` stub chain with **real** rows.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_5fbf10_template_re
  python3 -m tools.decomp.palette_5fbf10_template_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import WORKRAM_ROM_MIRROR, wr_to_rom, rom_slice
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment, D_TEMPLATE_G6
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"
TEMPLATE_BASE = 0x005FBF10

# --- Disasm-backed copy path (``maincpu_05cf50_a00.asm``) --------------------

D_TEMPLATE_COPY = (
    {"rom": "0x05D7E8", "effect": "``r7`` outer repeat; ``g5`` inner; ``g6=10`` row width"},
    {"rom": "0x05D808", "effect": "``remo g6,g5,g4`` — row index = ``repeat % 10``"},
    {"rom": "0x05D810", "effect": "``ldob (g8)[g4],g4`` — byte from ``0x005FBF10`` row"},
    {"rom": "0x05D818", "effect": "``stob g4,(r6)`` — copy into emit stack buffer @ ``0x19c(fp)``"},
    {"rom": "0x05D828", "effect": "``lda 0x005FBF10,g8`` — template base (ROM mirror @ ``0x05CF10``)"},
    {"rom": "0x05D860", "effect": "``bal 0x027008`` per copied byte + ``r10`` repeat loop"},
)

BOOT_27260 = (
    {
        "rom": "0x012DE4",
        "args": "``g0=15, g1=30, g2=35, g3=6``",
        "effect": "``call 0x027260`` — batch ``g14`` stub patch into ``0x01000000`` descriptor bus",
    },
    {
        "rom": "0x012DF8",
        "args": "``g0=7, g1=29, g2=35, g3=21``",
        "effect": "Second ``0x027260`` batch (different tag base ``g1<<7``)",
    },
    {
        "rom": "0x012DB0",
        "effect": "``stos g6,0x20B914`` — seeds opcode stream head with ``0xC000`` flags",
    },
)

HANDLER_RECORD = {
    "table": "0x20B1C0[index*4] — filled @ ``0x26800`` clone",
    "layout": (
        "+0: slot/width counters (``0x026F4C`` ``st g5`` / ``stl g6``)",
        "+8: bx target (``0x026FA4`` ``ld 8(g4),g4`` → ``bx``)",
    ),
    "bind": {
        "rom": "0x026F44",
        "effect": "``index = stream_halfword``; slot 477 ``D`` → **0x20**",
    },
    "restore": {
        "rom": "0x026F94",
        "effect": "Pop record → restore ``0x20B1A4/A8/AC``; ``bx`` handler @ +8",
    },
}

DESERT_27130 = {
    "rom": "0x02A038",
    "effect": "``bal 0x029958`` only — **no** ``call 0x027130``",
    "contrast": "``0x029A4C`` @ ``0x005C8A30`` thunk **does** ``call 0x027130`` prewalk",
    "verdict": "Desert mismatch-compile path skips bytecode prewalk in static disasm",
}


def load_template_rows(*, rom_dir: Path | None = None) -> list[bytes]:
    """Read ``10 × g6`` template rows from ROM mirror @ ``0x05CF10``."""
    _, words = load_maincpu_words(resolve_rom_dir(rom_dir))
    blob = rom_slice(words, wr_to_rom(TEMPLATE_BASE), D_TEMPLATE_G6 * 10)
    return [blob[i * D_TEMPLATE_G6 : (i + 1) * D_TEMPLATE_G6] for i in range(10)]


def _row_preview(rows: list[bytes]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for i, row in enumerate(rows):
        ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append({"index": i, "hex": row.hex(), "ascii": ascii_s})
    return out


def _slot477_last_d_chain(rows: list[bytes]) -> dict[str, Any]:
    events = compile_format_fragment(SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    if not d_events:
        return {"error": "no D events"}
    last = d_events[-1]
    repeat = int(last.get("repeat") or 1)
    row_idx = (repeat - 1) % D_TEMPLATE_G6
    row = rows[row_idx]
    bc = [int(x, 16) for x in last.get("bytecode", [])]
    state = bind_and_run(bc, template_row=row)
    return {
        "fragment": SLOT477_FRAG,
        "last_d_repeat": repeat,
        "template_row_index": row_idx,
        "template_row_hex": row.hex(),
        "template_row_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in row),
        "bytecode_hex": bytes(bc).hex(),
        "descriptor_0": f"0x{state.descriptors.get(0, 0):04x}",
        "stub_patches_271d0": len(state.stub_patches),
        "patch_template_bytes": [p.get("template_byte") for p in state.stub_patches[:12]],
        "final_counters": {"slot": state.counters.slot, "width": state.counters.width},
        "note": (
            "Repeat=1 → row 0 = ``0123456789`` → **10** ``0x0271D0`` patches "
            "(not 0 with zeros assumption)"
        ),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    rows = load_template_rows()
    g13_table = g13_mask_for_slot(0x0700, slot)

    st_near = sum(
        1
        for i, w in enumerate(words)
        if (w & 0xFF000000) in (0x92000000, 0x92800000, 0x92A00000)
        and TEMPLATE_BASE <= (w & 0xFFFFFF) <= TEMPLATE_BASE + 0x200
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM mirror bytes — no MAME workram",
        "mirror_formula": f"workram 0x005FBF10 → ROM 0x{wr_to_rom(TEMPLATE_BASE):06X}",
        "closure": (
            "Prior open gap ``Recover 0x005FBF10 template row`` **closed** for static image: "
            "rows are embedded in maincpu ROM @ ``0x05CF10``, not zero-filled workram."
        ),
        "template_rows": _row_preview(rows),
        "d_template_copy": list(D_TEMPLATE_COPY),
        "boot_27260": list(BOOT_27260),
        "handler_record": HANDLER_RECORD,
        "desert_27130": DESERT_27130,
        "rom_mirror_stats": {
            "lda_refs_5FBF10": len(find_word_refs(words, TEMPLATE_BASE)),
            "static_st_into_band": st_near,
            "row0_ascii": _row_preview(rows)[0]["ascii"],
        },
        "slot477_last_d": _slot477_last_d_chain(rows),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "oracle": f"0x{int(target) & 0x7FFF:04x}",
            "xor_oracle": f"0x{(int(raw_u16) ^ g13_table) & 0x7FFF:04x}",
        },
        "conclusions": (
            "``0x005FBF10`` @ ``0x05D828`` reads **ROM mirror** rows (``0123456789`` …) — "
            "``0x0271D0`` stub count for slot-477 last ``D`` is **10**, not 0.",
            "``0x012DE4``/``0x012DF8`` ``call 0x027260`` pre-seed descriptor bus @ boot; "
            "separate from per-``D`` ``0x0271D0`` template walk at run.",
            "Desert ``0x02A038`` ``bal 0x029958`` **without** ``0x027130`` — bytecode counters "
            "rely on ``0x05D860`` emit during ``0x05CEC0`` compile (same ``0x027008`` engine).",
            "Template bytes ``0x30``–``0x39`` trigger **zero-fill** of descriptor link halfwords "
            "(@ ``0x0271D0`` ``stos g14`` with ``g14=0``) — still **no** ``xor g13`` / FIFO decode.",
        ),
        "open_gaps": (
            "Runtime ``bx`` @ handler record ``+8`` for opcode ``0x20`` clone — body in ``0x20B600`` list",
            "Map 10× ``0x0271D0`` zero-fills → ``0x02A6D0`` wrapper ``g4`` for merge @ ``0x02A62C``",
            "``fp+0x40`` stream root / ``0x29F9C`` row ``+4`` FIFO cursor validity (``palette_block_stream_link_re``)",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0x005FBF10 ROM template row RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_5fbf10_template_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    print(f"\n{report['closure']}")
    print("\nTemplate rows (ROM mirror):")
    for row in report["template_rows"][:4]:
        print(f"  [{row['index']}] {row['ascii']}")

    chain = report["slot477_last_d"]
    print(
        f"\nSlot-477 last D: row {chain.get('template_row_index')} "
        f"→ {chain.get('stub_patches_271d0')} stub patches"
    )
    print(f"  row ascii: {chain.get('template_row_ascii')}")

    print(f"\n{report['desert_27130']['verdict']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
