#!/usr/bin/env python3
"""Disasm RE: map ``0x0271D0`` stub patches → descriptor chain → upload ``g4``.

Slot-477 last ``D`` with ROM template row ``0123456789`` yields **10** patches
(bytes ``0x30``–``0x39``) into ``0x01000000`` descriptor slots.  Each patch
stores workram return stub ``0x005C6250`` (ROM mirror = ``ret`` @ ``0x027250``).

Documents the only ``ldos→g4`` handler mirror routine (@ ``0x26750``) as a static
halfword list copy — **not** CGM FIFO.  Formalizes negative decode: template
bytes are ASCII digit indices for stub patching, not palette color transforms.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_271d0_stub_upload_trace_re
  python3 -m tools.decomp.palette_271d0_stub_upload_trace_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5fbf10_template_re import load_template_rows
from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom, rom_slice
from tools.i960_scan import load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment, D_TEMPLATE_G6
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

STUB_6250_WR = 0x005C6250
STUB_6250_ROM = 0x027250
HANDLER_26750 = 0x026750
G7_LIST_WR = 0x005C5670
G7_LIST_ROM = 0x026670

# --- Disasm-proven mechanics -------------------------------------------------

PATCH_MECHANICS = (
    {
        "rom": "0x0271D0",
        "effect": (
            "``g1 = 0x005C6250`` (return); ``g14 = 0``; for each non-zero template byte: "
            "``stos g14 → 0x01000000[(width<<6|slot)*2]`` link halfword; ``0x20B1A8++``"
        ),
    },
    {
        "rom": "0x0271F8",
        "effect": "``g7 = slot + 31`` — cap check before patch (``cmpibg g4,g7``)",
    },
    {
        "rom": "0x027248",
        "effect": "``bx (g1)`` — return through saved ``0x005C6250`` stub",
    },
)

UPLOAD_MERGE = (
    {
        "rom": "0x02A6D0",
        "effect": "Save ``g4→r6``; four ``call 0x02A5A0`` permutations",
    },
    {
        "rom": "0x02A62C",
        "effect": "When ``r5`` bit 0: ``g2 = r14`` (wrapper entry ``g4``) → merge bus",
    },
    {
        "verdict": (
            "Static disasm: ``g4`` at merge must come from **compiled thunk** "
            "that ran via patched descriptor chain — not from ``0x0271D0`` template bytes"
        ),
    },
)

HANDLER_26750_DOC = {
    "rom": "0x026750",
    "g7": f"``0x005C5670`` → ROM ``0x{G7_LIST_ROM:06X}``",
    "insn": "``ldos (g7),g4`` × 10 → ``stos`` @ ``0x01800000`` scratch",
    "transform": "identity halfword copy from static ROM bytes",
    "xor_g13": False,
    "fifo": False,
    "return_stub": f"``0x005C57F0`` → ROM ``0x0267F0`` = ``ret``",
    "note": (
        "First halfwords @ ``0x026670`` decode as ``0xFFFF``/``0xFC00``/… — "
        "embedded code/data band, not tier-B FIFO cursor"
    ),
}

NEGATIVE_DECODE = (
    {
        "hypothesis": "Template byte ``0x30``–``0x39`` = color index",
        "result": "Bytes are ASCII ``'0'``–``'9'`` from row ``0123456789`` — stub slot selectors only",
        "proven": True,
    },
    {
        "hypothesis": "``0x0271D0`` patch count encodes xor key",
        "result": "Count = non-zero row width (10 for row0); no arithmetic on FIFO u16",
        "proven": True,
    },
    {
        "hypothesis": "``0x26750`` ``ldos`` reads fifo+0x3A6 raw ``0x8843``",
        "result": "``g7`` fixed @ ``0x005C5670`` in static image; no FIFO pointer patch in ROM",
        "proven": True,
    },
    {
        "hypothesis": "xor_table ``raw ^ 0xEEC0`` is hardware lone-``D`` decode",
        "result": "Only ``xor g13`` site is @ ``0x02A258`` (``#`` batch path); lone ``D`` never reaches it",
        "proven": True,
    },
)


def _stub_mirror_word(*, rom_dir: Path | None = None) -> dict[str, str]:
    _, words = load_maincpu_words(resolve_rom_dir(rom_dir))
    blob = rom_slice(words, STUB_6250_ROM, 4)
    word = struct.unpack_from("<I", blob, 0)[0]
    is_ret = word == 0x0A000000
    return {
        "workram": f"0x{STUB_6250_WR:08X}",
        "rom_mirror": f"0x{STUB_6250_ROM:06X}",
        "word": f"0x{word:08X}",
        "disasm": "ret" if is_ret else "?",
    }


def _g7_list_preview(*, rom_dir: Path | None = None, count: int = 10) -> list[str]:
    _, words = load_maincpu_words(resolve_rom_dir(rom_dir))
    blob = rom_slice(words, G7_LIST_ROM, count * 2)
    return [f"0x{struct.unpack_from('<H', blob, i)[0] & 0xFFFF:04x}" for i in range(0, len(blob), 2)]


def _slot477_patch_map(rows: list[bytes]) -> dict[str, Any]:
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

    patches = []
    for i, p in enumerate(state.stub_patches):
        tb = p.get("template_byte", "")
        tb_val = int(tb, 16) if tb else 0
        patches.append(
            {
                "step": i,
                "rom": p.get("rom"),
                "patch": p.get("patch", "zero_halfword"),
                "desc_idx": p.get("desc_idx"),
                "slot_at_patch": p.get("slot"),
                "width_at_patch": p.get("width"),
                "template_byte": tb,
                "ascii": chr(tb_val) if 32 <= tb_val < 127 else None,
                "return_stub": p.get("return_stub") or p.get("stub"),
                "role": "clear descriptor link halfword; return via saved stub @ end",
            }
        )

    return {
        "fragment": SLOT477_FRAG,
        "last_d_repeat": repeat,
        "template_row_index": row_idx,
        "template_row_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in row),
        "bytecode_hex": bytes(bc).hex(),
        "descriptor_bus": {str(k): f"0x{v:04x}" for k, v in state.descriptors.items()},
        "stub_patches": patches,
        "final_counters": {"slot": state.counters.slot, "width": state.counters.width},
        "upload_inference": state.infer_upload_chain(),
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict[str, Any]:
    rows = load_template_rows()
    g13 = g13_mask_for_slot(0x0700, slot)
    raw = int(raw_u16) & 0xFFFF
    tgt = int(target) & 0x7FFF

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + bytecode/stub sim — no MAME workram",
        "patch_mechanics": list(PATCH_MECHANICS),
        "upload_merge": list(UPLOAD_MERGE),
        "handler_26750": HANDLER_26750_DOC,
        "stub_6250_mirror": _stub_mirror_word(),
        "g7_static_halfwords": _g7_list_preview(),
        "slot477_patch_map": _slot477_patch_map(rows),
        "negative_decode": list(NEGATIVE_DECODE),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{raw:04x}",
            "oracle": f"0x{tgt:04x}",
            "xor_oracle": f"0x{(raw ^ g13) & 0x7FFF:04x}",
            "xor_matches_oracle": (raw ^ g13) & 0x7FFF == tgt,
        },
        "conclusions": (
            "10× ``0x0271D0`` zero-fills for slot-477 last ``D`` at descriptor indices "
            "1–10 — one per non-zero template byte (``0123456789``).",
            "Template bytes ``0x30``–``0x39`` select **how many** link slots to clear, "
            "not color operands — negative proof formalized.",
            "Only static ``ldos→g4`` in handler mirror band (@ ``0x26750``) copies "
            f"halfwords from ``0x{G7_LIST_ROM:06X}`` — cannot produce ``0x6683`` from ``0x8843``.",
            "``0x02A62C`` merge still requires runtime ``g4`` from compiled thunk execution; "
            "static disasm does not connect stub patches to FIFO halfword decode.",
        ),
        "open_gaps": (
            "Runtime fill of ``0x005C6250`` / ``0x005C8964`` bodies before ``0x029958`` "
            "(static mirror = ``ret`` only)",
            "Which patched descriptor slot's ``bx`` chain first loads FIFO u16 into ``g4``",
            "``0x20B600[0x20]`` cloned handler ``+8`` bx target (runtime-built list)",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="0271D0 stub patch → upload g4 trace")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_271d0_stub_upload_trace_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    pm = report["slot477_patch_map"]
    print(f"\nSlot-477: {len(pm.get('stub_patches', []))} stub patches")
    for p in pm.get("stub_patches", [])[:4]:
        print(
            f"  [{p['step']}] desc_idx={p['desc_idx']} byte={p['template_byte']} "
            f"ascii={p.get('ascii')!r}"
        )
    print(f"\nStub 0x005C6250 mirror: {report['stub_6250_mirror']['disasm']}")
    print(f"g7[0:3]: {report['g7_static_halfwords'][:3]}")
    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
