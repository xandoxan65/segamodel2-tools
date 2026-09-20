#!/usr/bin/env python3
"""Disasm RE: handler template @ ROM mirror ``0x26690`` (workram list ``0x005C5670``).

MAME slices ``maincpu_026670_120.asm``, ``maincpu_026b90_100.asm``,
``maincpu_026c40_100.asm``, ``maincpu_026a10_200.asm``, ``maincpu_026800_200.asm``.

Documents the template body, its ``call`` targets (palram nibble packers — **not**
upload ``0x02A6D0``), and the ``0x26800`` clone chain for ``0x20B1C0`` handlers.
Confirms **no** CGM parameter-FIFO ``ldos`` on this static path.

  python3 -m tools.decomp.palette_handler_template_26690_re
  python3 -m tools.decomp.palette_handler_template_26690_re --slot 477
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_workram_rom_mirror_re import wr_to_rom, _ascii_preview
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment
from tools.rom_io import resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

DISASM_SLICES = (
    {"file": "decomp/disasm/maincpu/maincpu_026670_120.asm", "range": "0x26670–0x26790"},
    {"file": "decomp/disasm/maincpu/maincpu_026b90_100.asm", "range": "0x26B90–0x26C34"},
    {"file": "decomp/disasm/maincpu/maincpu_026c40_100.asm", "range": "0x26C40–0x26CCC"},
    {"file": "decomp/disasm/maincpu/maincpu_026a10_200.asm", "range": "0x26A10–0x26B54"},
    {"file": "decomp/disasm/maincpu/maincpu_026800_200.asm", "range": "0x26800–0x269FC"},
)

# --- ``0x26690`` template body (MAME disasm) -----------------------------------

TEMPLATE_26690 = (
    {"rom": "0x26690", "insn": "``lda 0xFFAC,g5``", "effect": "Load device/config halfword"},
    {"rom": "0x26698", "insn": "``stos g5,0x01040000``", "effect": "**staging1** bus (@ ``D`` ``r9`` bit-0 path)"},
    {"rom": "0x266A0", "insn": "``lda 0x52(g5),g5``", "effect": "Indirect table fetch from config block"},
    {"rom": "0x266A4", "insn": "``lda 0x01080000,r4``", "effect": "Palram packed bus base — row pointer for packers"},
    {"rom": "0x266AC", "insn": "``mov 0,r5``", "effect": "Loop counter (7 rows)"},
    {"rom": "0x266B0", "insn": "``stos g5,0x01060000``", "effect": "Secondary staging alias"},
    {
        "rom": "0x266B8",
        "insn": "``lda 0x005C5250,g0``",
        "effect": "Bitmap/source pointer cell — static mirror @ ``0x26250`` is glyph data, not code",
    },
    {"rom": "0x266C4", "insn": "``setbit 7,0,g2``", "effect": "Packer flag for ``0x26B94`` bit-doubling path"},
    {"rom": "0x266C8", "insn": "``mov 1,g3``", "effect": "Low-nibble lane selector @ ``0x26B94``"},
    {"rom": "0x266CC", "insn": "``call 0x26B94``", "effect": "Palram nibble pack — ``ldob (g0)`` bitmap, ``st g5,(g1)`` stride +4"},
    {"rom": "0x266D0", "insn": "``addo r5,1,r5``", "effect": "Row index++"},
    {"rom": "0x266D8", "insn": "``lda 0x1000(r4),r4``", "effect": "Advance palram bus row (+0x1000 per iteration)"},
    {"rom": "0x266E0", "insn": "``ble 0x266B8``", "effect": "7-row outer loop (``cmpi r5,7``)"},
    {
        "rom": "0x266E4",
        "insn": "``lda 0x005C5250,g0`` + ``call 0x26C44``",
        "effect": "Second pack pass — ``mov 2,g4`` @ ``0x266F8`` selects dual-nibble ``0x26C44`` path",
    },
    {"rom": "0x26700", "insn": "``call 0x26A10``", "effect": "Cold-boot bus zero-fill (``0x01000000`` … ``0x01008C00``)"},
    {"rom": "0x26704", "insn": "``st g14,0x20B910`` … ``0x20B1B0``", "effect": "Clear handler-bootstrap globals (``g14`` typically 0 @ clone entry)"},
    {"rom": "0x26744", "insn": "``ret``", "effect": "Template tail — **no** ``bx`` to upload cluster"},
)

# --- ``0x26B94`` / ``0x26C44`` packers -----------------------------------------

PACKER_26B94 = {
    "entry": "0x26B94",
    "args": {"g0": "bitmap byte stream (advanced per ``ldob``)", "g1": "dest row ptr (palram bus)", "g2": "bit7 flag", "g3": "nibble lane (masked to 15)"},
    "algorithm": (
        "For each of 7 output words: walk 16 bit positions via ``ldob`` + ``addo g4,g4``; "
        "accumulate nibble contributions with ``shlo 12/8/4`` masks; ``rotate`` into ``g5``; "
        "``st g5,(g1)``; ``g1 += 4``."
    ),
    "fifo_ldos": False,
    "xor_g13": False,
}

PACKER_26C44 = {
    "entry": "0x26C44",
    "args": {"g0": "bitmap stream", "g1": "dest row", "g3": "lane A", "g4": "lane B (template passes ``2``)"},
    "algorithm": (
        "Per byte: if bit7 set add ``g3`` else add ``g4`` into nibble accumulator; "
        "16 inner steps; ``rotate``; ``st`` — dual-lane variant of ``0x26B94``."
    ),
    "fifo_ldos": False,
    "xor_g13": False,
}

BUS_INIT_26A10 = {
    "entry": "0x26A10",
    "effect": "Zero ``0x01000000``, ``0x01002000``, ``0x01004000``, ``0x01006000`` via ``0x26B60``; "
    "``stq 0`` bands @ ``0x0100C000``–``0x01008C00``.",
    "note": "Called at template tail — re-inits device buses after palram pack, not CGM FIFO.",
}

# --- ``0x26760`` list copy + ``0x26800`` clone ---------------------------------

COPY_26760 = (
    {"rom": "0x26750", "effect": "``lda 0x005C57F0,g14`` → ``bx`` through return stub"},
    {"rom": "0x26760", "effect": "``lda 0x005C5670,g7`` — halfword stream source (embedded template blob @ ``0x26670``)"},
    {"rom": "0x26778", "effect": "``stos g14,(g5)`` + ``ldos (g7),g4`` + ``stos g4`` × 10 entries → ``0x01800000`` scratch"},
    {"rom": "0x267B0", "effect": "Optional colorbase copy ``0x005FB89E`` → ``0x01802000`` when ``0x005FB89C`` > 0"},
)

CLONE_26800 = (
    {"rom": "0x26800", "effect": "Walk ``0x20B600`` linked list; per node ``call 0x05DAA0`` memcpy template"},
    {"rom": "0x26860", "effect": "Opcode index table: ``0x20B600[g5*4]`` ← handler ptr; ``+8`` ← ``g2``"},
    {"rom": "0x26880", "effect": "``lda (g5)[g5*2],g4`` — index → node; patch handler + metadata"},
    {"rom": "0x26980", "effect": "``ldos 0x20B914`` stream → ``0x0100A000``; ``call 0x26800`` — **no static callers**"},
)

UPLOAD_CLUSTER = (0x02A4E0, 0x02A6D0, 0x02A5A0, 0x02A490, 0x02A258)


def _word_at(words: list[int], rom: int) -> int:
    idx = rom // 4
    return words[idx] if 0 <= idx < len(words) else 0


def _scan_asm_for_fifo_xor(asm_path: Path) -> dict[str, list[str]]:
    if not asm_path.is_file():
        return {"fifo_ldos": [], "xor_g13": []}
    text = asm_path.read_text(encoding="utf-8", errors="replace")
    fifo = re.findall(r"^([0-9a-f]+):.*\bldos\b", text, re.M | re.I)
    xor = re.findall(r"^([0-9a-f]+):.*\bxor\s+g13\b", text, re.M | re.I)
    return {"fifo_ldos": fifo[:8], "xor_g13": xor[:8]}


def _list_blob_at_5670(words: list[int]) -> dict[str, Any]:
    rom = wr_to_rom(0x005C5670)
    rows: list[dict[str, str]] = []
    off = 0
    while off < 64:
        w = _word_at(words, rom + off)
        lo, hi = w & 0xFFFF, (w >> 16) & 0xFFFF
        if lo == 0 and hi == 0 and off > 0:
            break
        rows.append({"offset": f"+0x{off:02X}", "lo": f"0x{lo:04X}", "hi": f"0x{hi:04X}", "word": f"0x{w:08X}"})
        off += 4
    return {
        "workram": "0x005C5670",
        "rom_mirror": f"0x{rom:08X}",
        "note": "First words are **in-place code** (@ ``0x26670``), not pointer table — ``0x26760`` copies halfword pairs as metadata",
        "head_words": rows,
    }


def _bx_cell_5250(words: list[int]) -> dict[str, Any]:
    vaddr = 0x005C5250
    rom = wr_to_rom(vaddr)
    blob = bytes(_word_at(words, rom + i) & 0xFF for i in range(0, 16, 4))
    refs = find_word_refs(words, vaddr)
    return {
        "workram": f"0x{vaddr:08X}",
        "rom_mirror": f"0x{rom:08X}",
        "first_qword": f"0x{_word_at(words, rom):08X}",
        "ascii": _ascii_preview(blob, 16),
        "static_kind": "glyph_or_pattern_data",
        "rom_lda_refs": len(refs),
        "lda_sites": [f"0x{r:08X}" for r in refs[:6]],
    }


def _upload_cluster_xrefs(words: list[int]) -> dict[str, Any]:
    return {
        label: {"rom": f"0x{addr:05X}", "refs": len(find_word_refs(words, addr))}
        for label, addr in (
            ("merge", 0x02A4E0),
            ("wrapper", 0x02A6D0),
            ("fifo_runner", 0x02A5A0),
            ("scratch_write", 0x02A490),
            ("xor_batch", 0x02A258),
        )
    }


def _opcode_20_context(*, slot: int) -> dict[str, Any]:
    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    last = d_events[-1] if d_events else None
    bc = [int(x, 16) for x in (last or {}).get("bytecode", [])]
    bound = bind_and_run(bc) if bc else None
    return {
        "slot": slot,
        "bind_index": "0x0020",
        "handler_pool": "0x20B1C0[0x20*4] — filled by ``0x26800`` clone, not static ROM image",
        "template_rom_entry": "0x26690 — palram pack + bus init; **does not** call ``0x02A4E0``/``0x02A6D0``",
        "upload_path_note": "Lone ``D`` decode still on compile+run upload cluster after ``0x005C8964`` patch",
        "stub_patches": len(bound.stub_patches) if bound else 0,
    }


def build_report(*, slot: int = 477) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    slice_scans = {
        s["file"]: _scan_asm_for_fifo_xor(REPO_ROOT / s["file"]) for s in DISASM_SLICES[:3]
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "MAME i960 disasm slices + ROM word xref — no MAME workram capture",
        "disasm_slices": list(DISASM_SLICES),
        "template_26690": list(TEMPLATE_26690),
        "packer_26b94": PACKER_26B94,
        "packer_26c44": PACKER_26C44,
        "bus_init_26a10": BUS_INIT_26A10,
        "copy_26760": list(COPY_26760),
        "clone_26800": list(CLONE_26800),
        "list_blob_5670": _list_blob_at_5670(words),
        "bx_cell_5250": _bx_cell_5250(words),
        "asm_negative_scan": {
            **slice_scans,
            "note": (
                "Single ``ldos`` @ ``0x26780`` is ``(g7)`` halfword copy from ``0x005C5670`` list — "
                "not CGM parameter-FIFO."
            ),
        },
        "upload_cluster_xrefs": _upload_cluster_xrefs(words),
        "opcode_0x20_slot_context": _opcode_20_context(slot=slot),
        "conclusions": (
            "Handler template @ ``0x26690`` is **palram staging**: writes ``0x01040000``/``0x01060000``, "
            "packs bitmap bytes via ``0x26B94``/``0x26C44`` into ``0x01080000`` rows — **no** parameter-FIFO ``ldos``, **no** ``xor g13``.",
            "``0x005C5250`` loaded as ``g0`` bitmap cursor — static ROM mirror is pattern data; runtime patch expected before ``ldob`` loop.",
            "Template tail ``call 0x26A10`` zero-fills descriptor buses — separate from desert ``0x029EB0`` compile path.",
            "``0x26800`` clones nodes from ``0x20B600`` into ``0x20B1C0`` pool; invoked only from ``0x26980`` (no static ``call``). "
            "Opcode ``0x20`` slot 477 handler record is **runtime-built**, not a direct ``bx`` to ``0x26690``.",
            "Slot 477 lone ``D`` color15 transform remains on upload cluster ``0x02A4E0`` merge (post-``0x005C8964``), not this template.",
        ),
        "open_gaps": (
            "Runtime body @ ``0x005C8964`` after desert ``0x02A038`` — links FIFO runner to merge for slot 477",
            "Which ``0x20B600`` node maps opcode ``0x20`` → cloned handler vs ``0x26690`` ROM image",
            "``0x005FBF10`` template row bytes for emit path (``0x027260`` writes ``g14`` stub addrs, not 10-byte rows)",
            "Static link matched tail inner nodes → fifo+``0x3A6`` / tier-B slot 477",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Handler template 0x26690 disasm RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_handler_template_26690_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    neg = report["asm_negative_scan"]
    for path, scan in neg.items():
        print(f"\n{path}:")
        print(f"  ldos lines: {len(scan['fifo_ldos'])}")
        print(f"  xor g13:    {len(scan['xor_g13'])}")

    upl = report["upload_cluster_xrefs"]
    print("\nUpload cluster static refs:")
    for label, body in upl.items():
        print(f"  {label:14s} {body['rom']}: {body['refs']}")

    ctx = report["opcode_0x20_slot_context"]
    print(f"\nSlot {args.slot} opcode 0x20: stub_patches={ctx['stub_patches']}")

    for line in report["conclusions"][:3]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
