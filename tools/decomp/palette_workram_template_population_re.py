#!/usr/bin/env python3
"""Disasm-only: who fills ``0x005C8Exx`` workram templates before desert compile?

Traces negative results for suspected population paths (``0x013238``,
``0x0333C8``, ``0x027260``, handler clone @ ``0x026700``) and documents the
workram stub chain behind ``0x029958`` / ``0x005C8964``.

Does **not** use MAME captures or infer XOR.

  python3 -m tools.decomp.palette_workram_template_population_re
  python3 -m tools.decomp.palette_workram_template_population_re --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_5ce18_stream_re import cgm_block_head_facts, simulate_5ce18
from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_palette import COURSE_CGM_VADDRS
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Workram slots with exactly one ROM ``lda`` (no ROM ``st`` with immediate in 0x5C8000–0x5C9200).
WORKRAM_LDAS_ONLY: tuple[dict[str, str], ...] = (
    {"workram": "0x005C8E60", "rom_lda": "0x029EE0", "role": "``0x05CE18`` compare template (8 bytes)"},
    {"workram": "0x005C8E70", "rom_lda": "0x02A014", "role": "Overflow compile format ptr (@ ``0x02A004``)"},
    {"workram": "0x005C8E90", "rom_lda": "0x02A02C", "role": "Mismatch compile format ptr (@ ``0x02A01C`` desert)"},
    {"workram": "0x005C8964", "rom_lda": "0x029954", "role": "Post-compile run trampoline (@ ``0x029960`` ``bx``)"},
    {"workram": "0x005C8BF0", "rom_lda": "0x029C5C", "role": "``0x029C10`` compile+run format ptr"},
    {"workram": "0x005C89B0", "rom_lda": "0x029A00", "role": "Alternate compile wrapper (@ ``0x299FC``)"},
)

# Suspected population paths — **disproven** as direct writers to ``0x005C8E90``.
NEGATIVE_POPULATION_PATHS: tuple[dict[str, Any], ...] = (
    {
        "id": "013238_course_mirror",
        "rom": "0x012DFC",
        "destinations": ["0x0100808E", "0x010080EE", "0x010080F0"],
        "effect": "Mirrors ``0x20A790`` course id — **not** ``0x005C8Exx``",
    },
    {
        "id": "0333C8_colorbase_copy",
        "rom": "0x0333C8",
        "destinations": ["0x01802000"],
        "effect": "Copies u16 table from ``0x005FB89E`` when ``0x005FB89C`` > 0 — palram staging",
    },
    {
        "id": "267B0_colorbase_fill",
        "rom": "0x0267B0",
        "destinations": ["0x01802000"],
        "effect": "Same ``0x005FB89C``/``0x005FB89E`` → ``0x01802000`` path as ``0x0333C8``",
    },
    {
        "id": "27260_descriptor_bus",
        "rom": "0x012DE4",
        "destinations": ["0x01000000"],
        "effect": "``call 0x027260`` patches D/U descriptor bus — **not** format template region",
    },
    {
        "id": "26760_template_table",
        "rom": "0x026760",
        "destinations": ["0x01800000"],
        "effect": "Copies halfword list from workram ``0x005C5670`` → ``0x01800000`` scratch — handler metadata",
    },
)

# Handler-clone bootstrap @ ``0x026700`` — **no static ROM call sites** (indirect via ``0x20B910`` only).
HANDLER_CLONE_CHAIN = (
    {"rom": "0x026700", "note": "``call 0x026A10`` cold-boot bus init; seeds ``0x20B910`` — **zero static callers**"},
    {"rom": "0x026750", "note": "Entry: ``lda 0x005C57F0`` return stub → ``0x026760`` template copy"},
    {"rom": "0x026800", "note": "``call 0x05DAA0`` clone nodes @ ``0x20B600``; invoked from ``0x026980`` only"},
    {"rom": "0x026980", "note": "``0x20B914`` stream → ``0x0100A000``; ``call 0x026800`` + ``0x0268B0`` — **no static callers**"},
    {"rom": "0x0269C4", "note": "``callx (0x20B910)`` when non-zero — only writer @ ``0x026704``"},
)

# Workram return stubs for bytecode bind / upload (all ``lda``-only in ROM).
WORKRAM_STUB_CHAIN = (
    {"workram": "0x005C5F68", "rom_lda": "0x026F14", "helper": "0x026F10 bind"},
    {"workram": "0x005C5FCC", "rom_lda": "0x026F74", "helper": "0x026F70 restore"},
    {"workram": "0x005C5FF0", "rom_lda": "0x026FD4", "helper": "0x026FD8 shift-base"},
    {"workram": "0x005C612C", "rom_lda": "0x027004", "helper": "0x027008 opcode dispatch"},
    {"workram": "0x005C61C8", "rom_lda": "0x027164", "helper": "0x027160 descriptor patch"},
    {"workram": "0x005C6250", "rom_lda": "0x0271D4", "helper": "0x0271D0 template emit"},
)

EMPTY_FORMAT_COMPILE = (
    {"rom": "0x02A01C", "insn": "``mov 1,g0; mov 1,g1`` then ``bal 0x026E18`` — counter seed only"},
    {"rom": "0x02A028", "insn": "``g0 = lda 0x005C8E90`` — **pointer cell** in workram slab"},
    {"rom": "0x05CEE4", "insn": "``stq g0,(g13)`` — record ``+0x00`` = format scan cursor value"},
    {"rom": "0x05CF60", "insn": "``mov g0,r12`` — format scan pointer in ``r12``"},
    {"rom": "0x05CF74", "insn": "``ldob (r12),g0`` — first format byte"},
    {"rom": "0x05CF78", "insn": "``cmpibne 0,g0,0x5CF8C`` — **byte 0 → empty compile**, ``r11=0``, ret"},
)

FIFO_REACHABILITY = (
    {
        "rom": "0x02A148",
        "path": "matched stream @ ``0x02A0F8`` only",
        "insn": "``ldos (g4),g3`` — per-chunk halfword read",
        "desert_static": False,
    },
    {
        "rom": "0x0299C0",
        "path": "XOR cluster @ ``0x029900`` (no static callers on desert ``0x012D90`` chain)",
        "insn": "``ldl 0xF00004,g4`` — hardware FIFO status/data",
        "desert_static": False,
    },
    {
        "rom": "0x02A7C8",
        "path": "upload cluster ``0x02A5A0``–``0x02A740`` (compiled thunk target)",
        "insn": "``lda 0x500000`` / ``0x504000`` — palette device map",
        "desert_static": "reachable only via ``0x005C8964`` patched body (OPEN)",
    },
)


def _scan_rom_stores_to_workram() -> list[tuple[str, str, str]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    hits: list[tuple[str, str, str]] = []
    for i, w in enumerate(words):
        rom = i * 4
        if rom > 0x600000:
            break
        hi = (w >> 24) & 0xFF
        if hi in (0x92, 0xB2, 0x9A, 0x8A, 0x82):
            imm = w & 0xFFFFFF
            if 0x5C8000 <= imm <= 0x005C9200:
                hits.append((f"0x{rom:08X}", f"0x{w:08X}", f"0x{imm:08X}"))
    return hits


def _workram_xref_table() -> list[dict[str, Any]]:
    _, words = load_maincpu_words(resolve_rom_dir())
    rows: list[dict[str, Any]] = []
    for entry in WORKRAM_LDAS_ONLY:
        addr = int(entry["workram"], 16)
        refs = find_word_refs(words, addr)
        rows.append({**entry, "rom_ref_count": len(refs), "rom_refs": [f"0x{r:08X}" for r in refs]})
    return rows


def _gate_head_analysis(main_data: bytes) -> dict[str, Any]:
    from tools.model2_palette import find_cgm_blocks

    alpine = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[0])
    desert = cgm_block_head_facts(main_data, COURSE_CGM_VADDRS[1])
    blocks = {b.vaddr: b for b in find_cgm_blocks(main_data)}
    vaddr_heads: dict[str, dict[str, str]] = {}
    tpl_cmp: dict[str, dict[str, Any]] = {}
    cgm_header_tpl = b"CGM 1.0 "
    for vaddr in COURSE_CGM_VADDRS[:2]:
        b = blocks[vaddr]
        head = main_data[b.rom_offset : b.rom_offset + 8]
        key = f"0x{vaddr:08X}"
        vaddr_heads[key] = {
            "bytes_hex": head.hex(),
            "ascii": "".join(chr(x) if 32 <= x < 127 else "." for x in head),
        }
        cmp = simulate_5ce18(head, cgm_header_tpl)
        tpl_cmp[key] = {"g0": cmp.g0, "reason": cmp.reason, "first_mismatch_index": cmp.first_mismatch_index}
    return {
        "vaddr_head_8_bytes": vaddr_heads,
        "identical_vaddr_prefix": vaddr_heads.get("0x028CCAF8") == vaddr_heads.get("0x028AF104"),
        "compare_vs_zero_template": {
            "alpine": alpine["compare_vs_static_zero_template"],
            "desert": desert["compare_vs_static_zero_template"],
        },
        "compare_vs_cgm_header_8_bytes": tpl_cmp,
        "note": (
            "``0x029ECC`` reads ``lda 0(g2)`` at block **vaddr** (``rom_offset``), not ``data_offset``. "
            "Alpine and desert share the same 8-byte vaddr prefix ``CGM 1.0 `` (byte7=0x20). "
            "With zero ``0x005C8E60`` template both mismatch; with ``CGM 1.0 `` template both match "
            "→ ``0x029EF0`` stream walk **if** ``0x20C954 <= 0x1FF``."
        ),
    }


def build_report(*, slot: int | None = None) -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    rom_stores = _scan_rom_stores_to_workram()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM scan — no MAME, no XOR inference",
        "slot_focus": slot,
        "summary": (
            "No ROM ``st``/``stq`` with immediate in ``0x005C8000``–``0x005C9200``. "
            "``0x005C8E90`` content at desert ``0x02A028`` must be runtime-filled; if qword=0 "
            "or first format byte=0, ``0x05CF50`` returns empty bytecode (``r11=0`` @ ``0x05CF8C``). "
            "``0x005C8964`` runner body is likewise workram-only; desert ``0x02A038`` skips "
            "``call 0x027130`` pre-walk used @ ``0x29A4C``."
        ),
        "workram_ldas_only": _workram_xref_table(),
        "rom_store_scan_5c8000_5c9200": {
            "count": len(rom_stores),
            "hits": [{"rom": a, "word": b, "imm": c} for a, b, c in rom_stores],
        },
        "negative_population_paths": list(NEGATIVE_POPULATION_PATHS),
        "handler_clone_chain": list(HANDLER_CLONE_CHAIN),
        "workram_stub_chain": list(WORKRAM_STUB_CHAIN),
        "empty_format_compile": list(EMPTY_FORMAT_COMPILE),
        "fifo_reachability": list(FIFO_REACHABILITY),
        "gate_head_analysis": _gate_head_analysis(main_data),
        "open_gaps": [
            "Runtime writer(s) for ``0x005C8E60`` compare template and ``0x005C8E90`` format bytes",
            "``0x005C8964`` patched body — link from ``0x05D5AC`` bytecode to ``0x026F10`` / ``0x02A6D0``",
            "Runtime fill of ``0x20B1C0[0x20]`` handler record (clone @ ``0x26800``)",
            "``0x005C8964`` body: walk ``0x05D5AC`` bytecode without ``0x027130`` pre-call",
            "Consumer of ``0x20A7B0`` desert compile return (@ ``0x012E48``)",
        ],
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slot", type=int, default=None)
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_workram_template_population_re.json",
    )
    args = ap.parse_args()
    report = build_report(slot=args.slot)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}")
    gate = report["gate_head_analysis"]
    print(f"Identical 8-byte vaddr prefix alpine/desert: {gate['identical_vaddr_prefix']}")
    print(f"ROM stores to 0x5C8000–0x5C9200: {report['rom_store_scan_5c8000_5c9200']['count']}")


if __name__ == "__main__":
    main()
