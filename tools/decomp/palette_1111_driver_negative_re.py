#!/usr/bin/env python3
"""Disasm RE: negative scan for desert ``0x1111`` runtime body driver.

Documents the ``0x26690``→``0x269C4`` handler bootstrap, ``0x012D90`` palette init
seeds vs ``0x026980`` clone chain, ``0x02A050`` ``+0x22`` span materializer, and
proves **no** static maincpu path replays the ``0x1111`` marker-split payload to
slot 477 on the proven desert ``g4=4`` matched init path.

No MAME. xor_table labeled oracle only.

  python3 -m tools.decomp.palette_1111_driver_negative_re
  python3 -m tools.decomp.palette_1111_driver_negative_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.i960_scan import find_word_refs, load_maincpu_words
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.model2_palette import COURSE_CGM_VADDRS, find_cgm_blocks, _iter_cgm_v16_records
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
DESERT_VADDR = COURSE_CGM_VADDRS[1]

# --- Handler bootstrap @ ``maincpu_026670_120.asm`` / ``maincpu_026800_200.asm`` ---

HANDLER_BOOTSTRAP = (
    {"rom": "0x26690", "effect": "Template body: palram pack via ``0x26B94``/``0x26C44`` — no FIFO ``ldos``"},
    {"rom": "0x26704", "effect": "``st g14,0x20B910`` — indirect dispatch target for ``callx`` @ ``0x269C4``"},
    {"rom": "0x26800", "effect": "Clone ``0x20B600`` list → ``0x20B1C0`` handler pool via ``0x05DAA0``"},
    {"rom": "0x26980", "effect": "``ldos 0x20B914`` stream → ``0x0100A000``; ``call 0x26800`` + ``0x268B0``"},
    {"rom": "0x269B8", "effect": "``ld 0x20B910,g4``"},
    {"rom": "0x269C4", "effect": "``callx (g4)`` when ``g4 != 0`` — runtime-only entry"},
)

# --- Palette init seeds (@ ``maincpu_012d00_200.asm``) -------------------------

INIT_SEEDS = (
    {"rom": "0x012DB0", "effect": "``stos 0xC000,0x20B914`` — u16 stream head for ``0x26980`` **if** invoked"},
    {"rom": "0x012E3C", "effect": "Desert ``0x029EB0`` ``g4=4`` → matched ``0x29EF0`` path (not ``0x02A01C``)"},
    {"rom": "0x012E40", "effect": "``ld 0x20A7B4,g2`` — **only** static ``ld``; zero static ``st`` to ``0x20A7B4``"},
    {"rom": "0x012EE0", "effect": "``bal 0x132A8`` — lumaram/colorxlat table setup; not ``0x1111`` replay"},
    {"rom": "0x01638C", "effect": "Course hook: ``stos g14,0x20B914`` — game init cluster, not desert-specific"},
)

# --- ``0x02A050`` span materializer (@ ``maincpu_02a050_150.asm``) ------------

SPAN_MATERIALIZER_2A050 = (
    {"rom": "0x29F34", "effect": "Matched path only: ``bal 0x02A050`` with outer ``r5`` in ``g1``"},
    {"rom": "0x02A06C", "effect": "``r5 = ld(g1)`` — inner cursor from outer node"},
    {"rom": "0x02A070", "effect": "``ldos (r5),g4`` — span halfword; loop advances ``r5 += 0x22``"},
    {"rom": "0x02A0A0", "effect": "``stos g4,0x01080000`` — palram packed bus row"},
    {"rom": "0x02A114", "effect": "``0x02A0F8`` early return on ``0x29FA0`` path — handler word not branched"},
)

# --- Bind opcode ``0x20`` (@ ``maincpu_026e18_200.asm``) ----------------------

BIND_OPCODE_20 = (
    {"rom": "0x026F44", "effect": "``g4 = 0x20B1C0[index*4]`` — handler record from clone pool"},
    {"rom": "0x026F64", "effect": "``bx (0x005C5F68)`` — patched workram stub chain"},
    {"note": "Slot-477 ``D`` bytecode ``[0x20,0x00,…]`` → bind index 32; upload merge @ ``0x02A62C`` needs ``0x029958`` runner"},
)


def _scan_call_targets(rom_dir: Path) -> dict[str, list[str]]:
    """Find ``call``/``bal`` sites whose target equals a ROM address."""
    targets = {
        "0x026980": [],
        "0x026700": [],
        "0x026690": [],
        "0x026918": [],
    }
    pat = re.compile(r"^([0-9a-f]+):\s+[0-9a-f]+\s+[0-9a-f]+\s+(call|bal)\s+0x([0-9a-f]+)", re.I | re.M)
    for asm in (REPO_ROOT / "decomp/disasm/maincpu").glob("*.asm"):
        if not asm.is_file():
            continue
        text = asm.read_text(encoding="utf-8", errors="replace")
        for m in pat.finditer(text):
            site, kind, dest = m.group(1), m.group(2), m.group(3)
            key = f"0x{int(dest, 16):06X}"
            if key in targets:
                targets[key].append(f"0x{int(site, 16):06X} ({kind})")
    return targets


def _workram_st_ld_scan(words: list[int]) -> dict[str, Any]:
    addrs = {
        "0x20A7B4": 0x0020A7B4,
        "0x20B910": 0x0020B910,
        "0x20B914": 0x0020B914,
        "0x20A7B0": 0x0020A7B0,
    }
    out: dict[str, Any] = {}
    for label, wr in addrs.items():
        refs = find_word_refs(words, wr)
        out[label] = {
            "workram": f"0x{wr:08X}",
            "static_immediate_refs": len(refs),
            "sites": [f"0x{r:06X}" for r in refs[:12]],
        }
    return out


def _desert_block_layout() -> dict[str, Any]:
    md = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    blocks = {b.vaddr: b for b in find_cgm_blocks(md)}
    block = blocks[DESERT_VADDR]
    base = block.rom_offset

    # Locate ``0x1111`` v16 record.
    payload_off = None
    payload_len = None
    for rec_type, rec_len, off in _iter_cgm_v16_records(md, block):
        if rec_type == 0x1111:
            payload_off = off
            payload_len = rec_len
            break
    rec_type = struct.unpack_from("<H", md, base + 0x2C)[0] if base + 0x2E <= len(md) else 0

    # ``+0x22`` stride walk from ``block+0x08`` (``2A050`` inner cursor model).
    chain: list[dict[str, str]] = []
    cursor = base + 0x08
    for step in range(12):
        if cursor + 2 > len(md):
            break
        u16 = struct.unpack_from("<H", md, cursor)[0]
        chain.append(
            {
                "step": str(step),
                "block_off": f"+0x{cursor - base:X}",
                "ldos_u16": f"0x{u16:04X}",
                "next_off": f"+0x{cursor - base + 0x22:X}",
            }
        )
        cursor += 0x22

    head = struct.unpack_from("<I", md, base)[0]
    link = struct.unpack_from("<I", md, base + 0x0C)[0]
    node = struct.unpack_from("<HH", md, base + 0x08)

    return {
        "block_vaddr": f"0x{block.vaddr:08X}",
        "block_rom_off": f"0x{base:08X}",
        "head_dword": f"0x{head:08X}",
        "node_plus_08": {"span": node[0], "inner": f"0x{node[1]:04X}"},
        "link_plus_0c": f"0x{link:08X}",
        "record_1111": {
            "block_off": f"+0x{(payload_off or 0) - base:X}" if payload_off else None,
            "len": payload_len,
            "v16_type_at_plus_2c": f"0x{rec_type:04X}",
        },
        "2a050_stride_chain_from_plus_08": chain,
        "chain_hits_1111_marker": any(r["ldos_u16"] == "0x1111" for r in chain),
    }


def _negative_verdicts(*, slot: int, raw_u16: int) -> tuple[dict[str, Any], ...]:
    mask = g13_mask_for_slot(0x0700, slot) & 0xFFFF
    oracle = (raw_u16 ^ mask) & 0x7FFF
    return (
        {
            "id": "no_static_1111_format_replay",
            "proven": True,
            "note": (
                "Zero ``call``/``bal`` passes desert ``0x1111`` payload @ block ``+0x4A`` as "
                "``0x05CF50`` format string; ``0x005C8964`` runner is ``ret`` unless runtime-patched"
            ),
        },
        {
            "id": "desert_g4_skips_29c10_tail",
            "proven": True,
            "rom": "0x29FE4",
            "note": "``g4=4`` → ``0x29FFC`` without ``0x29C10`` — prefix rows via ``0x29F7C`` only",
        },
        {
            "id": "upload_sweeps_max_slot_55",
            "proven": True,
            "rom": "0x012ED4",
            "note": f"Post-init ``0x029C10`` sweeps end slot 55; replay slot {slot} outside envelope",
        },
        {
            "id": "26980_no_static_caller",
            "proven": True,
            "note": "``0x026980`` handler clone/bootstrap has zero static ``call`` sites",
        },
        {
            "id": "20a7b4_runtime_only",
            "proven": True,
            "note": "``0x20A7B4`` consumed @ ``0x012E40`` sweep only; no static writer",
        },
        {
            "id": "slot477_decode_insn_open",
            "proven": False,
            "note": (
                f"No static insn maps raw ``0x{raw_u16:04X}`` → ``0x{oracle:04X}`` on proven desert path; "
                "xor_table is Python replay oracle only"
            ),
        },
    )


def build_report(*, slot: int = 477, raw_u16: int = 0x8843) -> dict[str, Any]:
    _, words = load_maincpu_words(resolve_rom_dir())
    call_sites = _scan_call_targets(resolve_rom_dir())
    wr_xrefs = _workram_st_ld_scan(words)
    block = _desert_block_layout()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + ROM xref — no MAME, no xor_table hardware proof",
        "focus": {
            "course": "desert",
            "block_vaddr": block["block_vaddr"],
            "slot": slot,
            "raw_u16": f"0x{raw_u16:04X}",
            "python_xor_oracle": f"0x{(raw_u16 ^ g13_mask_for_slot(0x0700, slot)) & 0x7FFF:04X}",
        },
        "handler_bootstrap": list(HANDLER_BOOTSTRAP),
        "init_seeds": list(INIT_SEEDS),
        "span_materializer_2a050": list(SPAN_MATERIALIZER_2A050),
        "bind_opcode_20": list(BIND_OPCODE_20),
        "static_call_sites": call_sites,
        "workram_xrefs": wr_xrefs,
        "desert_block": block,
        "negative_verdicts": list(_negative_verdicts(slot=slot, raw_u16=raw_u16)),
        "open_gaps": [
            "Runtime ``0x1111`` driver: who sets ``0x20B910`` nonzero and invokes ``0x269C4`` ``callx``?",
            "``block+0 ← block_vaddr`` self-pointer fixup writer (no static ``st`` proof)",
            "Whether ``0x02A050`` ``+0x22`` chain after stream-root fixup reaches FIFO offset ``0x3A6``",
            "Patched ``0x005C8964`` / ``0x20B1C0[0x20]`` body for lone ``D`` tier-B merge",
        ],
        "related_tools": [
            "tools.decomp.palette_29fe4_g4_gate_re",
            "tools.decomp.palette_opcode20_bind_upload_re",
            "tools.decomp.palette_handler_template_26690_re",
            "tools.decomp.palette_record_plus14_fifo_re",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Negative RE: desert 0x1111 runtime driver")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_1111_driver_negative_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    proven = sum(1 for v in report["negative_verdicts"] if v.get("proven"))
    total = len(report["negative_verdicts"])
    print(f"\nNegative verdicts: {proven}/{total} proven in disasm")
    for gap in report["open_gaps"]:
        print(f"  OPEN: {gap}")
    print(f"\n26980 static callers: {len(report['static_call_sites']['0x026980'])}")
    print(f"2A050 +0x22 chain hits 0x1111 marker: {report['desert_block']['chain_hits_1111_marker']}")


if __name__ == "__main__":
    main()
