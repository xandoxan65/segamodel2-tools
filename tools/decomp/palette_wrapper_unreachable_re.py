#!/usr/bin/env python3
"""Disasm RE: upload wrapper ``0x02A6D0`` has no static entry — close false leads.

Byte-displacement ``call``/``bal`` scan of maincpu proves:

- External entries into ``0x02A2E0``–``0x02A900`` are only ``0x02A7A0`` (bus list init)
  and internal runner↔merge links. **Zero** hits on ``0x02A2E0`` / ``0x02A490`` /
  ``0x02A6D0`` / ``0x02A750``.
- No ROM or main_data dword equals those addresses (no pointer table).
- Format cluster (``0x05Dxxx``) only ``bal 0x027008`` — never the upload cluster.
- Desert ``0x1111`` still has ~2971 ``D`` atoms; Python oracle uses ``merge_raw`` +
  scratch. Lift interim: ``cgm_fifo_record(D)`` → drain → ``cgm_d_merge_commit``.

No MAME. No xor_table as hardware proof.

  python3 -m tools.decomp.palette_wrapper_unreachable_re
"""

from __future__ import annotations

import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.model2_cgm_1111 import CGM_RECORD_1111, _is_format_chunk, _split_inner_chunks
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_palette import COURSE_CGM_VADDRS, _iter_cgm_v16_records, find_cgm_blocks
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

CLUSTER_ENTRIES = {
    0x2A2E0: "digit_staging",
    0x2A490: "scratch_write",
    0x2A4E0: "merge",
    0x2A5A0: "runner",
    0x2A6D0: "wrapper",
    0x2A750: "span",
    0x2A7A0: "bus_list_init",
}


def _ctrl_dest(ip: int, word: int) -> int:
    disp = word & 0xFFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return ip + disp


def _load_maincpu() -> bytes:
    built = REPO_ROOT / "decomp/out/i960/maincpu_deinterleaved.bin"
    if built.is_file():
        return built.read_bytes()
    from tools.i960_scan import load_maincpu_words

    words = load_maincpu_words(resolve_rom_dir())
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def _scan_entries(rom: bytes) -> dict[str, Any]:
    by_name: dict[str, list[dict[str, str]]] = {n: [] for n in CLUSTER_ENTRIES.values()}
    into_band: list[dict[str, str]] = []
    for i in range(0, len(rom) - 4, 4):
        w = struct.unpack_from("<I", rom, i)[0]
        if (w >> 24) not in (0x09, 0x0B):
            continue
        dest = _ctrl_dest(i, w)
        name = CLUSTER_ENTRIES.get(dest)
        row = {
            "from": f"0x{i:X}",
            "to": f"0x{dest:X}",
            "op": "call" if (w >> 24) == 0x09 else "bal",
            "scope": "int" if 0x2A2E0 <= i < 0x2A900 else "ext",
        }
        if name:
            by_name[name].append(row)
        if 0x2A2E0 <= dest < 0x2A900:
            into_band.append({**row, "name": name or "other"})
    return {"by_entry": by_name, "into_0x2A2E0_0x2A900": into_band}


def _dword_refs(rom: bytes) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for addr, name in CLUSTER_ENTRIES.items():
        refs = [
            f"0x{i:X}"
            for i in range(0, len(rom) - 4, 4)
            if struct.unpack_from("<I", rom, i)[0] == addr
        ]
        out[name] = refs
    return out


def _desert_d_stats() -> dict[str, Any]:
    main_data = load32_word_region(resolve_rom_dir(), SRALLY_DATA_ROMS["main_data"])
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    ops: Counter[str] = Counter()
    d_atoms = 0
    u_atoms = 0
    hash_batches = 0
    frags = 0
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type != CGM_RECORD_1111:
            continue
        payload = main_data[off : off + rec_len]
        for chunk in _split_inner_chunks(payload):
            if not chunk or not _is_format_chunk(chunk):
                continue
            frags += 1
            frag = chunk.decode("latin1", errors="replace")
            for event in compile_format_fragment(frag):
                op = str(event.get("op") or "")
                ops[op] += 1
                rep = int(event.get("repeat") or 1)
                if op == "D":
                    d_atoms += rep
                elif op == "U":
                    u_atoms += rep
                elif op == "#":
                    hash_batches += rep
    return {
        "format_frags": frags,
        "op_event_counts": dict(ops.most_common()),
        "D_atoms_with_repeat": d_atoms,
        "U_atoms_with_repeat": u_atoms,
        "hash_batches": hash_batches,
    }


def build_report() -> dict[str, Any]:
    rom = _load_maincpu()
    scan = _scan_entries(rom)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 byte-displacement call/bal scan + desert CGM format count",
        "verdict": (
            "``0x02A6D0`` / ``0x02A2E0`` / ``0x02A490`` / ``0x02A750`` have **zero** "
            "static callers and **zero** ROM pointer immediates. Wrapper ``g4`` publish "
            "cannot be recovered from bind/clone or format emit. Interim: FIFO ``D`` → "
            "``cgm_d_merge_commit`` (``merge_raw``)."
        ),
        "cluster_call_bal": scan,
        "cluster_dword_refs": _dword_refs(rom),
        "desert_1111": _desert_d_stats(),
        "lift_interim": (
            "``cgm_fifo_record(D/U)`` in format handlers; drain calls "
            "``cgm_d_merge_commit`` for D and ADD tile-place for U"
        ),
        "still_open": (
            "Runtime/indirect entry into ``0x02A6D0`` with bus coords — no static lead remains"
        ),
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_wrapper_unreachable_re.json",
    )
    args = ap.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    print(report["verdict"])
    d = report["desert_1111"]
    print(
        f"Desert D atoms={d['D_atoms_with_repeat']} U={d['U_atoms_with_repeat']} "
        f"#={d['hash_batches']}"
    )
    wrap = report["cluster_call_bal"]["by_entry"]["wrapper"]
    print(f"Wrapper call/bal sites: {len(wrap)}")


if __name__ == "__main__":
    main()
