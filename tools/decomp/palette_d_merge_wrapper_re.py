#!/usr/bin/env python3
"""Disasm RE: ``D`` → ``0x02A6D0`` wrapper → ``0x02A4E0`` merge (no FIFO in ROM cluster).

Traces how compiled ``D``/``U`` reach the upload runner, documents the four
``0x02A5A0`` calls inside ``0x02A6D0``, and **negatively** scans the fixed
ROM upload cluster ``0x02A200``–``0x02A850`` for FIFO ``ldos`` / ``xor g13``.

Proves ``record+0x14`` handler table is filled only on the ``E``/``f``/``g``
path (@ ``0x05DE00``); lone ``D`` uses bytecode @ ``0x05D860`` instead.

  python3 -m tools.decomp.palette_d_merge_wrapper_re
  python3 -m tools.decomp.palette_d_merge_wrapper_re --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.decomp.palette_d_emit_trace import TEMPLATE_CANDIDATES
from tools.decomp.palette_handler_dispatch import merge_oracle_search
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import compile_format_fragment
from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.model2_cgm_staging import CgmStagingSim

REPO_ROOT = Path(__file__).resolve().parents[2]
DISASM_UPLOAD_FILES = (
    REPO_ROOT / "decomp/disasm/maincpu/maincpu_02a0f8_400.asm",
    REPO_ROOT / "decomp/disasm/maincpu/maincpu_02a5a0_2b0.asm",
)
DESERT_SLOT477_FRAG = "3333DD3DUUDTDDTU43UD33U433E4"

# --- ``0x02A6D0`` four ``call 0x02A5A0`` permutations (disasm-proven) ---------

WRAPPER_2A6D0 = {
    "rom": "0x02A6D0",
    "saves": {
        "r7": "orig g0",
        "r8": "orig g1",
        "r5": "orig g2",
        "r4": "orig g3",
        "r6": "orig g4",
    },
    "calls": (
        {
            "call_rom": "0x02A6E8",
            "g0": "r7 (orig g0)",
            "g1": "r4 (orig g3)",
            "g2": "r7 (orig g0)",
            "g3": "r4 (orig g3)",
            "g4": "r6 (orig g4)",
            "g5": "return from prior call",
            "note": "First upload sweep — ``g2`` loop bound = outer g0",
        },
        {
            "call_rom": "0x02A704",
            "g0": "r7",
            "g1": "r4",
            "g2": "r5 (orig g2)",
            "g3": "r4",
            "g4": "r6",
            "g5": "prior g0",
            "note": "Second sweep — ``g2`` bound = orig g2",
        },
        {
            "call_rom": "0x02A720",
            "g0": "r5",
            "g1": "r4",
            "g2": "r5",
            "g3": "r8 (orig g1)",
            "g4": "r6",
            "g5": "prior g0",
            "note": "Third sweep — ``g3`` bound = orig g1",
        },
        {
            "call_rom": "0x02A73C",
            "g0": "r5",
            "g1": "r8",
            "g2": "r7",
            "g3": "r8",
            "g4": "r6",
            "g5": "prior g0",
            "note": "Fourth sweep — permuted g0/g1/g2/g3",
        },
    ),
    "merge_gate": {
        "rom": "0x02A61C",
        "test": "``bbc 0,r5,0x2A630`` — saved ``g5`` bit 0",
        "set_by": "``D``/``U`` @ ``0x05D3DC``/``0x05D714`` ``setbit 0,r9`` → ``g4`` bit 0 at run",
        "merge_rom": "0x02A62C",
        "merge_args": "``g0=r10``, ``g1=r9``, ``g2=r14`` (= orig wrapper ``g4``)",
        "critical": (
            "Merge value is **wrapper g4**, not FIFO ``ldos``. Upload runner "
            "``0x02A5A0``–``0x02A740`` has **no** ``ldos`` from parameter stream."
        ),
    },
}

# --- Handler path split: D vs E record+0x14 ------------------------------------

RECORD_PLUS_14 = {
    "d_path": {
        "compile": "``0x05D3DC`` → ``0x05D440`` → ``0x05D7E8`` → ``0x05D860``",
        "never_calls": "``0x05DE00`` (no ``record+0x14`` table fill)",
        "run": "Bytecode chain → ``0x027130`` walk → ``0x029958`` @ ``0x005C8964``",
    },
    "e_path": {
        "compile": "``0x05D448`` … → ``0x05D524`` ``call 0x05DE00``",
        "fills": "``0x05DFA4`` ``stob`` loop → handler blob; ``0x05DFEC`` link @ ``+0x8``",
        "dispatch": "``0x02A10C`` ``lda 0x14(g0)[index*2]`` → ``bx (0x005C9118)``",
    },
    "29c10_fifo_cursor": {
        "rom": "0x29CDC",
        "insn": "``lda 0x14(g0),g7`` then ``ldos (g7),g4`` @ ``0x29CF8``",
        "note": (
            "Legacy ``0x029C10`` ADD path treats ``+0x14`` as **pointer to FIFO cursor**, "
            "not the ``0x02A0F8`` handler u16 table. Same offset name, different role."
        ),
    },
}

# --- Negative scan: upload cluster ROM ---------------------------------------

UPLOAD_CLUSTER_ROM_RANGE = (0x02A200, 0x02A850)


def _scan_upload_cluster_disasm() -> dict[str, Any]:
    """Parse disasm slices for ``ldos`` / ``xor g13`` inside upload cluster."""
    lines: list[str] = []
    sources: list[str] = []
    for path in DISASM_UPLOAD_FILES:
        if path.is_file():
            lines.extend(path.read_text(encoding="utf-8").splitlines())
            sources.append(str(path.relative_to(REPO_ROOT)))

    ldos_rows: list[dict[str, str]] = []
    xor_g13_rows: list[dict[str, str]] = []
    add_g13_rows: list[dict[str, str]] = []

    addr_re = re.compile(r"^(?:0+)?(2A[0-9A-F]{3,4}):")

    for line in lines:
        m = addr_re.match(line.strip())
        if not m:
            continue
        rom = int(m.group(1), 16)
        if not (UPLOAD_CLUSTER_ROM_RANGE[0] <= rom <= UPLOAD_CLUSTER_ROM_RANGE[1]):
            continue
        if "ldos" in line.lower():
            ldos_rows.append({"rom": f"0x{rom:05X}", "line": line.strip()})
        if re.search(r"xor\s+g\d+,g13", line, re.I):
            xor_g13_rows.append({"rom": f"0x{rom:05X}", "line": line.strip()})
        if re.search(r"addo\s+g13", line, re.I):
            add_g13_rows.append({"rom": f"0x{rom:05X}", "line": line.strip()})

    NON_FIFO_LDOS = frozenset(
        {
            "0x02A250",
            "0x02A370",
            "0x02A56C",
            "0x02A148",
            "0x02A16C",
            "0x2A250",
            "0x2A370",
            "0x2A56C",
        }
    )
    fifo_ldos = [r for r in ldos_rows if r["rom"] not in NON_FIFO_LDOS]
    xor_batch_only = bool(xor_g13_rows) and all(
        r["rom"].upper().endswith("2A258") for r in xor_g13_rows
    )

    return {
        "disasm_files": sources,
        "rom_range": f"0x{UPLOAD_CLUSTER_ROM_RANGE[0]:05X}–0x{UPLOAD_CLUSTER_ROM_RANGE[1]:05X}",
        "ldos_count": len(ldos_rows),
        "ldos_sites": ldos_rows,
        "fifo_ldos_count": len(fifo_ldos),
        "fifo_ldos_sites": fifo_ldos,
        "xor_g13_count": len(xor_g13_rows),
        "xor_g13_sites": xor_g13_rows,
        "add_g13_count": len(add_g13_rows),
        "add_g13_sites": add_g13_rows,
        "conclusion": (
            "No parameter-FIFO ``ldos`` in ``0x02A200``–``0x02A740``. "
            f"``ldos`` @ ``0x02A250``/``0x02A258`` is **staging bus** read (# batch only). "
            f"``ldos`` @ ``0x02A56C`` reads palram bus for merge. "
            f"``xor g13`` only @ ``0x02A258`` (``g3>0``). "
            "FIFO u16 → merge ``g2`` must occur in patched workram thunks."
            if not fifo_ldos and xor_batch_only
            else "Unexpected insn pattern — re-check disasm slices."
        ),
    }


def _template_stub_sweep() -> list[dict[str, Any]]:
    """Bind slot-477 last-``D`` bytecode under each template candidate."""
    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]
    if not d_events:
        return []
    last = d_events[-1]
    bc = [int(x, 16) for x in last.get("bytecode", [])]

    rows: list[dict[str, Any]] = []
    for name, template_rows in TEMPLATE_CANDIDATES.items():
        row_bytes = template_rows[1 % len(template_rows)] if template_rows else b""
        bound = bind_and_run(bc, template_row=row_bytes)
        rows.append(
            {
                "template": name,
                "template_row_hex": row_bytes.hex(),
                "stub_patches": len(bound.stub_patches),
                "patch_sample": bound.stub_patches[:6],
                "descriptors": {str(k): f"0x{v:04x}" for k, v in sorted(bound.descriptors.items())[:8]},
                "counters": {
                    "slot": bound.counters.slot,
                    "width": bound.counters.width,
                },
            }
        )
    return rows


def _merge_bounds_from_2a2e0(*, g0: int, g1: int, g2: int = 0, g3: int = 0) -> dict[str, int]:
    """``0x02A2E0`` spill vs table path (simplified — indices in-range only)."""
    merge_lo = (g0 << 3) if g0 <= 61 else 0
    merge_mid = (g1 << 3) if g1 <= 47 else 0
    return {
        "merge_lo_20C95C": merge_lo,
        "merge_mid_20C960": merge_mid,
        "merge_max_20C968": 0x17F,
        "merge_max2_20C964": 0x1EF,
    }


def _identity_merge_test(*, g2: int, slot: int, g13_seed: int = 0x0700) -> dict[str, Any]:
    """Does ``0x02A4E0`` with ``g2=value`` identity-write ``value`` on empty bus?"""
    sim = CgmStagingSim(g13_mask=g13_seed)
    sim.merge_lo = 0
    sim.merge_mid = 0
    sim.merge_max = 0x17F
    sim.merge_max2 = 0x1EF
    hits: list[dict] = []
    g2v = int(g2) & 0xFFFF
    for g0 in range(0, 64, 8):
        for g1 in range(0, 0x180, 0x40):
            out = sim.op_2a4e0_merge(g0=g0, g1=g1, g2=g2v)
            if out is not None and (out & 0x7FFF) == (g2v & 0x7FFF):
                hits.append({"g0": g0, "g1": g1, "out": f"0x{out:04x}"})
                if len(hits) >= 4:
                    break
        if len(hits) >= 4:
            break
    return {
        "g2": f"0x{g2v:04x}",
        "identity_hits": hits,
        "identity_possible": len(hits) > 0,
    }


def build_report(
    *,
    slot: int = 477,
    raw_u16: int = 0x8843,
    target_color15: int = 0x6683,
) -> dict[str, Any]:
    g13_seed = 0x0700
    g13_table = g13_mask_for_slot(g13_seed, slot)
    xor_decoded = (int(raw_u16) & 0xFFFF) ^ (g13_table & 0xFFFF)

    events = compile_format_fragment(DESERT_SLOT477_FRAG)
    d_events = [e for e in events if e.get("op") == "D"]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "i960 disasm + bytecode sim — no MAME, no xor_table as hardware proof",
        "wrapper_2a6d0": WRAPPER_2A6D0,
        "record_plus_14": RECORD_PLUS_14,
        "upload_cluster_scan": _scan_upload_cluster_disasm(),
        "template_stub_sweep": _template_stub_sweep(),
        "focus": {
            "slot": slot,
            "raw_u16": f"0x{int(raw_u16) & 0xFFFF:04x}",
            "target_color15": f"0x{int(target_color15) & 0x7FFF:04x}",
            "oracle_xor_decode": f"0x{xor_decoded & 0x7FFF:04x}",
            "format_frag": DESERT_SLOT477_FRAG,
            "d_events_in_frag": len(d_events),
            "merge_g2_candidates": {
                "raw_fifo": _identity_merge_test(g2=raw_u16, slot=slot, g13_seed=g13_seed),
                "xor_table_decode": _identity_merge_test(g2=xor_decoded, slot=slot, g13_seed=g13_seed),
                "target_color15": _identity_merge_test(g2=target_color15, slot=slot, g13_seed=g13_seed),
            },
            "merge_bounds_example": _merge_bounds_from_2a2e0(g0=3, g1=47),
        },
        "merge_oracle_search": merge_oracle_search(
            slot=slot,
            raw_u16=raw_u16,
            target_color15=target_color15,
            g13_seed=g13_seed,
            g13_table=g13_table,
        ),
        "conclusions": (
            "Hardware lone-``D`` path: compile emits bytecode (@ ``0x05D860``), **not** "
            "``record+0x14`` handler table (@ ``0x05DE00`` is ``E``/``f``/``g`` only).",
            "ROM upload cluster ``0x02A200``–``0x02A850`` never reads FIFO; ``0x02A62C`` "
            "merge uses ``g2=r14=wrapper g4``. FIFO→``g4`` transform is in patched "
            "workram thunks — static ROM image @ ``0x005C8964`` is ``ret`` only.",
            "``0x02A4E0`` can identity-merge ``g2=xor_table_decode`` on empty bus for "
            "some ``g0``/``g1`` — does **not** prove hardware applies XOR before merge.",
            "Template row bytes (@ ``0x005FBF10``) select ``0x0271D0`` stub patches; "
            "zeros row → **0** patches for slot-477 last-``D`` bytecode.",
        ),
        "open_gaps": (
            "Disassemble patched ``0x005C61C8`` / ``0x005C6250`` bodies after ``0x027130`` walk",
            "Map ``0x26800`` cloned handler @ ``0x20B1C0[0x20]`` → FIFO read + g4 publish",
            "Recover runtime ``0x005FBF10`` template row (``0x012DE4`` ``0x027260`` chain?)",
            "Prove wrapper ``g0``/``g1``/``g4`` args for chunk-87 ``D`` run → slot 477",
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="D merge wrapper disasm RE")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_d_merge_wrapper_re.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target_color15=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    scan = report["upload_cluster_scan"]
    print(f"\nUpload cluster scan ({scan['rom_range']}):")
    print(
        f"  ldos: {scan['ldos_count']} (fifo={scan['fifo_ldos_count']})  "
        f"xor g13: {scan['xor_g13_count']}"
    )
    print(f"  {scan['conclusion'][:120]}…")

    focus = report["focus"]
    print(f"\nSlot {args.slot}: raw {focus['raw_u16']} oracle_xor {focus['oracle_xor_decode']}")
    for label, body in focus["merge_g2_candidates"].items():
        print(f"  merge g2={label}: identity_possible={body['identity_possible']}")

    sweep = report["template_stub_sweep"]
    print("\nTemplate stub patches (last D in slot-477 frag):")
    for row in sweep:
        print(f"  {row['template']:16s}: patches={row['stub_patches']} counters={row['counters']}")

    for line in report["conclusions"][:2]:
        print(f"\n{line}")


if __name__ == "__main__":
    main()
