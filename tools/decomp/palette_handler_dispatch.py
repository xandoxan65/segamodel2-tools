#!/usr/bin/env python3
"""Static RE: ``0x20B1C0`` handler dispatch + ``0x02A2E0`` merge globals.

Traces how palette boot (@ ``0x012DE4`` / ``0x026980``) clones handler templates
from ``0x20B600``, how ``0x026F10`` binds descriptor opcodes into live records,
and what ``0x02A4E0`` expects for ``g0``/``g1``/``g2`` on the D/U merge path.

No MAME workram captures — ROM disasm + bounded merge search only.

  python3 -m tools.decomp.palette_handler_dispatch
  python3 -m tools.decomp.palette_handler_dispatch --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.model2_cgm_staging import CgmStagingSim

REPO_ROOT = Path(__file__).resolve().parents[2]

# Disasm-backed bootstrap chain (workram addresses are runtime-only in static ROM).
HANDLER_BOOTSTRAP = (
    {
        "rom": "0x012DE4",
        "effect": "Palette init: call 0x27260 batch stub patch (g0=15,g1=30,g2=35,g3=6)",
    },
    {
        "rom": "0x012DF8",
        "effect": "Second 0x27260 (g0=7,g1=29,g2=35,g3=21) — seeds descriptor chains",
    },
    {
        "rom": "0x026980",
        "effect": "Copy u16 stream @ 0x20B914 → staging bus 0x0100A000",
    },
    {
        "rom": "0x0269B0",
        "effect": "call 0x26800 — clone handler templates from 0x20B600 linked list",
    },
    {
        "rom": "0x0269B4",
        "effect": "call 0x268B0 — scratch flush helper",
    },
    {
        "rom": "0x026800",
        "effect": "Walk 0x20B600 nodes; each node → call 0x5DAA0 memcpy into handler pool",
    },
    {
        "rom": "0x026860",
        "effect": "For opcode index g5: 0x20B600[g4*4] record ← g0, +8 ← g2",
    },
)

STAGING_COUNTERS = {
    "0x20B1A0": "Opcode-stream cursor (index into descriptor byte stream)",
    "0x20B1A4": "Saved bind arg (width / outer index)",
    "0x20B1A8": "Slot counter (@ 0x27008 emit, capped ~61)",
    "0x20B1AC": "Width counter (@ 0x27008 opcodes 8–10)",
    "0x20B1B0": "Tag base (g0<<7 @ 0x26FD8)",
    "0x20B1C0": "Per-opcode handler record pointer table (128 × 4 bytes, runtime)",
    "0x20B600": "Head of handler-template clone list (runtime, no static ROM image)",
}

DISPATCH_HELPERS = (
    {
        "rom": "0x026F10",
        "stub": "0x005C5F68",
        "effect": (
            "Bind: opcode = stream[g0*2]; handler = 0x20B1C0[opcode*4]; "
            "store g5→+0, g6→+4 (slot/width counters)"
        ),
    },
    {
        "rom": "0x026F70",
        "stub": "0x005C5FCC",
        "effect": "Restore bind: pop handler record → 0x20B1A4/A8/AC + bx thunk",
    },
    {
        "rom": "0x027160",
        "stub": "0x005C61C8",
        "effect": "Patch return stub into g0 descriptor slots walking backward",
    },
    {
        "rom": "0x0271D0",
        "stub": "0x005C6250",
        "effect": "For each non-zero template byte: patch 0x005C6250 stub, slot++",
    },
    {
        "rom": "0x027260",
        "stub": "chain",
        "effect": "Batch chain patch (palette init @ 0x012DE4; g1<<7 tag base)",
    },
)

MERGE_GLOBALS_2A2E0 = {
    "rom": "0x02A2E0",
    "inputs": "g0,g1,g2,g3 from compiled thunk (not FIFO u16 directly)",
    "outputs": {
        "0x20C95C": "merge_lo = (g0 <= 61) ? (g0 << 3) : g14 spill",
        "0x20C960": "merge_mid = (g1 <= 47) ? (g1 << 3) : g14 spill",
        "0x20C964": "merge_max2 = table[g2] if g2 <= 61 else 0x1EF",
        "0x20C968": "merge_max = table[g3] if g3 <= 47 else 0x17F",
    },
    "then": "0x02A370 loads g13 from 0x20C958; 0x02A3AC fills per-slot g13 bus table",
}

FIFO_RUNNER_2A5A0 = {
    "rom": "0x02A5A0",
    "wrapper": "0x02A6D0 — first call passes g2=orig g0; merge uses g2=r14=orig g4",
    "saved": {
        "r10": "original g0 (merge X bus coord)",
        "r9": "original g1 (merge Y bus coord)",
        "r8": "g2 loop bound (abs)",
        "r7": "g3 loop bound (abs)",
        "r14": "original g4 (16-bit value → merge g2)",
        "r5": "original g5 (bit 0 set → merge path @ 0x02A61C)",
    },
    "d_path": (
        "0x02A61C: r5 bit 0 set → 0x02A62C call 0x02A4E0 with "
        "g0=r10, g1=r9, g2=r14 (= entry g4 at 0x02A5AC). "
        "Where entry g4 is transformed from raw FIFO is not identified in static disasm."
    ),
}


def merge_oracle_search(
    *,
    slot: int,
    raw_u16: int,
    target_color15: int,
    g13_seed: int,
    g13_table: int,
) -> dict:
    """Bounded search: can ``0x02A4E0`` with ``g2=raw`` reach ``target`` on empty palram bus?"""
    raw = int(raw_u16) & 0xFFFF
    target = int(target_color15) & 0x7FFF
    xor_g13 = raw ^ (int(g13_table) & 0xFFFF)

    g2_candidates: list[tuple[str, int]] = [
        ("raw_fifo", raw),
        ("raw_xor_g13_table", xor_g13),
        ("target_color15", target),
    ]

    hits: dict[str, list[dict]] = {}
    for label, g2 in g2_candidates:
        matches: list[dict] = []
        for g13_mask in (int(g13_seed) & 0xFFFF, (int(slot) & 0x3FF) << 7):
            for g0 in range(0x200):
                for g1 in range(0x200, 0x400):
                    sim = CgmStagingSim(g13_mask=g13_mask)
                    sim.merge_lo = 0
                    sim.merge_mid = 0
                    sim.merge_max = 0x17F
                    sim.merge_max2 = 0x1EF
                    out = sim.op_2a4e0_merge(g0=g0, g1=g1, g2=g2)
                    if out is not None and (out & 0x7FFF) == target:
                        matches.append(
                            {
                                "g13_mask": f"0x{g13_mask:04x}",
                                "g0": g0,
                                "g1": g1,
                                "out": f"0x{out:04x}",
                            }
                        )
                        if len(matches) >= 8:
                            break
                if len(matches) >= 8:
                    break
            if len(matches) >= 8:
                break
        hits[label] = {
            "g2": f"0x{g2 & 0xFFFF:04x}",
            "match_count_capped": len(matches),
            "sample": matches[:8],
        }

    raw_hits = hits["raw_fifo"]["match_count_capped"]
    xor_hits = hits["raw_xor_g13_table"]["match_count_capped"]
    conclusion = (
        "Hardware D path calls 0x02A4E0 with g2=r14 (compiled flag/value word), "
        "not FIFO u16 directly. Empty palram-bus merge with g2=raw never reaches "
        f"target 0x{target:04x}; g2=(raw^g13_table) matches only when g2 already "
        "equals decoded color15 (identity merge). Tier-B oracle still requires "
        "tracing compiled thunk → r10/r9/r14 from descriptor opcode 0x20."
    )
    if raw_hits == 0 and xor_hits > 0:
        conclusion = (
            f"Empty-bus 0x02A4E0: g2=raw 0x{raw:04x} → 0 matches for target 0x{target:04x}. "
            f"g2=(raw^g13_table=0x{xor_g13 & 0xFFFF:04x}) yields identity merge only "
            "(Python sim — does not prove hardware applies XOR before merge)."
        )

    return {
        "slot": slot,
        "raw_u16": f"0x{raw:04x}",
        "target_color15": f"0x{target:04x}",
        "g13_seed": f"0x{int(g13_seed) & 0xFFFF:04x}",
        "g13_table": f"0x{int(g13_table) & 0xFFFF:04x}",
        "search": hits,
        "conclusion": conclusion,
    }


def build_report(*, slot: int = 477, raw_u16: int = 0x8843, target: int = 0x6683) -> dict:
    g13_table = 0xEEC0  # desert slot 477 from xor_table replay
    g13_seed = 0x0700

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "handler_bootstrap": HANDLER_BOOTSTRAP,
        "staging_counters": STAGING_COUNTERS,
        "dispatch_helpers": DISPATCH_HELPERS,
        "merge_globals": MERGE_GLOBALS_2A2E0,
        "fifo_runner": FIFO_RUNNER_2A5A0,
        "static_rom_gap": (
            "0x20B1C0 / 0x20B600 have zero maincpu word refs — handler records are "
            "cloned @ 0x26800 from a runtime-built list. 0x027160/0x0271D0 are only "
            "reachable via patched workram thunks (0x005C61C8 / 0x005C6250), not bal "
            "from ROM."
        ),
        "descriptor_tag_0x20": {
            "bytecode_primer": "0x05D8AC emits g0=32 (31+1) when r9 bit 5 set by digits",
            "descriptor_bus_word": "0x027008 → 0x01000000[idx] = 0x8420 (tag 0x400 | opcode 0x20)",
            "bind_stream_halfword": "Bytecode chain LE halfword @ byte0 = 0x0020 → 0x26F44 index 32",
            "closed": "0x8420 is descriptor-bus encoding; 0x26F44 indexes 0x20B1C0[0x20*4] via 0x0020",
            "zeros_template": "No 0x0271D0 stub patches — template row all zero",
        },
        "merge_oracle_search": merge_oracle_search(
            slot=slot,
            raw_u16=raw_u16,
            target_color15=target,
            g13_seed=g13_seed,
            g13_table=g13_table,
        ),
        "next_re": (
            "Simulate 0x5CF50 output record layout (+0x10/+0x14 param table) for "
            "desert slot-477 fragment; map wrapper g0/g1 bus coords from 0x02A6D0. "
            "See palette_thunk_catalog.json + palette_compiled_d_trace.json."
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CGM handler dispatch static RE report")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_handler_dispatch.json",
    )
    args = parser.parse_args()

    report = build_report(slot=args.slot, raw_u16=args.raw, target=args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    search = report["merge_oracle_search"]
    print(f"\nSlot {args.slot}: raw {search['raw_u16']} → target {search['target_color15']}")
    for label, body in search["search"].items():
        print(f"  {label}: {body['match_count_capped']} merge hits (capped)")
    print(f"\n{search['conclusion']}")


if __name__ == "__main__":
    main()
