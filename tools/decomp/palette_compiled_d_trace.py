#!/usr/bin/env python3
"""Python ``xor_table`` arithmetic check for tier-B slot(s) + merge sim notes.

Static simulation only: verifies ``raw ^ g13_table → color15`` under Python replay.
Does **not** prove hardware decode — see ``palette_disasm_provenance``.

  python3 -m tools.decomp.palette_compiled_d_trace --slot 477 --raw 0x8843
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.model2_cgm_g13_table import g13_mask_for_slot
from tools.model2_cgm_staging import CgmStagingSim

REPO_ROOT = Path(__file__).resolve().parents[2]


def trace_d_slot(
    *,
    slot: int,
    raw_u16: int,
    g13_seed: int,
    target_color15: int | None = None,
) -> dict:
    raw = int(raw_u16) & 0xFFFF
    seed = int(g13_seed) & 0xFFFF
    mask = g13_mask_for_slot(seed, slot) & 0xFFFF
    decoded = (raw ^ mask) & 0x7FFF

    sim = CgmStagingSim(stream_cursor=slot, g13_mask=seed)
    sim.setup_merge_globals(g0_idx=0, g1_idx=0)

    merge_samples: list[dict] = []
    for g0 in (0, 3, slot & 0x3F):
        for g1 in (0x17F, 0x180, 0x200):
            out = sim.op_2a4e0_merge(g0=g0, g1=g1, g2=decoded)
            if out is not None:
                merge_samples.append(
                    {
                        "g0": g0,
                        "g1": g1,
                        "g2": f"0x{decoded:04x}",
                        "out": f"0x{out & 0x7FFF:04x}",
                        "identity": (out & 0x7FFF) == decoded,
                    }
                )
                if len(merge_samples) >= 6:
                    break
        if len(merge_samples) >= 6:
            break

    target = target_color15 if target_color15 is not None else decoded
    target &= 0x7FFF

    return {
        "slot": slot,
        "raw_u16": f"0x{raw:04x}",
        "g13_seed": f"0x{seed:04x}",
        "g13_table": f"0x{mask:04x}",
        "decoded_xor": f"0x{decoded:04x}",
        "target_color15": f"0x{target:04x}",
        "xor_matches_target": decoded == target,
        "disasm_path_proven": [
            "Desert static: 0x05CE18 mismatch → 0x02A01C → 0x05CEC0 → 0x029958 (@ 0x005C8964)",
            "0x029F7C → 0x02A0F8 is matched-stream only (0x29EF0 when gate g0==0) — not desert",
            "0x02A62C: g2=r14=entry g4 when r5 bit 0 set (inside upload runner, not 29F7C path)",
        ],
        "python_xor_replay": f"raw ^ g13_table = 0x{decoded:04x}",
        "merge_identity_samples": merge_samples,
        "conclusion": (
            f"Python xor_table: 0x{raw:04x} ^ 0x{mask:04x} = 0x{decoded:04x} "
            f"(target 0x{target:04x}). Hardware D decode for 0x1111 not proven in disasm. "
            "Open: compiled thunk body, wrapper g0/g1 bus coords."
            if decoded == target
            else "Python xor_table does not match target — check g13_seed/slot window."
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Compiled D path trace")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument("--raw", type=lambda s: int(s, 0), default=0x8843)
    parser.add_argument("--g13-seed", type=lambda s: int(s, 0), default=0x0700)
    parser.add_argument("--target", type=lambda s: int(s, 0), default=0x6683)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_compiled_d_trace.json",
    )
    args = parser.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trace": trace_d_slot(
            slot=args.slot,
            raw_u16=args.raw,
            g13_seed=args.g13_seed,
            target_color15=args.target,
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    t = report["trace"]
    print(
        f"\nSlot {args.slot}: raw {t['raw_u16']} ^ {t['g13_table']} "
        f"= {t['decoded_xor']} (target {t['target_color15']})"
    )
    print(f"  {t['conclusion']}")


if __name__ == "__main__":
    main()
