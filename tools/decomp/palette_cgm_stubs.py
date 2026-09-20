#!/usr/bin/env python3
"""Static RE map: CGM format compile → ROM upload stubs (no MAME captures).

Traces the path from ``0x05D860`` emit through ``0x027130`` / ``0x029958`` into
the **ROM** upload cluster ``0x02A4E0``–``0x02A740`` (previously a disasm gap).

  python3 -m tools.decomp.palette_cgm_stubs
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Workram bx targets (zero in static ROM; immediates only appear in lda @ ROM sites).
WORKRAM_TRAMPOLINES = (
    {"workram": "0x005C8964", "rom_lda_sites": ["0x029954"], "role": "Post-0x5CEC0 compile entry (@ 0x029958 bx)"},
    {"workram": "0x005C612C", "rom_lda_sites": ["0x027004"], "role": "0x027008 opcode dispatcher return"},
    {"workram": "0x005C61C8", "rom_lda_sites": ["0x027164"], "role": "0x027160 staging descriptor patch"},
    {"workram": "0x005C6250", "rom_lda_sites": ["0x0271D4"], "role": "0x0271D0 template-byte emit"},
    {"workram": "0x005C9488", "rom_lda_sites": ["0x02A414"], "role": "Return stub for 0x02A410 palram pack"},
    {"workram": "0x005C94D8", "rom_lda_sites": ["0x02A494"], "role": "Return stub for 0x02A490 scratch write"},
    {"workram": "0x005C9118", "rom_lda_sites": ["0x02A0F4"], "role": "Per-chunk format read (@ 0x02A0F8 bx)"},
)

# ROM handlers in the CGM upload cluster (static code — fully disasm-able).
ROM_UPLOAD_HANDLERS = (
    {
        "rom": "0x02A200",
        "name": "batched_staging_xor",
        "when": "g3 > 0 only (@ 0x2A228 ble skips inner loop when g3==0)",
        "effect": "0x2A258: staging[word] ^= g13 (0x8040 + setbit 15); # batch path",
        "python": "op_2a200_hash_batch — not used for lone D",
    },
    {
        "rom": "0x02A410",
        "name": "palram_nibble_pack",
        "when": "Compiled thunk; g6 = 0x20C958",
        "effect": "Pack g0 into 0x01080000 palram bus with setbit-15 loop (@ 0x02A458)",
        "python": "Not modeled",
    },
    {
        "rom": "0x02A490",
        "name": "scratch_colorbase_write",
        "when": "g1 = color15; slot = 0x20C958 >> 7",
        "effect": "stos g1 → 0x01800000 + (slot<<5) (@ 0x02A4B8); flush later @ 0x26918",
        "python": "op_2a490_scratch_write",
    },
    {
        "rom": "0x02A4E0",
        "name": "palram_merge",
        "when": "Called from 0x02A62C / 0x02A694 inside upload runner",
        "effect": "Read-modify-write color15 @ 0x01080000 using 0x20C958–0x20C968 tables",
        "python": "Not modeled — merge uses existing destination bits",
    },
    {
        "rom": "0x02A5A0",
        "name": "fifo_upload_runner",
        "when": "Compiled 0x1111 thunks; outer calls @ 0x02A6E8–0x02A780",
        "effect": "FIFO u16 loop @ 0x02A5F8; branch on r14 bit 0",
        "python": "Not modeled — format-walk bypasses this entirely",
    },
    {
        "rom": "0x02A648",
        "name": "flag_word_update",
        "when": "0x02A61C: bbc 0,r5 → 0x02A630 (r5 bit 0 **clear**)",
        "effect": "Shift/or r5 flag word (@ 0x02A648–0x02A654); walk r6 list; no XOR",
        "python": "Not modeled",
    },
    {
        "rom": "0x02A61C",
        "name": "d_u_branch",
        "when": "r5 bit 0 set (D/U @ 0x05D3DC setbit 0,r9 → g4→r14→r5)",
        "effect": "call 0x02A4E0 @ 0x02A62C with g0=r10,g1=r9,g2=r14 (saved args)",
        "python": "ingest_u16 xor_table — contradicts D branch (no pre-XOR)",
    },
)

COMPILE_TO_RUN_CHAIN = (
    {"step": 1, "rom": "0x05D3DC", "effect": "D: setbit 0,r9; g6=10 → 0x05D7E8 copy template row → 0x05D860"},
    {"step": 2, "rom": "0x05D860", "effect": "bal 0x027008 per template/primer byte — descriptors @ 0x01000000"},
    {
        "step": 3,
        "rom": "0x02A01C",
        "effect": (
            "Desert static path: 0x05CE18 mismatch → 0x05CEC0 (0x005C8E90) @ 0x02A034 "
            "→ bal 0x029958 run @ 0x005C8964 — skips 0x29EF0 stream walk"
        ),
    },
    {
        "step": 4,
        "rom": "0x029F7C",
        "effect": (
            "Matched-stream path only (@ 0x29EF0 when 0x05CE18 g0==0): inner loop "
            "bal 0x02A0F8 via 0x005C9118 — not taken for desert block head vs zero template"
        ),
    },
    {
        "step": 5,
        "rom": "0x02A004",
        "effect": (
            "Overflow when 0x20C954 > 0x1FF at 0x029ED8: 0x05CEC0 (0x005C8E70) "
            "→ 0x029958 — separate from desert mismatch path"
        ),
    },
    {
        "step": 6,
        "rom": "0x012E60",
        "effect": (
            "Post-init: five 0x029C10 upload sweeps with g2=0x20A79C (alpine compile context); "
            "g0/g1/g3 vary slot window — each may 0x05CEC0 → 0x029958 when g2<0"
        ),
    },
    {
        "step": 7,
        "rom": "0x029FE4",
        "effect": (
            "Inner overflow (slot>0x1FF): if (entry_g4&7)<3 skip 0x029C10; else call 0x029C10 "
            "ADD @ 0x29CFC — separate from 0x02A034 compile path"
        ),
    },
    {"step": 8, "rom": "0x02A0F8", "effect": "ldis +0x10/+0x12; lda +0x14[g4*2]; bx (g1) — indirect handler"},
    {"step": 9, "rom": "0x02A61C", "effect": "r5 bit 0 set → 0x02A62C call 0x02A4E0 (g2=r14=entry g4)"},
    {"step": 10, "rom": "0x02A120", "effect": "Record end: scratch flush → 0x26918 palram commit"},
)


def build_stub_report() -> dict:
    return {
        "compile_to_run": COMPILE_TO_RUN_CHAIN,
        "workram_trampolines": WORKRAM_TRAMPOLINES,
        "rom_upload_handlers": ROM_UPLOAD_HANDLERS,
        "d_decode_conclusion": {
            "proven": (
                "Desert 0x029EB0: 0x05CE18 mismatch → 0x02A01C → 0x05CEC0 → 0x029958 (@ 0x005C8964). "
                "0x029F7C → 0x02A0F8 is matched-stream only (0x29EF0). D/U set r9 bit 0 @ 0x05D3DC "
                "→ 0x02A61C merge when r5 bit 0 set. 0x02A258 XOR only when g3>0 (# batch)."
            ),
            "python_gap": (
                "Python format-walk applies xor_table then scratch write, skipping "
                "0x02A4E0 merge. xor_table matches desert geometry (oracle only); "
                "hardware FIFO→g4 transform for lone D not identified in static disasm."
            ),
            "next_static_re": (
                "Map 0x5CF50 compiled record +0x10/+0x14 fields → wrapper g0/g1 bus "
                "coords; simulate 0x26800 handler clone for opcode 0x20."
            ),
        },
        "disasm_slices_added": [
            "maincpu/maincpu_02a5a0_2b0.asm (0x02A5A0–0x02A850 upload runner + dispatch)",
            "maincpu/maincpu_0271d0_100.asm (0x027160–0x027260 stub patch helpers)",
            "maincpu/maincpu_027008_200.asm (0x027130 walk + 0x027160/0x0271D0 cluster)",
        ],
    }


def main() -> None:
    out = REPO_ROOT / "out/decomp/palette_cgm_stubs.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_stub_report()
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    print("\nROM upload handlers:")
    for h in ROM_UPLOAD_HANDLERS:
        print(f"  {h['rom']} {h['name']}: {h['when']}")
    con = report["d_decode_conclusion"]
    print("\nD decode (static RE):")
    print(f"  {con['proven']}")
    print(f"  Gap: {con['python_gap']}")


if __name__ == "__main__":
    main()
