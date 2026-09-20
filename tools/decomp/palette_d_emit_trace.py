#!/usr/bin/env python3
"""Static trace: desert format ``D`` → ``0x05D860`` bytecode → upload stub chain.

Correlates ``0x1111`` replay (chunk/bin_pos) with disasm-backed ``0x027008`` emit
simulation.  Template rows @ ``0x005FBF10`` are zero in static ROM; this tool
compares candidate row tables and records bytecode shape — no MAME captures.

  python3 -m tools.decomp.palette_d_emit_trace
  python3 -m tools.decomp.palette_d_emit_trace --slot 477
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.model2_cgm_1111 import (
    CGM_RECORD_1111,
    _is_format_chunk,
    _split_inner_chunks,
    replay_1111_record,
)
from tools.decomp.palette_handler_dispatch import merge_oracle_search
from tools.model2_cgm_bytecode import bind_and_run
from tools.model2_cgm_emit import (
    D_TEMPLATE_G6,
    compile_d_emit,
    compile_format_fragment,
    decode_bytecode_stream,
)
from tools.model2_palette import (
    COURSE_CGM_VADDRS,
    PaletteState,
    find_cgm_blocks,
    load_palette_from_main_data,
    _iter_cgm_v16_records,
)
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, resolve_rom_dir

REPO_ROOT = Path(__file__).resolve().parents[2]

# Candidate template tables (10 rows × g6=10 bytes).  Row index = repeat % 10 @ 0x05D808.
TEMPLATE_CANDIDATES: dict[str, list[bytes]] = {
    "zeros": [bytes(D_TEMPLATE_G6) for _ in range(10)],
    "digit_row0": [b"0123456789", b"abcdef%"] + [bytes(D_TEMPLATE_G6) for _ in range(8)],
    "desc_32_41": [bytes(range(32, 32 + D_TEMPLATE_G6)) for _ in range(10)],
    "width48_prefix": [
        bytes([48] + [0] * (D_TEMPLATE_G6 - 1)),
        bytes([48, 32] + [0] * (D_TEMPLATE_G6 - 2)),
    ]
    + [bytes(D_TEMPLATE_G6) for _ in range(8)],
}


def _desert_1111_payload(main_data: bytes) -> bytes:
    block = {b.vaddr: b for b in find_cgm_blocks(main_data)}[COURSE_CGM_VADDRS[1]]
    for rec_type, rec_len, off in _iter_cgm_v16_records(main_data, block):
        if rec_type == CGM_RECORD_1111:
            return main_data[off : off + rec_len]
    raise SystemExit("desert 0x1111 record not found")


def _desert_format_fragments(payload: bytes) -> list[str]:
    return [
        c.decode("latin1", errors="replace")
        for c in _split_inner_chunks(payload)
        if c and _is_format_chunk(c)
    ]


def _replay_slot_trace(main_data: bytes, slot: int) -> list[dict]:
    state = PaletteState()
    state._install_default_lumaram()
    from tools.model2_palette import load_colorxlat_from_main_data

    load_colorxlat_from_main_data(state, main_data)
    payload = _desert_1111_payload(main_data)
    replay = replay_1111_record(state, payload, trace_slots=frozenset({slot}))
    return list(replay.trace)


def _compile_desert_d_events(fragments: list[str]) -> dict:
    by_template: dict[str, list[dict]] = {}
    unique_bytecode: dict[str, dict] = {}

    for name, rows in TEMPLATE_CANDIDATES.items():
        frag_events: list[dict] = []
        for frag in fragments:
            if "D" not in frag and "d" not in frag:
                continue
            events = compile_format_fragment(frag, template_rows=rows)
            d_events = [e for e in events if e.get("op") == "D"]
            if not d_events:
                continue
            frag_events.append({"fragment": frag, "d_events": d_events})
            for ev in d_events:
                key = " ".join(ev.get("bytecode") or [])
                if key and key not in unique_bytecode:
                    unique_bytecode[key] = {
                        "template": name,
                        "fragment": frag[:80],
                        "repeat": ev.get("repeat"),
                        "bytecode": ev.get("bytecode"),
                        "decoded": ev.get("bytecode_decoded"),
                    }
        by_template[name] = frag_events

    return {"by_template": by_template, "unique_bytecode_signatures": unique_bytecode}


def _tier_b_vectors(trace_rows: list[dict], *, slot: int) -> list[dict]:
    vectors: list[dict] = []
    for row in trace_rows:
        raw = int(row["raw"], 16)
        vectors.append(
            {
                "slot": slot,
                "chunk": row.get("chunk"),
                "format_frag": row.get("format_frag"),
                "bin_pos": row.get("bin_pos"),
                "raw_u16": row["raw"],
                "python_xor_color15": row["color15"],
                "g13_table": row["g13"],
                "disasm_path": (
                    "0x029F7C → 0x02A0F8 (slot<=0x1FF) → 0x02A62C 0x02A4E0 when r5 bit0"
                ),
                "oracle_status": (
                    "python xor_table matches geometry; hardware 0x1111 D decode "
                    "unproven; merge g0/g1 bus coords open"
                ),
            }
        )
    return vectors


def build_report(*, focus_slot: int = 477) -> dict:
    rom_dir = resolve_rom_dir(None)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    payload = _desert_1111_payload(main_data)
    fragments = _desert_format_fragments(payload)
    trace_rows = _replay_slot_trace(main_data, focus_slot)

    # Minimal D-only baselines (repeat=1 / repeat=3).
    baseline_emits = {
        "D_repeat1_zeros": compile_d_emit(repeat=1, template_rows=TEMPLATE_CANDIDATES["zeros"]),
        "D_repeat3_zeros": compile_d_emit(repeat=3, template_rows=TEMPLATE_CANDIDATES["zeros"]),
        "D_repeat1_desc32": compile_d_emit(
            repeat=1, template_rows=TEMPLATE_CANDIDATES["desc_32_41"]
        ),
    }
    baselines = {
        key: {
            "bytecode": [f"0x{b:02x}" for b in sim.bytecode],
            "decoded": decode_bytecode_stream(sim.bytecode),
            "descriptors": len(sim.descriptors),
        }
        for key, sim in baseline_emits.items()
    }

    frag_for_slot = trace_rows[0].get("format_frag") if trace_rows else None
    slot_compile = (
        compile_format_fragment(frag_for_slot, template_rows=TEMPLATE_CANDIDATES["zeros"])
        if frag_for_slot
        else []
    )

    bind_reports: dict[str, dict] = {}
    for label, rows in TEMPLATE_CANDIDATES.items():
        sim = compile_d_emit(repeat=1, template_rows=rows)
        row = rows[1 % len(rows)] if rows else bytes(D_TEMPLATE_G6)
        bound = bind_and_run(sim.bytecode, template_row=row)
        bind_reports[label] = {
            "bytecode_len": len(sim.bytecode),
            "bytecode_head": [f"0x{b:02x}" for b in sim.bytecode[:16]],
            "descriptors_after_walk": {
                str(k): f"0x{v:04x}" for k, v in sorted(bound.descriptors.items())[:12]
            },
            "stub_patches": bound.stub_patches[:16],
            "upload_chain_hint": bound.infer_upload_chain(),
            "final_counters": {
                "slot": bound.counters.slot,
                "width": bound.counters.width,
            },
        }

    slot477_bind: dict | None = None
    if frag_for_slot:
        d_events = [e for e in slot_compile if e.get("op") == "D"]
        if d_events:
            last_d = d_events[-1]
            bc = [int(x, 16) for x in last_d.get("bytecode", [])]
            bound = bind_and_run(bc)
            slot477_bind = {
                "fragment": frag_for_slot,
                "d_event_repeat": last_d.get("repeat"),
                "bytecode_len": len(bc),
                "stub_patches": bound.stub_patches,
                "descriptors": {str(k): f"0x{v:04x}" for k, v in bound.descriptors.items()},
                "upload_chain_hint": bound.infer_upload_chain(),
            }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "focus_slot": focus_slot,
        "replay_trace": trace_rows,
        "slot_format_compile_zeros": slot_compile,
        "desert_format_fragment_count": len(fragments),
        "template_candidates": list(TEMPLATE_CANDIDATES.keys()),
        "compile_survey": _compile_desert_d_events(fragments),
        "baseline_emits": baselines,
        "bytecode_bind": bind_reports,
        "slot477_last_d_bind": slot477_bind,
        "stub_patch_rom": {
            "0x027160": "patch 0x005C61C8 return stub into staging0 descriptor @ (width<<6)+slot",
            "0x0271D0": "read template bytes; patch 0x005C6250 stub per byte; inc slot",
            "0x027260": "batch chain patch (palette init @ 0x012DE4)",
            "0x026F10": "bind slot/width into 0x20B1C0[opcode] handler records (skipped @ 0x02A038?)",
        },
        "merge_arg_gap": (
            "0x02A62C passes g0=r10,g1=r9,g2=r14 saved @ 0x02A5A0 entry. "
            "0x005FBF10 template row bytes select which 0x20B1C0 handlers run @ 0x029958; "
            "zeros row → only 0x20 primers + noop 0x00 (no 27160 patch). "
            "Need non-zero template row from 0x02A2C4 compile side-effect or boot init."
        ),
        "tier_b_vectors": _tier_b_vectors(trace_rows, slot=focus_slot),
        "merge_oracle_search": (
            merge_oracle_search(
                slot=focus_slot,
                raw_u16=int(trace_rows[0]["raw"], 16) if trace_rows else 0x8843,
                target_color15=int(trace_rows[0]["color15"], 16) if trace_rows else 0x6683,
                g13_seed=int(trace_rows[0]["g13_seed"], 16) if trace_rows else 0x0700,
                g13_table=int(trace_rows[0]["g13"], 16) if trace_rows else 0xEEC0,
            )
            if trace_rows
            else None
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="D emit bytecode trace for desert 0x1111")
    parser.add_argument("--slot", type=int, default=477)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "out/decomp/palette_d_emit_trace.json",
    )
    args = parser.parse_args()

    report = build_report(focus_slot=args.slot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    if report["replay_trace"]:
        row = report["replay_trace"][0]
        print(
            f"\nSlot {args.slot}: chunk={row.get('chunk')} bin_pos={row.get('bin_pos')} "
            f"raw={row.get('raw')} python={row.get('color15')}"
        )
        frag = row.get("format_frag") or ""
        print(f"  format_frag: {frag[:72]}{'…' if len(frag) > 72 else ''}")

    sigs = report["compile_survey"]["unique_bytecode_signatures"]
    print(f"\nUnique D bytecode signatures (all templates): {len(sigs)}")
    for i, (key, body) in enumerate(list(sigs.items())[:5]):
        bc = body.get("bytecode") or []
        print(f"  [{body['template']}] repeat={body.get('repeat')} len={len(bc)} {bc[:12]}")

    baselines = report["baseline_emits"]
    print("\nBaseline emit (zeros template row):")
    for name, body in baselines.items():
        bc = body["bytecode"]
        print(f"  {name}: {len(bc)} bytes  first={bc[:8]}")

    bind = report.get("slot477_last_d_bind")
    if bind:
        print(f"\nSlot {args.slot} last-D bytecode bind (zeros template):")
        print(f"  bytecode_len={bind.get('bytecode_len')} repeat={bind.get('d_event_repeat')}")
        desc = bind.get("descriptors") or {}
        print(f"  descriptors: {desc}")
        patches = bind.get("stub_patches") or []
        print(f"  stub_patches: {len(patches)}")
        for p in patches[:4]:
            print(f"    {p.get('rom')} idx={p.get('desc_idx')} byte={p.get('template_byte', p.get('count'))}")

    bc_bind = report.get("bytecode_bind") or {}
    desc_row = bc_bind.get("desc_32_41") or {}
    if desc_row.get("stub_patches"):
        print("\ndesc_32_41 template stub patches (first 4):")
        for p in desc_row["stub_patches"][:4]:
            print(f"  {p.get('template_byte')} @ desc_idx={p.get('desc_idx')}")


if __name__ == "__main__":
    main()
