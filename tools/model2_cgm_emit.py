"""Disasm-backed trace of CGM format ``D`` → ``0x05D860`` thunk emission.

The format compiler ``0x05CF50`` does not call ``0x02A258`` directly.  Each ``D``
sets ``r9`` bit 0 and branches to ``0x05D860``, which emits bytecode via repeated
``bal 0x027008`` calls.  That bytecode is later walked by ``0x027130`` and
executed through workram trampolines @ ``0x005C8964`` (``bx`` @ ``0x029958``).

Python ``0x1111`` replay in ``tools/model2_cgm_1111`` skips this pipeline and
applies ``0x02A258``-style XOR on ``staging0`` directly — the top RE gap for hue
validation.

Sources: ``decomp/disasm/maincpu/maincpu_05cf50_a00.asm``,
``maincpu_05d860_200.asm``, ``maincpu_027008_200.asm``, ``maincpu_029900_300.asm``,
``maincpu_029c10_800.asm``, ``maincpu_029eb0_600.asm``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# --- ``0x05D3DC`` (char ``D``) ------------------------------------------------

D_HANDLER = 0x05D3DC
D_EMIT = 0x05D860
D_TEMPLATE_PREP = 0x05D7E8
EMIT_ENGINE = 0x027008
THUNK_WALK = 0x027130
THUNK_RUN = 0x029958
THUNK_ENTRY = 0x005C8964
RECORD_UPLOAD = 0x029C10

# ``g6=10`` @ ``0x05D440`` — template row width for ``D`` / ``U`` (@ ``0x05D808`` div/rem).
D_TEMPLATE_G6 = 10

# ``r13 = 31+14 = 45 (0x2D)`` when linked struct field @ ``-4(r5)[g4]`` > 0.
D_R13_WITH_PARAM = 45

# Workram-only template bases (static ROM read @ these addrs is zero).
TEMPLATE_BASES = (
    0x005FBF10,  # default row table (@ ``0x05D828``)
    0x005FBF22,  # ``%`` handler
    0x005FBF28,  # alternate handler cluster
    0x005FBF30,  # alternate handler cluster
)

# Repeat / width counters written by ``0x027008``.
COUNTER_SLOT = 0x0020B1A8
COUNTER_WIDTH = 0x0020B1AC
COUNTER_TAG = 0x0020B1B0

# Staging descriptor table filled when ``(g0 & 0xFF) > 31`` (@ ``0x0270CC``).
STAGING0_DESC = 0x01000000
STAGING1_DESC = 0x01004000


@dataclass
class EmitCounters:
    """``0x20B1A8`` / ``0x20B1AC`` / ``0x20B1B0`` stand-in."""

    slot: int = 0
    width: int = 0
    tag: int = 0


@dataclass
class Emit27008Log:
    op: str
    g0: int
    detail: str = ""


@dataclass
class DEmitSim:
    """Minimal ``0x05D860`` + ``0x027008`` logger (no workram template bytes)."""

    counters: EmitCounters = field(default_factory=EmitCounters)
    descriptors: dict[int, int] = field(default_factory=dict)
    log: list[Emit27008Log] = field(default_factory=list)
    bytecode: list[int] = field(default_factory=list)
    _desc_write_idx: int = 0

    def op_27008(self, g0: int) -> None:
        """Dispatch ``0x027008`` on one ``g0`` argument (@ ``0x05D8AC`` etc.)."""
        self.bytecode.append(g0 & 0xFF)
        low = g0 & 0xFF
        if low > 31:
            word = 0xFFFF8000 | ((g0 >> 24) & 0xFF) | (self.counters.tag & 0xFF)
            idx = (self.counters.width << 6) + self.counters.slot
            self.descriptors[idx] = word & 0xFFFF
            self._desc_write_idx = idx
            self.log.append(
                Emit27008Log("desc_write", g0, f"staging0[{idx}] = 0x{word & 0xFFFF:04x}")
            )
            self.counters.slot += 1
            return
        if low == 8:
            self.counters.slot = max(0, self.counters.slot - 1)
            self.log.append(Emit27008Log("slot_dec", g0, f"slot={self.counters.slot}"))
            return
        if low == 9:
            self.counters.width = g0 & 0xFF
            self.log.append(Emit27008Log("width_set", g0, f"width={self.counters.width}"))
            return
        if low == 10:
            self.counters.slot, self.counters.width = self.counters.width, self.counters.slot
            self.log.append(
                Emit27008Log(
                    "swap",
                    g0,
                    f"slot={self.counters.slot} width={self.counters.width}",
                )
            )
            return
        self.log.append(Emit27008Log("noop", g0, f"low={low}"))

    def emit_repeat_loop(self, count: int, *, g0: int = 32) -> None:
        """``0x05D8AC``–``0x05D8C0``: ``g0=31+1`` repeat counter priming."""
        for _ in range(max(0, count)):
            self.op_27008(g0)

    def emit_width_loop(self, count: int, *, g0: int = 48) -> None:
        """``0x05D8D8`` / ``0x05D908`` / ``0x05D92C``: ``g0=31+17`` width digits."""
        for _ in range(max(0, count)):
            self.op_27008(g0)

    def emit_template_bytes(self, template: bytes) -> None:
        """``0x05D94C``–``0x05D966``: each template byte → ``bal 0x027008``."""
        for byte in template:
            self.op_27008(byte)

    def simulate_d_emit(
        self,
        *,
        r9: int,
        r13: int,
        r8: int,
        r7: int,
        r3: int,
        r14: int,
        r10: int,
        template_row: bytes,
    ) -> None:
        """Replay ``0x05D860`` control flow (``0x05D864``–``0x05D9C0``)."""
        g11 = 48  # ``31+17`` @ ``0x05D890``

        # ``0x05D86C``–``0x05D87C``: derive ``r7`` from ``r8`` / ``r15`` / ``r9`` bit 6.
        if r13 & 0xFF:
            r7 = r7 + 1
        if r9 & 0x40:
            r7 = r7 + 2
        r10 = r3 if r3 >= r7 else r7

        # ``0x05D898``–``0x05D8C0``: ``(r9 & 0x30)`` digit-repeat priming.
        if (r9 & g11) and r14 > 0 and r10 < r14:
            self.emit_repeat_loop(r14 - r10)

        # ``0x05D8C4``–``0x05D8D0``: ``r13 & 0xFF`` slot priming.
        if r13 & 0xFF:
            self.emit_repeat_loop(r13 & 0xFF)

        # ``0x05D8D4``–``0x05D8EC``: ``r9`` bit 6 width path.
        if r9 & 0x40:
            self.op_27008(48)
            self.emit_template_bytes(template_row[:1])
            self.op_27008(template_row[0] if template_row else 0)

        # ``0x05D8F0``–``0x05D920``: ``(r9 & 0x30) == 1`` variant width loop.
        if (r9 & g11) == 1 and r14 > 0 and r10 < r14:
            self.emit_width_loop(r14 - r10)

        # ``0x05D920``–``0x05D944``: ``r7`` vs ``r3`` width loop.
        if r3 < r7:
            self.emit_width_loop(r7 - r3)

        # ``0x05D944``–``0x05D966``: copy ``r8`` template bytes from ``(r6)``.
        if r8 > 0 and template_row:
            self.emit_template_bytes(template_row[:r8])

        # ``0x05D988``–``0x05D9B0``: ``r9`` bit 4 cleanup repeat.
        if r9 & 0x10 and r14 > 0 and r10 < r14:
            self.emit_repeat_loop(r14 - r10)


def d_handler_flow() -> list[dict[str, str]]:
    """Static call graph from ``0x05D3DC`` through runtime upload."""
    return [
        {
            "step": "1",
            "rom": "0x05D3DC",
            "effect": "setbit 0,r9 (u16 upload flag); load linked struct; r13=45 if field@(-4)>0",
        },
        {
            "step": "2",
            "rom": "0x05D440",
            "effect": f"g6={D_TEMPLATE_G6}; branch 0x05D7E8",
        },
        {
            "step": "3",
            "rom": "0x05D7E8",
            "effect": "copy template row from 0x005FBF10[g6] into stack buffer (10-byte rows)",
        },
        {
            "step": "4",
            "rom": "0x05D824",
            "effect": "if r9 bit 3 (# pending): prefix template byte 48 ('0') when g6==8",
        },
        {
            "step": "5",
            "rom": "0x05D860",
            "effect": "emit bal 0x027008 opcodes (repeat/width/descriptor writes + template bytes)",
        },
        {
            "step": "6",
            "rom": "0x027130",
            "effect": "walk emitted bytecode; each byte → bal 0x027008; patch trampolines @ 0x027160",
        },
        {
            "step": "7",
            "rom": "0x029958",
            "effect": f"bx workram entry @ 0x{THUNK_ENTRY:08X} (return stub in g14)",
        },
        {
            "step": "8",
            "rom": "0x02A0F8",
            "effect": "per inner 0x1111 chunk: bx 0x005C9118 thunks consume binary FIFO",
        },
        {
            "step": "9",
            "rom": "0x029FF8",
            "effect": "call 0x029C10 with g2=r7 (group), g3=r14, g4=r11 (descriptor flags)",
        },
    ]


def runtime_upload_paths() -> list[dict[str, object]]:
    """How ``0x029C10`` / ``0x02A200`` interpret ``g4`` (``r11``) flag bits."""
    return [
        {
            "id": "29c74_staging1_add",
            "rom": "0x29C74",
            "when": "g4 bit 0 set (D/U handler setbit 0,r9)",
            "staging": "0x01004000",
            "g13_init": "0 (no setbit 15)",
            "math": "0x29CD8: g13 |= chain.head_u16; 0x29CFC: word = param + g13",
            "python_gap": "ingest_u16 XORs staging0 — wrong bank and ADD vs XOR",
        },
        {
            "id": "29c90_staging0_xor",
            "rom": "0x29C90",
            "when": "g4 bit 0 clear",
            "staging": "0x01000000",
            "g13_init": "setbit 15 → XOR path",
            "math": "0x29CD8 + inner loop; 0x29E48 sub for alternate batch",
            "python_gap": "Partially modeled via op_2a258_xor_staging on staging0",
        },
        {
            "id": "2a200_hash_batch",
            "rom": "0x2A200",
            "when": "g3>0 (# batch after digits); g4 bit 0 selects bank",
            "staging": "0x01004000 if bit0 else 0x01000000",
            "g13_init": "setbit 6+15 → 0x8040 XOR mask",
            "math": "0x2A258 xor loop over staging rows",
            "python_gap": "op_2a200_hash_batch uses seed|0x8040; inner loop uses fixed 0x8040",
        },
        {
            "id": "2a3ac_table_fill",
            "rom": "0x2A3AC",
            "when": "0x2A290 batch compile via 0x005C9280 → 0x05CEC0",
            "staging": "reads both banks → fills 0x8000[slot<<6] bus table",
            "math": "Per-slot g13 mask for later XOR lookups",
            "python_gap": "g13_mask_for_slot infers masks; table not in static ROM",
        },
    ]


def r9_bit_map() -> dict[str, dict[str, object]]:
    """``r9`` bits accumulated by format handlers before ``0x05D860``."""
    return {
        "bit0": {
            "set_by": "D, U",
            "rom": "0x05D3DC / 0x05D714",
            "runtime": "g4 bit 0 @ 0x29C74 → staging1 @ 0x01004000",
        },
        "bit3": {
            "set_by": "#",
            "rom": "0x05D1C8",
            "runtime": "0x05D824 template prefix; 0x29CB4 setbit 14 g13 when g4 bit 3",
        },
        "bit4": {
            "set_by": "digit repeat side-effects",
            "rom": "0x05D988 cleanup path",
            "runtime": "extra 0x27008 repeat priming after template copy",
        },
        "bit5": {
            "set_by": "0-9",
            "rom": "0x05D304",
            "runtime": "repeat count via 0x27008 g0=48 (31+17) loops",
        },
        "bit6": {
            "set_by": "# when linked count field == 0",
            "rom": "0x05D7E0",
            "runtime": "0x05D878 adds +2 to r7; width emit @ 0x05D8D8",
        },
    }


def decode_27008_byte(byte: int, counters: EmitCounters | None = None) -> dict:
    """Classify one ``0x027008`` / ``0x027130`` walk byte."""
    low = byte & 0xFF
    if low > 31:
        tag = low
        return {
            "kind": "desc_emit",
            "byte": low,
            "note": f"descriptor tag 0x{tag:02x} → staging0 @ 0x01000000",
        }
    if low == 8:
        return {"kind": "slot_dec", "byte": low, "note": "0x20B1A8 slot counter -= 1"}
    if low == 9:
        return {"kind": "width_set", "byte": low, "note": f"0x20B1AC width = {low}"}
    if low == 10:
        return {"kind": "swap", "byte": low, "note": "swap slot/width @ 0x20B1A8/AC"}
    if low == 0:
        return {"kind": "noop", "byte": low, "note": "no-op return @ 0x027028"}
    return {"kind": "control", "byte": low, "note": f"low opcode {low}"}


def decode_bytecode_stream(bytecode: list[int]) -> list[dict]:
    """Decode emitted ``0x027008`` bytecode (``g0`` bytes from ``0x05D860``)."""
    counters = EmitCounters()
    out: list[dict] = []
    for byte in bytecode:
        row = decode_27008_byte(byte, counters)
        row["byte_hex"] = f"0x{byte & 0xFF:02x}"
        out.append(row)
        low = byte & 0xFF
        if low == 8:
            counters.slot = max(0, counters.slot - 1)
        elif low == 9:
            counters.width = low
        elif low == 10:
            counters.slot, counters.width = counters.width, counters.slot
        elif low > 31:
            counters.slot += 1
    return out


def template_row_index(repeat: int, *, g6: int = D_TEMPLATE_G6) -> int:
    """``0x05D808`` remo/div row pick: ``repeat % g6`` when ``repeat > 0``."""
    if repeat <= 0:
        return 0
    return int(repeat) % g6


def compile_d_emit(
    *,
    repeat: int = 1,
    r9_extra: int = 0,
    r13: int = 0,
    template_rows: list[bytes] | None = None,
    with_param: bool = False,
) -> DEmitSim:
    """Simulate one ``D`` handler emit (@ ``0x05D3DC`` → ``0x05D860``)."""
    rows = template_rows or [bytes(D_TEMPLATE_G6) for _ in range(10)]
    row_idx = template_row_index(repeat)
    row = rows[row_idx] if row_idx < len(rows) else bytes(D_TEMPLATE_G6)
    if len(row) < D_TEMPLATE_G6:
        row = row + bytes(D_TEMPLATE_G6 - len(row))

    r9 = 0x01 | r9_extra
    if repeat > 1:
        r9 |= 0x20  # setbit 5 from prior digit handlers
    sim = DEmitSim()
    sim.simulate_d_emit(
        r9=r9,
        r13=D_R13_WITH_PARAM if with_param else r13,
        r8=D_TEMPLATE_G6,
        r7=0,
        r3=0,
        r14=max(0, repeat),
        r10=0,
        template_row=row,
    )
    return sim


def compile_format_fragment(
    text: str,
    *,
    template_rows: list[bytes] | None = None,
) -> list[dict]:
    """Compile desert-style format fragments into ``D``/``U`` emit bytecode (static)."""
    events: list[dict] = []
    repeat = 1
    r9_accum = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char.isdigit():
            value = 0
            while index < len(text) and text[index].isdigit():
                value = value * 10 + int(text[index])
                index += 1
            repeat = max(1, min(value, 512))
            r9_accum |= 0x20
            continue
        if char == "#":
            r9_accum |= 0x08
            events.append({"op": "#", "repeat": repeat, "r9": r9_accum})
            index += 1
            continue
        if char in "Dd":
            sim = compile_d_emit(
                repeat=repeat,
                r9_extra=r9_accum & ~0x01,
                template_rows=template_rows,
            )
            events.append(
                {
                    "op": "D",
                    "repeat": repeat,
                    "r9": r9_accum | 0x01,
                    "template_row": template_row_index(repeat),
                    "bytecode": [f"0x{b:02x}" for b in sim.bytecode],
                    "bytecode_decoded": decode_bytecode_stream(sim.bytecode),
                    "descriptor_count": len(sim.descriptors),
                    "emit_ops": [{"op": e.op, "g0": e.g0} for e in sim.log[:24]],
                }
            )
            repeat = 1
            index += 1
            continue
        if char in "Uu":
            sim = compile_d_emit(repeat=repeat, r9_extra=r9_accum & ~0x01, template_rows=template_rows)
            events.append({"op": "U", "repeat": repeat, "bytecode_len": len(sim.bytecode)})
            repeat = 1
            index += 1
            continue
        repeat = 1
        index += 1
    return events


def build_emit_report(*, template_row: bytes | None = None) -> dict:
    """JSON report for ``out/decomp/cgm_d_emit.json``."""
    sim = DEmitSim()
    row = template_row or bytes([60, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # placeholder row
    sim.simulate_d_emit(
        r9=0x01,
        r13=D_R13_WITH_PARAM,
        r8=len(row),
        r7=0,
        r3=0,
        r14=0,
        r10=0,
        template_row=row,
    )
    return {
        "d_handler": f"0x{D_HANDLER:06X}",
        "emit_engine": f"0x{EMIT_ENGINE:06X}",
        "template_g6": D_TEMPLATE_G6,
        "template_bases": [f"0x{a:08X}" for a in TEMPLATE_BASES],
        "template_note": (
            "Row bytes @ 0x005FBF10 are runtime-filled (static ROM reads zero). "
            "Placeholder row used in simulation unless --template-hex supplied."
        ),
        "flow": d_handler_flow(),
        "runtime_upload_paths": runtime_upload_paths(),
        "r9_bits": r9_bit_map(),
        "python_replay_gap": (
            "tools/model2_cgm_1111._execute_format_chunk calls ingest_u16 via "
            "decode_d_u16 (default xor_table). Hardware single-D does not use 0x2A258 "
            "(that XOR loop requires g3>0, # batch). Compare modes: "
            "python3 -m tools.decomp.palette_d_path_compare"
        ),
        "simulated_emit_log": [
            {"op": e.op, "g0": e.g0, "detail": e.detail} for e in sim.log
        ],
        "simulated_bytecode": [f"0x{b:02x}" for b in sim.bytecode],
        "simulated_descriptor_count": len(sim.descriptors),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CGM D-handler emit trace (disasm-backed)")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("out/decomp/cgm_d_emit.json"),
    )
    parser.add_argument(
        "--template-hex",
        default=None,
        help="10-byte template row for g6=10 (hex, no spaces)",
    )
    args = parser.parse_args()

    row = None
    if args.template_hex:
        row = bytes.fromhex(args.template_hex)
        if len(row) != D_TEMPLATE_G6:
            raise SystemExit(f"template row must be {D_TEMPLATE_G6} bytes, got {len(row)}")

    report = build_emit_report(template_row=row)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    print(f"D handler 0x{D_HANDLER:06X} → emit 0x{D_EMIT:06X} → walk 0x{THUNK_WALK:06X}")
    print(f"Simulated {report['simulated_descriptor_count']} staging descriptors")
    for path in runtime_upload_paths():
        print(f"  {path['id']}: {path['when']}")


if __name__ == "__main__":
    main()
