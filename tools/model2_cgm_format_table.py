"""CGM format-string jump table @ ``0x05CF50`` / ``0x05FBFD0``.

The format compiler in ``maincpu_05cf50_a00.asm`` dispatches each ASCII
format character through a 121-entry pointer table (indices ``0``–``0x78``):

  ``0x05CFC4``: ``ld 0x5fbfd0[g4*4], g4``  — runtime mirror (workram)
  ``0x05CFD0``: embedded ROM image of the same pointer table

Each pointer targets a tiny handler in the ``0x05D000``–``0x05D800`` cluster
(runtime alias ``0x05FC000``–``0x05FA800``, delta ``+0x2A000``).  Handlers set
flags in ``r9`` and/or branch to the thunk emitter ``0x05D860``, which calls
``0x027008`` (repeat / width counters @ ``0x20B1A8``) and copies template bytes
from ``0x05FBF10`` / ``0x05FBF22`` / ``0x05FBF28`` / ``0x05FBF30``.

This module reads the ROM-embedded table and maps desert ``0x1111`` format
characters to their disasm-backed semantics.  No XOR guessing — widths and
``r9`` flag bits come directly from the handler cluster.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from tools.i960_scan import load_maincpu_words

# ``cmpobg g4,g9`` @ 0x05CFC0 with ``g9 = 15<<3 = 120``.
FORMAT_CHAR_LIMIT = 0x78

# ROM-embedded pointer table (immediates after ``bx`` fall-through @ 0x05CFD0).
TABLE_ROM = 0x05CFD0

# Workram mirror used at compile time.
TABLE_RUNTIME = 0x05FBFD0

# Default handler: advance format pointer, no emission.
HANDLER_DEFAULT = 0x05FC9B4

# Out-of-range handler @ ``cmpobg`` fall-through.
HANDLER_OOR = 0x05D9B4

# Workram mirror uses delta ``-0x29000`` from ROM impl (@ ``0x5FC3DC`` → ``0x5D3DC``).
RUNTIME_TO_IMPL_DELTA = 0x29000

# Disasm-derived handler semantics (impl ROM address → metadata).
HANDLER_INFO: dict[int, dict[str, object]] = {
    0x05D1C8: {
        "name": "hash_batch",
        "chars": "#",
        "r9_bits": (3,),
        "effect": "setbit 3,r9 — enables # batch path @ 0x05D824/0x05D7E0 before 0x05D860 emit",
        "fifo": "none",
        "replay": "op_2a200_hash_batch(repeat) after 0x27008 digit counter",
    },
    0x05D304: {
        "name": "digit_repeat",
        "chars": "0123456789",
        "r9_bits": (5,),
        "effect": "setbit 5,r9 — feeds 0x27008 @ g0=17 (repeat accumulator)",
        "fifo": "none",
        "replay": "extend repeat count for next opcode; digits alone do not read FIFO",
    },
    0x05D350: {
        "name": "flag_bit2",
        "chars": "h",
        "r9_bits": (2,),
        "effect": "setbit 2,r9",
        "fifo": "none",
        "replay": "no-op for desert replay",
    },
    0x05D3C8: {
        "name": "pct_template",
        "chars": "%",
        "r9_bits": (),
        "effect": "template @ 0x05FBF22, r8=1 → 0x05D860",
        "fifo": "none",
        "replay": "no FIFO; desert block rarely uses emitted width",
    },
    0x05D3DC: {
        "name": "u16_upload",
        "chars": "D",
        "r9_bits": (0,),
        "arg_bytes": 2,
        "g6": 10,
        "effect": (
            "setbit 0,r9 (@ 0x05D3DC); optional r13 from -4(fp)[idx]; "
            "g6=10 → 0x05D7E8 template row copy → 0x05D860 → bal 0x027008 emit"
        ),
        "fifo": "u16 (consumed by compiled run, not in this handler)",
        "replay": "Python xor_table — hardware 0x1111 decode not traced in disasm",
    },
    0x05D448: {
        "name": "u32_float",
        "chars": "Efg",
        "r9_bits": (),
        "arg_bytes": 4,
        "g6": 10,
        "effect": "ldl u32 / float via 0x05DE00 → 0x05D860",
        "fifo": "u32",
        "replay": "read_u32 × repeat; does not write colorbase directly",
    },
    0x05D714: {
        "name": "u16_add_upload",
        "chars": "U",
        "r9_bits": (0,),
        "arg_bytes": 2,
        "g6": 10,
        "effect": "setbit 0,r9; g6=10 — same emit path as D but ADD @ 0x029CFC in runtime thunk",
        "fifo": "u16",
        "replay": "read_u16 × repeat; ADD g13 @ 0x029CFC (not XOR)",
    },
    0x05FC9B4: {
        "name": "nop",
        "chars": "!<>BCQTmq\"",
        "r9_bits": (),
        "effect": "return to 0x05CFB8 (advance format pointer only)",
        "fifo": "none",
        "replay": "no-op — includes T,t and C",
    },
}


@dataclass(frozen=True)
class FormatJumpEntry:
    char: str
    code: int
    handler: int
    impl: int | None
    in_table: bool
    info: dict[str, object] = field(default_factory=dict)


def _u32(raw: bytes, off: int) -> int:
    return raw[off] | (raw[off + 1] << 8) | (raw[off + 2] << 16) | (raw[off + 3] << 24)


def _impl_addr(handler: int) -> int | None:
    handler &= 0xFFFFFF
    if HANDLER_INFO.get(handler):
        return handler
    if 0x05D000 <= handler <= 0x05DFFF:
        return handler
    for impl in HANDLER_INFO:
        if impl >= 0x05D000 and ((impl + RUNTIME_TO_IMPL_DELTA) & 0xFFFFFF) == handler:
            return impl
    candidate = (handler - RUNTIME_TO_IMPL_DELTA) & 0xFFFFFF
    if HANDLER_INFO.get(candidate):
        return candidate
    return None


def _lookup_info(handler: int, impl: int | None) -> dict[str, object]:
    handler &= 0xFFFFFF
    if handler == HANDLER_DEFAULT:
        return dict(HANDLER_INFO[HANDLER_DEFAULT])
    if impl is not None and impl in HANDLER_INFO:
        return dict(HANDLER_INFO[impl])
    if handler == HANDLER_OOR:
        return {
            "name": "out_of_range",
            "effect": f"char > {FORMAT_CHAR_LIMIT:#x} — cmpobg @ 0x05CFC0",
            "fifo": "none",
            "replay": "treat as no-op or error",
        }
    return {
        "name": f"unknown_0x{handler:06x}",
        "effect": "disasm slice not yet classified",
        "fifo": "unknown",
        "replay": "unknown",
    }


def parse_format_jump_table(raw: bytes | None = None) -> list[FormatJumpEntry]:
    """Return all ``FORMAT_CHAR_LIMIT + 1`` jump-table slots from ROM."""
    if raw is None:
        raw, _ = load_maincpu_words(Path.cwd())  # fallback; prefer explicit bytes
    entries: list[FormatJumpEntry] = []
    for code in range(FORMAT_CHAR_LIMIT + 1):
        off = TABLE_ROM + code * 4
        handler = _u32(raw, off) & 0xFFFFFF
        impl = _impl_addr(handler)
        info = _lookup_info(handler, impl)
        entries.append(
            FormatJumpEntry(
                char=chr(code) if 32 <= code < 127 else "",
                code=code,
                handler=handler,
                impl=impl,
                in_table=True,
                info=info,
            )
        )
    return entries


def resolve_format_char(char: str, raw: bytes | None = None) -> FormatJumpEntry:
    """Resolve one format character through the jump table (or OOR path)."""
    if raw is None:
        from tools.rom_io import resolve_rom_dir

        raw, _ = load_maincpu_words(resolve_rom_dir())
    code = ord(char)
    if code > FORMAT_CHAR_LIMIT:
        return FormatJumpEntry(
            char=char,
            code=code,
            handler=HANDLER_OOR,
            impl=HANDLER_OOR,
            in_table=False,
            info=_lookup_info(HANDLER_OOR, HANDLER_OOR),
        )
    return parse_format_jump_table(raw)[code]


def desert_format_chars(payload_format_chunks: Iterable[str]) -> set[str]:
    chars: set[str] = set()
    for text in payload_format_chunks:
        chars.update(text)
    return chars


def report_desert_format_table(
    *,
    rom_dir: Path | None = None,
    payload: bytes | None = None,
) -> dict:
    """Build a JSON-serialisable report for desert (or supplied) format chars."""
    from tools.model2_cgm_1111 import _is_format_chunk, _split_inner_chunks
    from tools.model2_palette import COURSE_CGM_VADDRS, _iter_cgm_v16_records, find_cgm_blocks
    from tools.rom_io import load32_word_region, resolve_rom_dir, SRALLY_DATA_ROMS

    rd = resolve_rom_dir(rom_dir)
    raw, _ = load_maincpu_words(rd)

    if payload is None:
        md = load32_word_region(rd, SRALLY_DATA_ROMS["main_data"])
        block = {b.vaddr: b for b in find_cgm_blocks(md)}[COURSE_CGM_VADDRS[1]]
        for rec_type, rec_len, off in _iter_cgm_v16_records(md, block):
            if rec_type == 0x1111:
                payload = md[off : off + rec_len]
                break
        else:
            payload = b""

    format_texts = [
        c.decode("latin1", errors="replace")
        for c in _split_inner_chunks(payload)
        if c and _is_format_chunk(c)
    ]
    used = desert_format_chars(format_texts)

    by_handler: dict[str, list[str]] = {}
    rows: list[dict] = []
    for char in sorted(used, key=lambda c: ord(c)):
        entry = resolve_format_char(char, raw)
        key = f"0x{entry.handler:06x}"
        by_handler.setdefault(key, []).append(char)
        rows.append(
            {
                "char": char,
                "code": entry.code,
                "handler": f"0x{entry.handler:06x}",
                "impl": f"0x{entry.impl:06x}" if entry.impl is not None else None,
                "in_table": entry.in_table,
                **{k: entry.info.get(k) for k in ("name", "fifo", "replay", "r9_bits", "arg_bytes")},
            }
        )

    return {
        "table_rom": f"0x{TABLE_ROM:06x}",
        "table_runtime": f"0x{TABLE_RUNTIME:06x}",
        "char_limit": FORMAT_CHAR_LIMIT,
        "handler_default": f"0x{HANDLER_DEFAULT:06x}",
        "handler_oor": f"0x{HANDLER_OOR:06x}",
        "runtime_to_impl_delta": f"0x{RUNTIME_TO_IMPL_DELTA:x}",
        "desert_chars": "".join(sorted(used)),
        "handlers": {
            addr: {"chars": "".join(sorted(chars)), **resolve_format_char(chars[0], raw).info}
            for addr, chars in sorted(by_handler.items())
        },
        "entries": rows,
        "replay_rules": [
            "Digits 0-9: accumulate repeat via 0x27008; never read FIFO alone.",
            "#: set r9 bit 3 → batched XOR/hash over staging (0x02A200), repeat from prior digit.",
            "D: read u16 × repeat → XOR path (0x02A258, g13 from 0x20C958|0x8040).",
            "U: read u16 × repeat → ADD path (0x029CFC, same g13).",
            "E/f/g: read u32 × repeat (float/int emit); no direct colorbase write.",
            "T C B Q m q ! etc.: nop — advance format pointer only.",
            "{ and chars > 0x78: out-of-range handler @ 0x05D9B4.",
        ],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Decode CGM format jump table @ 0x05CFD0")
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=Path("out/decomp/cgm_format_jump_table.json"))
    parser.add_argument("--chars", default=None, help="Only print these format chars (e.g. '#DU')")
    args = parser.parse_args()

    from tools.rom_io import resolve_rom_dir

    raw, _ = load_maincpu_words(resolve_rom_dir(args.rom_dir))
    report = report_desert_format_table(rom_dir=args.rom_dir)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    chars = list(args.chars) if args.chars else sorted(report["desert_chars"])
    print(f"Wrote {args.json}")
    print(f"Table ROM @ 0x{TABLE_ROM:06x}  runtime @ 0x{TABLE_RUNTIME:06x}  limit=0x{FORMAT_CHAR_LIMIT:x}")
    print()
    for char in chars:
        e = resolve_format_char(char, raw)
        impl = f" impl=0x{e.impl:06x}" if e.impl else ""
        fifo = e.info.get("fifo", "?")
        name = e.info.get("name", "?")
        print(f"  {char!r} (0x{ord(char):02x}) → 0x{e.handler:06x}{impl}  {name}  fifo={fifo}")
    print()
    print("Handlers:")
    for addr, body in report["handlers"].items():
        print(f"  {addr}: {body['chars']!r} — {body.get('name')}")


if __name__ == "__main__":
    main()
