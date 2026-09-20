# TGP (MB86234) firmware — srallycb

## Provenance

Uploaded by i960 `@ 0x4BD0` (`decomp/disasm/maincpu/maincpu_004bc0_80.asm`):

1. `setbit 31` → `coproctl` `@ 0x980000` (upload mode)
2. Source cursor = workram **`0x5F9E94`**
3. Word count = **`*(0x5FB898)`** = `0x681` (1665)
4. Loop: `st` each word → FIFO `@ 0x884000` (MAME `copro_tgp_program[]`)
5. Clear bit31

Workram `@ 0x5F9E94` is a **ROM mirror**: `maincpu_off = vaddr - 0x59F000`
(see `WORKRAM_ROM_MIRROR` in `decomp/src/model2_rom.c`).

| VA | ROM off | Role |
|----|---------|------|
| `0x5F9E94` | `0x5AE94` | program words |
| `0x5FB898` | `0x5C898` | word count (`0x681`) |

Blob: `srally_tgp_program.bin` (6660 bytes).

## Disasm

```text
python3 -m tools.tgp.mb86233_dasm
# → decomp/disasm/tgp/srally_tgp_program.asm
```

ISA reference: MAME `mb86233d.cpp` (MB86233/34 family). Not Ghidra.

## FIFO dispatch

After reset (`brif alw #0x10` @ PC0), main loop `@ 0x70` reads FIFO (`rf1`),
validates the duplicated opcode byte, then:

```text
lid #0xaf
… add opcode …
bsul alw d          ; call jump table
```

Jump table base **`0xAF + opcode`**:

| Op | Table PC | Handler |
|----|----------|---------|
| `0x07` | `0xB6` | `0x16D` |
| `0x2f` | `0xDE` | `0x30E` |
| `0x51` | `0x100` | `0x48E` (orient R along FIFO xyz; helpers `0x4E3`/`0x4F8`) |
| `0x52` | `0x101` | `0x58A` |
| `0x53` | `0x102` | `0x63C` |
| `0x55` | `0x104` | `0x66E` |
| `0x60` | `0x10F` | `0x3DB` (store 12-float matrix to external list) |
| `0x61` | `0x110` | `0x3E9` (load matrix from external list) |

## `0x52` `@ 0x58A` (fill slot)

i960 `table_index_a` writes a nine-word block then `0x29005252`:

| Word | Field |
|------|--------|
| 0..2 | query XYZ |
| 3 | copro_data directory word addr (course row word1) |
| 4 | segment count<<2 |
| 5..7 | prev/index/next <<2 |
| 8 | `g3<<1` (slot arg) |

Handler loads bank `0x800000`, resolves entry at `dir + {index,next,prev}<<2`
(parallel `addd : mov d,$61` keeps the bare dir in `$61`). Per entry:

1. `{count, geom_byte, attr_byte, 0}` — word addrs via `>>2`
2. For each tri: copy 16 floats; `attr&4` → 4-edge else 3
3. XZ same-sign test (all non-neg → hit; mixed → next tri; all-neg → abandon entry)
4. Hit → slot `{attr_ptr, geom_ptr}` (host: flag word + 16 floats)

## `0x53` `@ 0x63C` (bit7 / plane flag)

i960 issues `0x29805353` then `arg2<<1` (`geo_view_table_index_b`).

```text
x1 = 0x68 + fifo_arg          ; slot in TGP data RAM
a  = *x1++                    ; word0
b  = *x1++                    ; word1
if a == 0:
    push 17×0 to FIFO out     ; flag=0 → i960 early out
else:
    a = *external(a)          ; FLAG word (17th readback)
    bank/rf3 = b; x1 = b
    rep 16: push *external(x1++)
    push a                    ; flag
```

i960 then does `masked = (flag>>16) & 0x8f`; **bit7 = masked & 0x80**.

Slot is filled by **`0x52`**. Flag is the copro_data attr word (often
`0x00800004` → bit7 set). Floats[12..15] are plane coeffs (bit7 clear) or
normal+divisor (bit7 set) — not host-invented.

## Related ROMs (not this blob)

| Region | ROMs | Role |
|--------|------|------|
| `copro_tgp_tables` | opr-14742a/43a | sin/inv/isqrt |
| `copro_data` | mpr-17754/55 | collision / height (TGP `rf3` bank `0x800000`) |

Host: `model2_tgp_fw_load_copro_data_default()` reads
`out/heightmaps/copro_data_deinterleaved.bin` on first `0x52`.
