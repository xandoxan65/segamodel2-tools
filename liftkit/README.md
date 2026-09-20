# liftkit

Multi-ISA uplift toolkit: **disasm → IR → deterministic C scaffold**, with optional AI semantic rewrite.

| Surface | Command |
|---------|---------|
| Lift | `liftkit lift --arch i960 --slice path.asm` |
| Address+length | `liftkit lift --arch i960 --address 0x420 --length 0x150` |
| Disasm | `liftkit disasm --arch i960 --address 0x420 --length 0x150` |
| AI rewrite | `liftkit rewrite --function NAME` (needs `LIFTKIT_API_KEY` for live) |
| GUI | `liftkit gui --project ./path` |
| Project | `liftkit project status|open|init|functions|recent` |

## Install

```bash
cd liftkit
python3 -m pip install -e ".[dev]"
# optional GUI / live AI:
# python3 -m pip install -e ".[gui,ai]"
```

## Quick start (against the Sega Rally decomp corpus)

```bash
python3 -m liftkit arches

python3 -m liftkit lift \
  --project ../decomp \
  --function libc_memcpy

python3 -m liftkit lift \
  --project ../decomp \
  --address 0x5daa0 --length 0x140 \
  --name libc_memcpy

# Offline AI hook (no API key) — writes *.semantic.c draft
python3 -m liftkit rewrite --project ../decomp --function libc_memcpy --provider echo

# Live rewrite (optional)
# export LIFTKIT_API_KEY=...
# python3 -m liftkit rewrite --project ../decomp --function libc_memcpy --provider openai

python3 -m liftkit gui --project ../decomp
```

## Layout

| Path | Role |
|------|------|
| `src/liftkit/` | Library + CLI |
| `src/liftkit/arch/i960/` | Ported i960 lifter |
| `src/liftkit/arch/{m68k,z80,arm,x86_64}/` | Stub backends |
| `prompts/` | AI rewrite prologue templates |
| `runtime/i960.h` | Lifted C runtime header |
| `gui-web/` | TypeScript Vite SPA (`npm run build` → `gui-web/dist`) |
| `gui-web/dist/` | Built UI served by `liftkit gui` |

## GUI

Project manager (not one-shot only): open/init projects, browse the symbol catalog with lift status, lift/rewrite selected functions, inspect curated/scaffold/IR/asm artifacts.

```bash
cd gui-web && npm install && npm run build && cd ..
python3 -m pip install -e ".[gui]"
python3 -m liftkit gui --project ../decomp
# http://127.0.0.1:8765

# CLI project helpers
python3 -m liftkit project status --project ../decomp
python3 -m liftkit project functions --project ../decomp --status not_lifted
```

## Policy

- Lift only from real disassembler input (no invented C).
- Deterministic lift is mandatory; AI rewrite is optional and post-lift.
- No emulator runtime memory capture as discovery input.
