# Sega Model 2 tools

Lift, disassembly, and asset tools for Sega Model 2 games. This repo is optional. A game tree such as Sega Rally builds without it.

Clone it **inside** a game checkout when you need to disassemble or lift more code:

```bash
git clone https://github.com/xandoxan65/segamodel2-tools.git tools
```

From the game root, the Python package is `tools/tools`:

```bash
export PYTHONPATH="$PWD/tools${PYTHONPATH:+:$PYTHONPATH}"
python3 -m tools.extract --rom-dir ROMS/srallyc-b --out out
python3 -m liftkit --project . lift --function libc_memcpy
```

`PYTHONPATH` must point at this repo root (the directory that contains the `tools` package, `liftkit/`, `viewer/`, and `tooling/`), not at the game root.

## Layout

| Path | Contents |
|------|----------|
| `tools/` | Python package: extract, i960 scan, lift helpers |
| `liftkit/` | Disasm to IR to C scaffold |
| `viewer/` | Web viewer for extracted assets |
| `catalog/` | Atlas tagger |
| `tooling/i960/` | i960 binutils container and spikes |

ROM dumps and `out/` stay in the game tree. Do not commit them here.
