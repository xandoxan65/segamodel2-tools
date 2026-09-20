# i960 cross toolchain (container)

Vintage **i960-elf binutils 2.30** + optional **GCC 2.95.3** + **Ghidra 12.1.2** inside a multi-arch Linux container. Host OS and CPU do not matter — only Docker or Podman is required.

## Decomp container (recommended)

Controlled **Debian bookworm** image with i960-elf GCC, Ghidra headless, and Python deps. Repo bind-mounted at `/src`.

```bash
./build decomp-image                              # build image (once)
./build decomp-shell                              # interactive shell
./build decomp-run -- i960-elf-gcc --version      # one-shot command
bash decomp/container/run.sh ./build reasm --all  # same via decomp/ scripts
```

| Image tag | `segamod2-decomp:12.1.2` |
|-----------|-------------------------------|
| Contents | binutils + GCC 2.95.3 + Ghidra + i960 processor + Python deps |

Docs: [decomp/container/README.md](../../decomp/container/README.md)

## Quick start (binutils only)

```bash
bash tooling/i960/container/build-image.sh
bash tooling/i960/spike/run-spike.sh
```

## Run arbitrary toolchain commands

```bash
bash tooling/i960/container/run-decomp.sh i960-elf-as --help
bash tooling/i960/container/run-decomp.sh i960-elf-objdump -d tooling/i960/spike/ret.o
```

The repo root is mounted at `/src` inside the container.

## Multi-arch image build

```bash
I960_PLATFORMS=linux/amd64,linux/arm64 I960_PUSH=1 \
  bash tooling/i960/container/build-decomp-image.sh
```

Local `--load` supports one platform at a time. Each platform builds its own native `i960-elf-as` (cross tools for i960, not cross-built themselves).

## Model 2 target flags

Sega Model 2A uses **i960-KB**. gas960 uses **`-AKB`** (GCC uses `-mkb`):

```bash
i960-elf-as -AKB ...
i960-elf-gcc -mkb -DCPU=I960KB ...
```

### Default C compile flags

Decomp C sources (hand ports, future `@rom` translations) default to:

```bash
export I960_GCC_FLAGS="-O2 -mkb"   # set in container_env.sh / run-decomp.sh
```

`-O2` enables leaf functions (`mov g14,gR` / `bx (gR)`) when parameters are declared **`register`**. Assembling pre-generated `.s` from MAME disasm still uses **`i960-elf-gcc -mkb -c`** only (no `-O`).

Override for experiments: `I960_GCC_FLAGS="-O0 -mkb" bash decomp/scripts/compare_libc_strcpy.sh`

See `tooling/i960/gcc_flags.sh` and `tools/decomp/i960_gcc_flags.py`.

## GCC 2.95.3

Pre-built in the decomp image. To rebuild after patching sources:

```bash
bash tooling/i960/container/run-decomp.sh build-i960-toolchain --prefix /opt/i960-elf
# or from decomp/: ./toolchain/build-i960-toolchain.sh --with-deps
bash tooling/i960/spike/run-gcc-spike.sh
```

Standalone GCC-only image (no Ghidra):

```bash
bash tooling/i960/container/build-gcc-image.sh
export I960_TOOLCHAIN_IMAGE=segamod2/i960-toolchain:gcc-2.95.3
```

Recipe follows [nkito/i960_sbc](https://github.com/nkito/i960_sbc) (gcc-core 2.95.3 + newlib 1.8.2, `t-960bare` tmakes, collect2 patch).

## Compile tiers

Three-layer strategy for maincpu code — see [docs/decomp_compile_tiers.md](../../docs/decomp_compile_tiers.md):

| Tier | Command | Role |
|------|---------|------|
| 1 | `./build reasm --all` | MAME disasm → gas → ROM bytes (**source of truth**) |
| 2 | `decomp/toolchain/patches/` | Optional gcc 2.95 patches (applied at toolchain build) |
| 3 | `./build c-reasm --c … --rom 0x…:0x…` | Hand C → gcc -S → peephole → as → ROM compare |

```bash
./build c-reasm --c decomp/src/libc/libc_strcpy.c --rom 0x05cdc8:0x3c --keep
bash decomp/scripts/compare_libc_strcpy.sh   # tier 1 + tier 3 demo
```

## Reassemble a MAME slice

```bash
./build reasm --slice decomp/disasm/maincpu/maincpu_023cc8_900.asm
./build reasm --all
./build reasm --all --mode bytes
./build reasm --all --mode gas
```

Pipeline: [tools/decomp/mame_to_gas960.py](../../tools/decomp/mame_to_gas960.py) → container `i960-elf-as` / `ld` → byte compare vs ROM.

### GCC driver on full slices

```bash
./build gcc-reasm --slice decomp/disasm/maincpu/maincpu_023cc8_900.asm --compare-gas
./build gcc-reasm --all
```

## Ghidra headless

```bash
bash tooling/i960/container/build-decomp-image.sh
./build analyze
./build ghidra --slice decomp/disasm/maincpu/maincpu_023cc8_900.asm
```

Reports: `out/decomp/ghidra/<slice>.json`. C scaffolds: `decomp/src/ghidra/<slice>/*.c` (auto-export; use `--no-export-c` to skip). Headless runs `FixI960LeafReturns.java` before export so `mov g14,gR` / `bx (gR)` leaf epilogues decompile as returns instead of indirect calls. Export then rewrites Ghidra `ac` condition-code bitmasks into normal boolean tests (`tools/decomp/ghidra_simplify_ac.py`). Allow several minutes and ~2 GiB RAM (`I960_CONTAINER_MEMORY=4g` optional).

Legacy wrappers `build-ghidra-image.sh` and `run-ghidra.sh` delegate to the decomp container.

## Provenance

| Component | Version | Source |
|-----------|---------|--------|
| binutils | 2.30 | https://ftp.gnu.org/gnu/binutils/ |
| gcc | 2.95.3 | https://ftp.gnu.org/gnu/gcc/ |
| newlib | 1.8.2 | ftp://sourceware.org/pub/newlib/ |
| ghidra | 12.1.2 | https://github.com/NationalSecurityAgency/ghidra/releases |
| ghidra_i960 | community | https://github.com/mumbel/ghidra_i960 |
| Base image | debian:bookworm-slim | Docker Hub (multi-arch) |

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `CONTAINER_ENGINE` | auto (`podman`, then `docker`) | Container runtime |
| `I960_DECOMP_IMAGE` | `segamod2/i960-decomp:12.1.2` | Unified decomp image |
| `I960_TOOLCHAIN_IMAGE` | same as decomp (or binutils tag for slim builds) | Toolchain image tag |
| `I960_GHIDRA_IMAGE` | fallback alias for `I960_DECOMP_IMAGE` | Legacy |
| `GHIDRA_ROOT` | `/opt/ghidra` in container | Ghidra install root |
| `I960_PLATFORMS` | host arch | Comma-separated platforms for buildx |
| `I960_PUSH` | `0` | Set `1` to push multi-arch manifest |
| `I960_CONTAINER_MEMORY` | unset | e.g. `4g` for Ghidra headless |
| `FORCE_I960_GCC_REBUILD` | `0` | Set `1` for `build-i960-gcc` |
