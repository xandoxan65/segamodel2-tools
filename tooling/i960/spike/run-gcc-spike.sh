#!/usr/bin/env bash
# GCC feasibility spikes: inline ret, return-0 epilogue, and add3 arithmetic.
# Encoding spikes intentionally use -O0 -mkb to match fixed reference .s files.
# Decomp C defaults to I960_GCC_FLAGS=-O2 -mkb (see tooling/i960/gcc_flags.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
# shellcheck source=../gcc_flags.sh
source "$REPO_ROOT/tooling/i960/gcc_flags.sh"
export I960_DECOMP_IMAGE="${I960_DECOMP_IMAGE:-${I960_GHIDRA_IMAGE:-segamod2/i960-decomp:12.1.2}}"
CONTAINER="$REPO_ROOT/tooling/i960/container/run-decomp.sh"
SPIKE_REL="tooling/i960/spike"
RET_OPCODE="0000000a"

if ! I960_DECOMP_IMAGE="$I960_DECOMP_IMAGE" "$CONTAINER" i960-elf-gcc --version >/dev/null 2>&1; then
  echo "error: i960-elf-gcc not found in image '$I960_DECOMP_IMAGE'" >&2
  echo "Build the decomp image first:" >&2
  echo "  bash tooling/i960/container/build-decomp-image.sh" >&2
  exit 1
fi

text_prefix_hex() {
  local object_rel=$1
  local length=$2
  local bin_rel="${object_rel%.o}.text.bin"
  "$CONTAINER" i960-elf-objcopy -O binary -j .text "$object_rel" "$bin_rel"
  xxd -p -l "$length" "$REPO_ROOT/$bin_rel" | tr -d '\n'
}

compare_text_prefix() {
  local label=$1
  local gcc_o=$2
  local gas_o=$3
  local length=$4

  local gcc_hex
  local gas_hex
  gcc_hex="$(text_prefix_hex "$gcc_o" "$length")"
  gas_hex="$(text_prefix_hex "$gas_o" "$length")"

  echo "  $label (first 0x$(printf '%x' "$length") bytes)"
  echo "    gcc: $gcc_hex"
  echo "    gas: $gas_hex"

  if [[ "$gcc_hex" == "$gas_hex" ]]; then
    echo "  PASS $label"
    return 0
  fi
  echo "  FAIL $label — gcc and gas instruction prefix differ" >&2
  return 1
}

test_inline_ret() {
  echo "==> [1/3] inline ret (ret.c vs ret.s)"
  local gas_o="$SPIKE_REL/ret_gas.o"
  local gcc_o="$SPIKE_REL/ret_gcc.o"

  "$CONTAINER" i960-elf-as -AKB -o "$gas_o" "$SPIKE_REL/ret.s"
  "$CONTAINER" i960-elf-gcc -mkb -c -o "$gcc_o" "$SPIKE_REL/ret.c" 2>/dev/null || \
    "$CONTAINER" i960-elf-gcc -mkb -c -o "$gcc_o" "$SPIKE_REL/ret.c"

  local gas_word gcc_word
  gas_word="$(text_prefix_hex "$gas_o" 4)"
  gcc_word="$(text_prefix_hex "$gcc_o" 4)"

  echo "  first word gas=$gas_word gcc=$gcc_word (expect $RET_OPCODE)"
  if [[ "$gas_word" == "$RET_OPCODE" && "$gcc_word" == "$RET_OPCODE" ]]; then
    echo "  PASS inline ret"
    return 0
  fi
  echo "  FAIL inline ret" >&2
  return 1
}

test_ret_zero_epilogue() {
  echo "==> [2/3] return-0 epilogue (ret_zero.c vs ret_zero_ref.s)"
  local gcc_o="$SPIKE_REL/ret_zero_gcc.o"
  local gas_o="$SPIKE_REL/ret_zero_gas.o"
  local gcc_s="$SPIKE_REL/ret_zero_gcc.s"

  "$CONTAINER" i960-elf-gcc -mkb -O0 -S -o "$gcc_s" "$SPIKE_REL/ret_zero.c"
  "$CONTAINER" i960-elf-gcc -mkb -O0 -c -o "$gcc_o" "$SPIKE_REL/ret_zero.c"
  "$CONTAINER" i960-elf-as -AKB -o "$gas_o" "$SPIKE_REL/ret_zero_ref.s"

  echo "  gcc -S excerpt:"
  grep -E 'mov|ret|_ret_zero' "$REPO_ROOT/$gcc_s" | head -6 | sed 's/^/    /'

  compare_text_prefix "ret_zero through ret" "$gcc_o" "$gas_o" 8
}

test_add3_arithmetic() {
  echo "==> [3/3] add3 arithmetic (add3.c vs add3_ref.s)"
  local gcc_o="$SPIKE_REL/add3_gcc.o"
  local gas_o="$SPIKE_REL/add3_gas.o"
  local gcc_s="$SPIKE_REL/add3_gcc.s"

  "$CONTAINER" i960-elf-gcc -mkb -O0 -S -o "$gcc_s" "$SPIKE_REL/add3.c"
  "$CONTAINER" i960-elf-gcc -mkb -O0 -c -o "$gcc_o" "$SPIKE_REL/add3.c"
  "$CONTAINER" i960-elf-as -AKB -o "$gas_o" "$SPIKE_REL/add3_ref.s"

  echo "  gcc -S excerpt:"
  grep -E 'addo|mov|st|ld|ret|_add3' "$REPO_ROOT/$gcc_s" | head -10 | sed 's/^/    /'

  compare_text_prefix "add3 through ret" "$gcc_o" "$gas_o" 24
}

FAIL=0
test_inline_ret || FAIL=1
test_ret_zero_epilogue || FAIL=1
test_add3_arithmetic || FAIL=1

if [[ "$FAIL" -eq 0 ]]; then
  echo "gcc spike PASS (3/3)"
  exit 0
fi

echo "gcc spike FAIL" >&2
exit 1
