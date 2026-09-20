# Default i960-elf-gcc flags for decomp C compilation (source with shell).
# Model 2A KB core; -O2 enables leafproc/bx epilogues when args use `register`.
#
# Override: I960_GCC_FLAGS="-O0 -mkb" bash decomp/scripts/compare_libc_strcpy.sh

: "${I960_GCC_DEFAULT_FLAGS:=-O2 -mkb}"
: "${I960_GCC_FLAGS:=${I960_GCC_DEFAULT_FLAGS}}"

# shellcheck disable=SC2206
I960_GCC_FLAG_ARR=(${I960_GCC_FLAGS})

i960_gcc() {
  i960-elf-gcc "${I960_GCC_FLAG_ARR[@]}" "$@"
}
