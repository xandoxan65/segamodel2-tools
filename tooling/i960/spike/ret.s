# Minimal gas960 spike for segamod2 i960 toolchain container.
# Assemble: run.sh i960-elf-as -AKB -o tooling/i960/spike/ret.o tooling/i960/spike/ret.s

	.text
	.align 4
	.globl _ret_spike
_ret_spike:
	ret
