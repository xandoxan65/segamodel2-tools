# Gas reference for ret_zero.c — instruction words from i960-elf-gcc -mkb -O0.
	.text
	.align 4
	.globl _ret_zero
_ret_zero:
	mov	0,g0
	ret
