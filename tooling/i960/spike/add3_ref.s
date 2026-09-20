# Gas reference for add3.c — instruction words from i960-elf-gcc -mkb -O0.
	.text
	.align 4
	.globl _add3
_add3:
	addo	16,sp,sp
	st	g0,0x40(fp)
	ld	0x40(fp),g5
	addo	3,g5,g4
	mov	g4,g0
	ret
