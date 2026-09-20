gcc2_compiled.:
___gnu_compiled_c:
.text
	.align 4
	.globl _libc_strcpy
	#  Function 'libc_strcpy'
	#  Registers used: g0 g1 g2 g4 g5 cc 
	#		   
	.globl	libc_strcpy.lf
	.leafproc	_libc_strcpy,libc_strcpy.lf
_libc_strcpy:
	lda    LR1,g14
libc_strcpy.lf:
	mov    g14,g2
	mov    0,g14
	cmpobe	0,g0,L8
	ldob	(g1),g4
	cmpobne	0,g4,L3
L8:
	mov	0,g0
	bx	(g2)
L3:
	subo	1,g0,g5
L7:
	ldob	(g1),g4
	addo	g5,1,g5
	stob	g4,(g5)
	shlo	24,g4,g4
	addo	g1,1,g1
	cmpobne	0,g4,L7
	bx	(g2)
LR1:	ret
