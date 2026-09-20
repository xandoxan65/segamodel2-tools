/*
 * Minimal i960-KB GCC spike — naked body matches tooling/i960/spike/ret.s.
 * Compile: i960-elf-gcc ${I960_GCC_FLAGS:--O2 -mkb} -c ret.c -o ret_gcc.o
 */
void ret_spike(void) __attribute__((naked));

void ret_spike(void)
{
	__asm__ volatile ("ret");
}
