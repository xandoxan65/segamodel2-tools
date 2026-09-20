/* Link a disasm slice at its ROM address (maincpu @ 0). */
SECTIONS
{
  . = 0x00000000;
  .text : {
    KEEP(*(.text))
  }
}
