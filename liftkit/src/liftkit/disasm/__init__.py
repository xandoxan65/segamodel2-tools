"""Disassembly frontends for liftkit."""

from liftkit.disasm.mame_i960 import disasm_maincpu_slice, find_mame, resolve_rom_dir

__all__ = ["disasm_maincpu_slice", "find_mame", "resolve_rom_dir"]
