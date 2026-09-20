"""Resolve maincpu ROM addresses to curated symbol names."""

from __future__ import annotations

from functools import lru_cache

from liftkit.arch.i960.export_symbols import load_functions_yaml
from liftkit.project.workspace import DECOMP_ROOT


@lru_cache(maxsize=1)
def _addr_to_name() -> dict[int, str]:
    path = DECOMP_ROOT / "symbols" / "functions.yaml"
    rows = load_functions_yaml(path)
    out: dict[int, str] = {}
    for row in rows:
        addr = row.get("address")
        name = row.get("name")
        if addr is None or not name:
            continue
        out[int(addr)] = str(name)
    syms = DECOMP_ROOT / "symbols" / "srallyc_maincpu.syms"
    if syms.is_file():
        for line in syms.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    out.setdefault(int(parts[1], 16), parts[0])
                except ValueError:
                    continue
    return out


def lookup_symbol_name(addr: int) -> str | None:
    return _addr_to_name().get(addr)


def _lookup_abi_by_addr(addr: int):
    from liftkit.arch.i960.i960_abi import lookup_abi_by_addr

    return lookup_abi_by_addr(addr)


def format_call(addr: int) -> str:
    name = lookup_symbol_name(addr)
    abi = _lookup_abi_by_addr(addr)
    if name and abi and abi.has_c_abi:
        args = ", ".join(abi.format_c_call_args())
        return f"{name}({args});"
    if name:
        return f"{name}();"
    return f"i960_call_rom(0x{addr:x});"


def format_extern_decl(addr: int) -> str | None:
    name = lookup_symbol_name(addr)
    if not name:
        return None
    abi = _lookup_abi_by_addr(addr)
    if abi and abi.has_c_abi:
        return f"extern {abi.c_signature(name)};"
    return f"extern void {name}(void);"
