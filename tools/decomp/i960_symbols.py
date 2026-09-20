"""Resolve maincpu ROM addresses to curated symbol names."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from tools.decomp.export_symbols import load_functions_yaml
from tools.decomp.workspace import DECOMP_ROOT


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


def format_call(addr: int) -> str:
    name = lookup_symbol_name(addr)
    if name:
        return f"{name}();"
    return f"call 0x{addr:08x};"
