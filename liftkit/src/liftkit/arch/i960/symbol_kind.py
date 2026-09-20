"""Symbol kind (code vs rodata) from functions.yaml and section map."""

from __future__ import annotations

from pathlib import Path

from liftkit.arch.i960.export_symbols import load_functions_yaml
from liftkit.project.workspace import resolve_in_repo
from liftkit.arch.i960.section_map import ROM_ANCHORS


def _default_functions_yaml() -> Path:
    return resolve_in_repo(Path("symbols/functions.yaml"))


def _anchor_kind(name: str, address: int) -> str | None:
    for addr, label, _conf, category in ROM_ANCHORS:
        if label == name or addr == address:
            return category
    return None


def lookup_symbol_row(name: str, *, functions_yaml: Path | None = None) -> dict | None:
    path = resolve_in_repo(functions_yaml or _default_functions_yaml())
    for row in load_functions_yaml(path):
        if str(row.get("name", "")) == name:
            return row
    return None


def lookup_symbol_kind(
    name: str,
    address: int,
    *,
    functions_yaml: Path | None = None,
    row: dict | None = None,
) -> str:
    """Return 'code' or 'rodata' (and future kinds)."""
    entry = row if row is not None else lookup_symbol_row(name, functions_yaml=functions_yaml)
    if entry and entry.get("kind"):
        return str(entry["kind"])
    cat = _anchor_kind(name, address)
    if cat in ("rodata", "data"):
        return "rodata"
    return "code"


def lookup_symbol_section(name: str, *, functions_yaml: Path | None = None) -> str | None:
    row = lookup_symbol_row(name, functions_yaml=functions_yaml)
    if not row:
        return None
    section = row.get("section")
    return str(section) if section else None


def default_src_dir(name: str, *, functions_yaml: Path | None = None) -> Path:
    section = lookup_symbol_section(name, functions_yaml=functions_yaml) or ""
    if "boot" in section:
        return Path("src/boot")
    if section == "irq_infrastructure":
        return Path("src/irq")
    if section in ("game_logic_core", "game_logic_geo_core", "game_logic_extended"):
        return Path("src/game")
    if section == "libc_runtime":
        return Path("src/libc")
    return Path("src/libc")
