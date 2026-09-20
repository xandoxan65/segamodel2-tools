"""Architecture plugin protocol and registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass
class ParsedSlice:
    """Arch-neutral wrapper around a parsed disasm slice."""

    arch: str
    base: int
    length: int
    source: str
    raw: Any  # arch-specific document (e.g. SliceDocument)


@dataclass
class LiftArtifacts:
    """Outputs of a deterministic lift (before optional AI rewrite)."""

    name: str
    arch: str
    addr: int
    length: int
    kind: str
    ir: Any | None
    scaffold_c: str
    lifted_text: str
    abi: dict[str, Any] | None = None
    extras: dict[str, Any] | None = None


@runtime_checkable
class ArchPlugin(Protocol):
    """Per-ISA backend: parse listing → IR → C scaffold."""

    name: str

    def parse_slice(self, path: Path) -> ParsedSlice:
        ...

    def lift(self, parsed: ParsedSlice, *, name: str) -> LiftArtifacts:
        ...

    def runtime_header(self) -> Path | None:
        """Path to C runtime header shipped with liftkit, if any."""
        ...


_REGISTRY: dict[str, ArchPlugin] = {}
_BUILTINS_LOADED = False


def register_arch(plugin: ArchPlugin) -> ArchPlugin:
    _REGISTRY[plugin.name] = plugin
    return plugin


def get_arch(name: str) -> ArchPlugin:
    _ensure_builtins()
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown arch {name!r}; known: {known}")
    return _REGISTRY[name]


def list_arches() -> list[str]:
    _ensure_builtins()
    return sorted(_REGISTRY)


def _ensure_builtins() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    from liftkit.arch import i960 as _i960  # noqa: F401
    from liftkit.arch import m68k as _m68k  # noqa: F401
    from liftkit.arch import z80 as _z80  # noqa: F401
    from liftkit.arch import arm as _arm  # noqa: F401
    from liftkit.arch import x86_64 as _x86  # noqa: F401

    _BUILTINS_LOADED = True
