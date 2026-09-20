"""Stub arch backends — implement ArchPlugin when adding a processor."""

from __future__ import annotations

from pathlib import Path

from liftkit.arch.base import LiftArtifacts, ParsedSlice, register_arch


class _StubPlugin:
    def __init__(self, name: str) -> None:
        self.name = name

    def parse_slice(self, path: Path) -> ParsedSlice:
        raise NotImplementedError(
            f"arch {self.name!r} is not implemented yet — i960 is the first backend"
        )

    def lift(self, parsed: ParsedSlice, *, name: str) -> LiftArtifacts:
        raise NotImplementedError(f"arch {self.name!r} is not implemented yet")

    def runtime_header(self) -> Path | None:
        return None


def _register(name: str) -> None:
    register_arch(_StubPlugin(name))
