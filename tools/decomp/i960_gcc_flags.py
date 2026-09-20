"""Shared default flags for i960-elf-gcc when compiling decomp C sources."""

from __future__ import annotations

import os
import shlex

DEFAULT_I960_GCC_FLAGS = ("-O2", "-mkb")


def i960_gcc_flags(extra: list[str] | None = None) -> list[str]:
    """Return gcc argv prefix: env I960_GCC_FLAGS or DEFAULT, plus optional extras."""
    env = os.environ.get("I960_GCC_FLAGS", "").strip()
    base = shlex.split(env) if env else list(DEFAULT_I960_GCC_FLAGS)
    if extra:
        return base + extra
    return base
