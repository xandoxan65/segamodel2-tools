"""Project workspace: root resolution, yaml helpers."""

from __future__ import annotations

import os
from pathlib import Path

_PROJECT_ROOT: Path | None = None


def set_project_root(root: Path | None) -> None:
    global _PROJECT_ROOT
    _PROJECT_ROOT = root.resolve() if root is not None else None


def project_root() -> Path:
    """Active project root (lift corpus), or cwd."""
    if _PROJECT_ROOT is not None:
        return _PROJECT_ROOT
    env = os.environ.get("LIFTKIT_PROJECT")
    if env:
        return Path(env).resolve()
    return Path.cwd().resolve()


# Legacy alias used by ported i960 modules
def decomp_root() -> Path:
    return project_root()


class _ProjectRootProxy:
    """Path-like proxy so `DECOMP_ROOT / "symbols"` tracks the active project."""

    def __truediv__(self, other: str | Path) -> Path:
        return project_root() / other

    def __fspath__(self) -> str:
        return str(project_root())

    def resolve(self) -> Path:
        return project_root()

    def __str__(self) -> str:
        return str(project_root())


DECOMP_ROOT = _ProjectRootProxy()


def resolve_in_repo(path: Path | str) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return project_root() / p


def repo_rel(path: Path) -> str:
    resolved = path if path.is_absolute() else project_root() / path
    return resolved.resolve().relative_to(project_root().resolve()).as_posix()
