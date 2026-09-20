"""Resolve Ghidra install paths (container / Homebrew)."""

from __future__ import annotations

import os
from pathlib import Path

CONTAINER_GHIDRA_ROOT = Path("/opt/ghidra")
BREW_GHIDRA_ROOT = Path("/opt/homebrew/Cellar/ghidra/12.1.2/libexec")

BREW_JAVA_CANDIDATES = (
    Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"),
    Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"),
)


def ghidra_root() -> Path:
    env_root = os.environ.get("GHIDRA_ROOT")
    if env_root:
        return Path(env_root)
    if (CONTAINER_GHIDRA_ROOT / "support" / "analyzeHeadless").is_file():
        return CONTAINER_GHIDRA_ROOT
    if (BREW_GHIDRA_ROOT / "support" / "analyzeHeadless").is_file():
        return BREW_GHIDRA_ROOT
    raise FileNotFoundError(
        "Ghidra not found — set GHIDRA_ROOT, build the container image "
        "(bash tooling/i960/container/build-ghidra-image.sh), or brew install ghidra"
    )


def analyze_headless() -> Path:
    path = ghidra_root() / "support" / "analyzeHeadless"
    if not path.is_file():
        raise FileNotFoundError(f"analyzeHeadless not found at {path}")
    return path


def i960_processor_dir() -> Path:
    return ghidra_root() / "Ghidra" / "Processors" / "i960"


def i960_processor_installed() -> bool:
    return i960_processor_dir().is_dir()


def ghidra_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("GHIDRA_ROOT", str(ghidra_root()))
    if "JAVA_HOME" not in env:
        for candidate in BREW_JAVA_CANDIDATES:
            if candidate.is_dir():
                env["JAVA_HOME"] = str(candidate)
                break
        container_java = Path("/opt/java")
        if "JAVA_HOME" not in env and container_java.is_dir():
            env["JAVA_HOME"] = str(container_java)
    return env


def require_i960_processor() -> None:
    if not i960_processor_installed():
        raise FileNotFoundError(
            f"i960 processor module missing at {i960_processor_dir()} — "
            "run bash tooling/setup_ghidra_i960.sh (host) or use the ghidra container image"
        )
