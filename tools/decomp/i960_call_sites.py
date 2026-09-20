"""Static caller xref scan for lifted function ABI notes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from tools.decomp.workspace import resolve_in_repo

_CALL = re.compile(r"^0*([0-9a-fA-F]+):\s+\S+\s+call\s+0x0*([0-9a-fA-F]+)\s*$", re.I)
_MOV_G = re.compile(
    r"^0*([0-9a-fA-F]+):\s+\S+\s+mov(?:l)?\s+(?:0x0|0),\s*(g\d+)\s*$"
    r"|^0*([0-9a-fA-F]+):\s+\S+\s+mov(?:l)?\s+(g\d+|r\d+),\s*(g\d+)\s*$"
    r"|^0*([0-9a-fA-F]+):\s+\S+\s+lda\s+0x[0-9a-fA-F]+,\s*(g\d+)\s*$",
    re.I,
)
_LD_G = re.compile(
    r"^0*([0-9a-fA-F]+):\s+\S+\s+ld\s+\([^)]+\),\s*(g\d+)\s*$",
    re.I,
)


@dataclass
class CallSiteNote:
    caller_addr: int
    caller_file: str
    g0: str | None = None
    g1: str | None = None
    g2: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "caller": f"0x{self.caller_addr:x}",
            "file": self.caller_file,
            "g0": self.g0,
            "g1": self.g1,
            "g2": self.g2,
        }

    def emit_comment(self) -> str:
        parts = [f"caller 0x{self.caller_addr:x}"]
        for reg in ("g0", "g1", "g2"):
            val = getattr(self, reg)
            if val:
                parts.append(f"{reg}={val}")
        return f"/* call site: {', '.join(parts)} */"


@lru_cache(maxsize=32)
def _scan_disasm_dir() -> dict[int, list[CallSiteNote]]:
    disasm = resolve_in_repo(Path("disasm/maincpu"))
    by_callee: dict[int, list[CallSiteNote]] = {}
    if not disasm.is_dir():
        return by_callee

    for path in sorted(disasm.glob("*.asm")):
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        rel = path.relative_to(resolve_in_repo(Path("."))).as_posix()
        for idx, line in enumerate(lines):
            m = _CALL.match(line.strip())
            if not m:
                continue
            callee = int(m.group(2), 16)
            caller = int(m.group(1), 16)
            note = CallSiteNote(caller_addr=caller, caller_file=rel)
            window = lines[max(0, idx - 12) : idx]
            for wline in reversed(window):
                w = wline.strip()
                lm = _LD_G.search(w)
                if lm and note.g2 is None and lm.group(2) == "g2":
                    note.g2 = f"*(u32*)..."
                lm2 = re.search(
                    r"mov(?:l)?\s+(g\d+|r\d+|0x[0-9a-fA-F]+|0),\s*(g[012])\b",
                    w,
                    re.I,
                )
                if lm2:
                    src, dst = lm2.group(1).lower(), lm2.group(2).lower()
                    if dst == "g0" and note.g0 is None:
                        note.g0 = src
                    elif dst == "g1" and note.g1 is None:
                        note.g1 = src
                    elif dst == "g2" and note.g2 is None:
                        note.g2 = src
                lda = re.search(r"lda\s+0x([0-9a-fA-F]+),\s*(g[012])\b", w, re.I)
                if lda:
                    dst = lda.group(2).lower()
                    val = f"rom:0x{lda.group(1)}"
                    if dst == "g0" and note.g0 is None:
                        note.g0 = val
                    elif dst == "g1" and note.g1 is None:
                        note.g1 = val
                    elif dst == "g2" and note.g2 is None:
                        note.g2 = val
            by_callee.setdefault(callee, []).append(note)
    return by_callee


def call_sites_for(addr: int, *, limit: int = 5) -> list[CallSiteNote]:
    return _scan_disasm_dir().get(addr, [])[:limit]
