"""Project inventory: symbols, slices, lift/rewrite artifact status."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from liftkit.arch.i960.export_symbols import load_functions_yaml
from liftkit.project.workspace import project_root, resolve_in_repo, set_project_root

_ROM_RE = re.compile(
    r"//\s*@rom\s+0x([0-9a-fA-F]+)\s+\+0x([0-9a-fA-F]+)(?:\s+(\w+))?",
)
_SLICE_RE = re.compile(r"^maincpu_([0-9a-f]+)_([0-9a-f]+)\.asm$", re.I)

RECENT_PATH = Path.home() / ".liftkit" / "recent_projects.json"
CONFIG_NAME = "liftkit.project.yaml"


@dataclass
class FunctionRow:
    name: str
    address: int
    length: int | None
    section: str | None
    kind: str
    has_slice: bool
    slice_path: str | None
    has_scaffold: bool
    has_curated: bool
    has_semantic: bool
    has_ir: bool
    src_dir: str
    status: str  # missing_slice | not_lifted | scaffold | curated | semantic_draft


@dataclass
class ProjectSummary:
    root: str
    name: str
    arch_default: str
    functions_total: int
    with_slice: int
    scaffolded: int
    curated: int
    semantic_drafts: int
    slices_on_disk: int
    has_symbols: bool
    has_disasm: bool
    has_src: bool
    config_present: bool


def src_dir_for_section(section: str | None) -> Path:
    s = section or ""
    if "boot" in s:
        return Path("src/boot")
    if s == "irq_infrastructure":
        return Path("src/irq")
    if s in ("game_logic_core", "game_logic_geo_core", "game_logic_extended"):
        return Path("src/game")
    return Path("src/libc")


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _status_for(row: FunctionRow) -> str:
    if not row.has_slice:
        return "missing_slice"
    if row.has_curated:
        return "curated"
    if row.has_semantic:
        return "semantic_draft"
    if row.has_scaffold or row.has_ir:
        return "scaffold"
    return "not_lifted"


def _slice_index() -> dict[int, list[tuple[int, Path]]]:
    """address -> [(length, path), ...] sorted by length."""
    disasm = resolve_in_repo(Path("disasm/maincpu"))
    index: dict[int, list[tuple[int, Path]]] = {}
    if not disasm.is_dir():
        return index
    for path in disasm.glob("maincpu_*.asm"):
        match = _SLICE_RE.match(path.name)
        if not match:
            continue
        addr = int(match.group(1), 16)
        length = int(match.group(2), 16)
        index.setdefault(addr, []).append((length, path))
    for addr in index:
        index[addr].sort(key=lambda t: t[0])
    return index


def find_slice(
    address: int,
    length: int | None = None,
    *,
    index: dict[int, list[tuple[int, Path]]] | None = None,
) -> Path | None:
    idx = index if index is not None else _slice_index()
    entries = idx.get(address) or []
    if not entries:
        return None
    if length is not None:
        for ln, path in entries:
            if ln == length:
                return path
        return None
    return entries[-1][1]


def list_slices() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for addr, entries in sorted(_slice_index().items()):
        for length, path in entries:
            rows.append(
                {
                    "path": str(path.relative_to(project_root())),
                    "address": addr,
                    "length": length,
                }
            )
    return rows


def inventory_functions() -> list[FunctionRow]:
    root = project_root()
    yaml_path = resolve_in_repo(Path("symbols/functions.yaml"))
    slices = _slice_index()
    rows_out: list[FunctionRow] = []
    for raw in load_functions_yaml(yaml_path):
        name = str(raw.get("name", ""))
        if not name:
            continue
        addr = _parse_int(raw.get("address"))
        if addr is None:
            continue
        length = _parse_int(raw.get("length"))
        section = str(raw["section"]) if raw.get("section") else None
        kind = str(raw.get("kind") or "code")
        slice_path = find_slice(addr, length, index=slices)
        src = src_dir_for_section(section)
        scaffold = resolve_in_repo(src / f"{name}.lifted.c")
        curated = resolve_in_repo(src / f"{name}.c")
        semantic = resolve_in_repo(src / f"{name}.semantic.c")
        ir = resolve_in_repo(Path("out/lift") / f"{name}.ir.json")
        row = FunctionRow(
            name=name,
            address=addr,
            length=length,
            section=section,
            kind=kind,
            has_slice=slice_path is not None,
            slice_path=str(slice_path.relative_to(root)) if slice_path else None,
            has_scaffold=scaffold.is_file(),
            has_curated=curated.is_file(),
            has_semantic=semantic.is_file(),
            has_ir=ir.is_file(),
            src_dir=str(src),
            status="",
        )
        row.status = _status_for(row)
        rows_out.append(row)
    rows_out.sort(key=lambda r: (r.address, r.name))
    return rows_out


def project_summary() -> ProjectSummary:
    root = project_root()
    fns = inventory_functions()
    slices = list_slices()
    config = root / CONFIG_NAME
    name = root.name
    if config.is_file():
        try:
            import yaml

            data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict) and data.get("name"):
                name = str(data["name"])
        except Exception:  # noqa: BLE001
            pass
    return ProjectSummary(
        root=str(root),
        name=name,
        arch_default="i960",
        functions_total=len(fns),
        with_slice=sum(1 for f in fns if f.has_slice),
        scaffolded=sum(1 for f in fns if f.has_scaffold or f.has_ir),
        curated=sum(1 for f in fns if f.has_curated),
        semantic_drafts=sum(1 for f in fns if f.has_semantic),
        slices_on_disk=len(slices),
        has_symbols=(root / "symbols" / "functions.yaml").is_file(),
        has_disasm=(root / "disasm" / "maincpu").is_dir(),
        has_src=(root / "src").is_dir(),
        config_present=config.is_file(),
    )


def function_detail(name: str) -> dict[str, Any]:
    rows = [r for r in inventory_functions() if r.name == name]
    if not rows:
        raise KeyError(f"unknown function {name!r}")
    row = rows[0]
    src = Path(row.src_dir)
    paths = {
        "scaffold": resolve_in_repo(src / f"{name}.lifted.c"),
        "curated": resolve_in_repo(src / f"{name}.c"),
        "semantic": resolve_in_repo(src / f"{name}.semantic.c"),
        "ir": resolve_in_repo(Path("out/lift") / f"{name}.ir.json"),
        "lifted": resolve_in_repo(Path("out/lift") / f"{name}.lifted"),
        "slice": resolve_in_repo(Path(row.slice_path)) if row.slice_path else None,
    }
    texts: dict[str, str | None] = {}
    for key, path in paths.items():
        if path is None or not path.is_file():
            texts[key] = None
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        texts[key] = raw if len(raw) < 200_000 else raw[:200_000] + "\n/* … truncated */\n"
    return {
        "function": asdict(row),
        "paths": {k: (str(v) if v else None) for k, v in paths.items()},
        "texts": texts,
    }


def init_project(root: Path, *, name: str | None = None, arch: str = "i960") -> dict[str, Any]:
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    for rel in (
        "symbols",
        "disasm/maincpu",
        "src/libc",
        "src/boot",
        "src/game",
        "src/irq",
        "out/lift",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    sym = root / "symbols" / "functions.yaml"
    if not sym.is_file():
        sym.write_text("functions: []\n", encoding="utf-8")
    cfg = root / CONFIG_NAME
    if not cfg.is_file():
        cfg.write_text(
            f"name: {name or root.name}\narch_default: {arch}\ncreated: {datetime.now(timezone.utc).isoformat()}\n",
            encoding="utf-8",
        )
    set_project_root(root)
    remember_project(root)
    return asdict(project_summary())


def remember_project(root: Path) -> None:
    root = root.resolve()
    RECENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    recent: list[str] = []
    if RECENT_PATH.is_file():
        try:
            recent = list(json.loads(RECENT_PATH.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            recent = []
    s = str(root)
    recent = [s] + [p for p in recent if p != s]
    RECENT_PATH.write_text(json.dumps(recent[:12], indent=2) + "\n", encoding="utf-8")


def recent_projects() -> list[dict[str, Any]]:
    if not RECENT_PATH.is_file():
        return []
    try:
        paths = list(json.loads(RECENT_PATH.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []
    for p in paths:
        path = Path(p)
        out.append({"path": p, "exists": path.is_dir(), "name": path.name})
    return out


def open_project(root: Path) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"project path not found: {root}")
    set_project_root(root)
    remember_project(root)
    return asdict(project_summary())


def scan_rom_annotations() -> list[dict[str, Any]]:
    """Find // @rom markers under src/ for coverage reporting."""
    src = resolve_in_repo(Path("src"))
    hits: list[dict[str, Any]] = []
    if not src.is_dir():
        return hits
    for path in src.rglob("*.c"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _ROM_RE.finditer(text):
            hits.append(
                {
                    "file": str(path.relative_to(project_root())),
                    "address": int(m.group(1), 16),
                    "length": int(m.group(2), 16),
                    "name": m.group(3),
                }
            )
    return hits
