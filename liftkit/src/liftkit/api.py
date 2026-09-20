"""Public library API for liftkit."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from liftkit.arch.base import get_arch, list_arches
from liftkit.arch.i960.disasm_parse import parse_slice_name
from liftkit.arch.i960.symbol_kind import default_src_dir
from liftkit.project.workspace import project_root, resolve_in_repo, set_project_root
from liftkit.rewrite.provider import RewriteContext, RewriteResult, get_provider


@dataclass
class LiftResult:
    name: str
    arch: str
    addr: int
    length: int
    kind: str
    scaffold_c: str
    lifted_text: str
    report: dict[str, Any] = field(default_factory=dict)
    ir_json: dict[str, Any] | None = None


def _default_name(slice_path: Path) -> str:
    parsed = parse_slice_name(slice_path)
    if parsed:
        from liftkit.arch.i960.export_symbols import load_functions_yaml

        addr, _length = parsed
        for row in load_functions_yaml(resolve_in_repo(Path("symbols/functions.yaml"))):
            if int(row.get("address", -1)) == addr:
                return str(row["name"])
        return f"fn_{addr:06x}"
    return slice_path.stem


def _parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 0)


def find_slice_for_address(address: int, length: int | None = None) -> Path | None:
    """Locate disasm/maincpu/maincpu_<addr>_<len>.asm under the project."""
    disasm = resolve_in_repo(Path("disasm/maincpu"))
    if not disasm.is_dir():
        return None
    prefix = f"maincpu_{address:06x}_"
    matches = sorted(disasm.glob(f"{prefix}*.asm"))
    if length is not None:
        exact = disasm / f"maincpu_{address:06x}_{length:x}.asm"
        if exact.is_file():
            return exact
        # Also try zero-padded length variants used in corpus
        for m in matches:
            parsed = parse_slice_name(m)
            if parsed and parsed[1] == length:
                return m
    if matches:
        if length is None:
            return matches[-1]  # prefer longest slice name lexicographically last often longer
        return None
    return None


def lookup_function(name: str) -> dict[str, Any]:
    from liftkit.arch.i960.export_symbols import load_functions_yaml

    path = resolve_in_repo(Path("symbols/functions.yaml"))
    rows = load_functions_yaml(path)
    matches = [row for row in rows if str(row.get("name", "")) == name]
    if not matches:
        raise KeyError(f"unknown function {name!r} in {path}")
    if len(matches) > 1:
        raise KeyError(f"ambiguous function name {name!r}")
    return matches[0]


def lift_function(
    name: str,
    *,
    arch: str = "i960",
    project: Path | str | None = None,
    out_dir: Path | str = "out/lift",
    src_dir: Path | str | None = None,
    emit_wasm: bool = False,
    length: int | None = None,
) -> LiftResult:
    """Resolve symbols/functions.yaml name → existing disasm slice → lift."""
    if project is not None:
        set_project_root(Path(project))
    row = lookup_function(name)
    addr = int(row["address"], 0) if isinstance(row["address"], str) else int(row["address"])
    yaml_len = row.get("length")
    if length is None and yaml_len is not None:
        length = int(yaml_len, 0) if isinstance(yaml_len, str) else int(yaml_len)
    slice_path = find_slice_for_address(addr, length)
    if slice_path is None:
        raise FileNotFoundError(
            f"no disasm slice for {name} @ 0x{addr:x}"
            + (f"+0x{length:x}" if length is not None else "")
            + f" under {resolve_in_repo(Path('disasm/maincpu'))}"
        )
    return lift_slice(
        slice_path,
        arch=arch,
        name=name,
        out_dir=out_dir,
        src_dir=src_dir,
        emit_wasm=emit_wasm,
        write=True,
    )


def lift_slice(
    slice_path: Path | str,
    *,
    arch: str = "i960",
    name: str | None = None,
    project: Path | str | None = None,
    out_dir: Path | str = "out/lift",
    src_dir: Path | str | None = None,
    emit_wasm: bool = False,
    write: bool = True,
) -> LiftResult:
    if project is not None:
        set_project_root(Path(project))

    plugin = get_arch(arch)
    path = resolve_in_repo(Path(slice_path))
    parsed = plugin.parse_slice(path)
    fn_name = name or _default_name(path)
    artifacts = plugin.lift(parsed, name=fn_name)

    report: dict[str, Any] = {
        "name": artifacts.name,
        "arch": artifacts.arch,
        "slice": str(path),
        "kind": artifacts.kind,
        "addr": f"0x{artifacts.addr:x}",
        "length": artifacts.length,
        "outputs": {},
    }

    if write:
        if arch == "i960":
            from liftkit.arch.i960 import write_lift_outputs

            dest_src = Path(src_dir) if src_dir else default_src_dir(fn_name)
            report = write_lift_outputs(
                artifacts,
                out_dir=Path(out_dir),
                src_dir=dest_src,
                slice_path=path,
                emit_wasm=emit_wasm,
            )
        else:
            out = resolve_in_repo(Path(out_dir))
            out.mkdir(parents=True, exist_ok=True)
            c_path = out / f"{fn_name}.lifted.c"
            c_path.write_text(artifacts.scaffold_c, encoding="utf-8")
            report["outputs"] = {"scaffold_c": str(c_path)}

    ir_json = None
    if artifacts.ir is not None and hasattr(artifacts.ir, "__dataclass_fields__"):
        ir_path = resolve_in_repo(Path(out_dir)) / f"{fn_name}.ir.json"
        if ir_path.is_file():
            ir_json = json.loads(ir_path.read_text(encoding="utf-8"))

    return LiftResult(
        name=artifacts.name,
        arch=artifacts.arch,
        addr=artifacts.addr,
        length=artifacts.length,
        kind=artifacts.kind,
        scaffold_c=artifacts.scaffold_c,
        lifted_text=artifacts.lifted_text,
        report=report,
        ir_json=ir_json,
    )


def lift_address(
    address: str | int,
    length: str | int,
    *,
    arch: str = "i960",
    name: str | None = None,
    project: Path | str | None = None,
    out_dir: Path | str = "out/lift",
    src_dir: Path | str | None = None,
    emit_wasm: bool = False,
) -> LiftResult:
    """Lift by address+length using an existing disasm slice (must already exist)."""
    if project is not None:
        set_project_root(Path(project))
    addr = _parse_int(address)
    ln = _parse_int(length)
    slice_path = find_slice_for_address(addr, ln)
    if slice_path is None:
        raise FileNotFoundError(
            f"no disasm slice for 0x{addr:x}+0x{ln:x} under {resolve_in_repo(Path('disasm/maincpu'))}; "
            "generate with MAME dasm first (liftkit disasm)"
        )
    return lift_slice(
        slice_path,
        arch=arch,
        name=name,
        out_dir=out_dir,
        src_dir=src_dir,
        emit_wasm=emit_wasm,
        write=True,
    )


def rewrite_function(
    name: str,
    *,
    arch: str = "i960",
    project: Path | str | None = None,
    provider: str | None = None,
    apply: bool = False,
) -> RewriteResult:
    """AI semantic rewrite from IR + scaffold (requires API key for live providers)."""
    if project is not None:
        set_project_root(Path(project))

    out_dir = resolve_in_repo(Path("out/lift"))
    src_guess = default_src_dir(name) if arch == "i960" else Path("src")
    scaffold = resolve_in_repo(src_guess / f"{name}.lifted.c")
    if not scaffold.is_file():
        scaffold = resolve_in_repo(src_guess / f"{name}.c")
    ir_path = out_dir / f"{name}.ir.json"
    lifted = out_dir / f"{name}.lifted"

    if not scaffold.is_file():
        raise FileNotFoundError(f"missing scaffold C for {name}: run lift first ({scaffold})")

    ir_json = None
    if ir_path.is_file():
        ir_json = json.loads(ir_path.read_text(encoding="utf-8"))
    else:
        raise FileNotFoundError(
            f"missing IR for {name} ({ir_path}); AI rewrite requires a successful deterministic lift"
        )

    asm_text = ""
    # Best-effort: find matching slice from addr in IR
    addr = None
    if isinstance(ir_json, dict):
        addr_s = ir_json.get("addr") or ir_json.get("entry") or ir_json.get("base")
        if addr_s is not None:
            try:
                addr = int(addr_s, 0) if isinstance(addr_s, str) else int(addr_s)
            except (TypeError, ValueError):
                addr = None
    if addr is not None:
        sp = find_slice_for_address(addr)
        if sp and sp.is_file():
            asm_text = sp.read_text(encoding="utf-8")

    ctx = RewriteContext(
        arch=arch,
        name=name,
        addr=addr,
        ir_json=ir_json,
        scaffold_c=scaffold.read_text(encoding="utf-8"),
        asm_text=asm_text,
        lifted_text=lifted.read_text(encoding="utf-8") if lifted.is_file() else "",
        symbols_excerpt=_symbols_excerpt(name),
        runtime_header_excerpt=_runtime_excerpt(arch),
    )
    result = get_provider(provider).rewrite(ctx)

    draft = resolve_in_repo(src_guess / f"{name}.semantic.c")
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(result.c_text, encoding="utf-8")
    result.draft_path = str(draft)

    if apply:
        curated = resolve_in_repo(src_guess / f"{name}.c")
        curated.write_text(result.c_text, encoding="utf-8")
        result.applied_path = str(curated)

    return result


def _symbols_excerpt(name: str, limit: int = 40) -> str:
    path = resolve_in_repo(Path("symbols/functions.yaml"))
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8")
    # Keep it small: include the target name line neighborhood + head
    lines = text.splitlines()
    hits = [i for i, ln in enumerate(lines) if name in ln]
    chunks: list[str] = []
    if hits:
        i = hits[0]
        chunks.extend(lines[max(0, i - 5) : i + 15])
    chunks.extend(lines[:limit])
    return "\n".join(chunks[: limit + 20])


def _runtime_excerpt(arch: str, max_chars: int = 4000) -> str:
    plugin = get_arch(arch)
    hdr = plugin.runtime_header()
    if not hdr or not hdr.is_file():
        return ""
    return hdr.read_text(encoding="utf-8")[:max_chars]


def available_arches() -> list[str]:
    return list_arches()
