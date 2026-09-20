#!/usr/bin/env python3
"""Export Ghidra decompiler JSON into decomp/src/ C scaffold files."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from tools.decomp.ghidra_simplify_ac import simplify_ghidra_ac

GHIDRA_SCAFFOLD_H = """\
/* Ghidra decompiler scaffold types — NOT build-ready; hand-edit before i960-elf-gcc.
 * Generated/updated by tools.decomp.ghidra_export_c — do not treat as final C port.
 */
#ifndef GHIDRA_SCAFFOLD_H
#define GHIDRA_SCAFFOLD_H

typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef void (*code)(void);

extern volatile unsigned int ac;
extern void *g14;
extern void *g13;
extern unsigned int fp;

#define CONCAT44(hi, lo) (((unsigned long)(hi) << 32) | (unsigned long)(lo))

#endif
"""

SAFE_NAME = re.compile(r"[^A-Za-z0-9_]+")


def decomp_root(repo_root: Path) -> Path:
    root = repo_root.resolve()
    if (root / "disasm").is_dir():
        return root
    return root / "decomp"


def load_functions_by_entry(functions_yaml: Path) -> dict[int, str]:
    if not functions_yaml.is_file():
        return {}
    try:
        import yaml
    except ImportError:
        yaml = None  # type: ignore
    text = functions_yaml.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if yaml is not None else json.loads(text)
    out: dict[int, str] = {}
    for fn in (data or {}).get("functions") or []:
        addr = int(fn["address"], 16) if isinstance(fn["address"], str) else int(fn["address"])
        out[addr] = str(fn["name"])
    return out


def safe_filename(name: str) -> str:
    cleaned = SAFE_NAME.sub("_", name).strip("_").lower()
    return cleaned or "unnamed"


def pick_c_source(row: dict) -> str | None:
    c = row.get("c")
    if isinstance(c, str) and c.strip():
        return c.lstrip("\n")
    preview = row.get("c_preview")
    if isinstance(preview, str) and preview.strip() and not preview.endswith("(*UNRECOVERED"):
        return preview.lstrip("\n")
    return None


def load_ghidra_rows(json_path: Path) -> list[dict]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        raw_path = json_path.with_suffix(".raw.json")
        if raw_path.is_file():
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                return raw
        functions = data.get("functions") or []
        if functions and any(isinstance(f.get("c"), str) for f in functions):
            return functions
        raise ValueError(
            f"{json_path} has no embedded C bodies; expected companion {raw_path.name}"
        )
    raise ValueError(f"unexpected Ghidra JSON shape: {json_path}")


def export_function_file(
    *,
    row: dict,
    dest: Path,
    symbol: str,
    slice_label: str,
    ghidra_name: str,
) -> dict | None:
    entry = int(str(row["entry"]), 16)
    size = int(row.get("size") or 0)
    end = entry + size if size > 0 else entry
    c_src = pick_c_source(row)
    if c_src is None:
        return None

    c_src, ac_simplified = simplify_ghidra_ac(c_src)

    lines = [
        "/* Ghidra decompiler scaffold — edit before attempting i960-elf-gcc. */",
        f"/* slice: {slice_label}  ghidra: {ghidra_name}  class: {row.get('class', 'unknown')} */",
        f"// @rom 0x{entry:06x} 0x{end:06x} {symbol}",
        "",
        '#include "ghidra_scaffold.h"',
        "",
        c_src.rstrip(),
        "",
    ]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines), encoding="utf-8")
    return {
        "file": str(dest.name),
        "entry": f"0x{entry:06x}",
        "end": f"0x{end:06x}",
        "symbol": symbol,
        "ghidra_name": ghidra_name,
        "warning_score": row.get("warning_score"),
        "decompiled": row.get("decompiled", True),
        "ac_simplified": ac_simplified,
    }


def export_ghidra_json(
    json_path: Path,
    *,
    repo_root: Path,
    slice_label: str | None = None,
    out_dir: Path | None = None,
) -> dict:
    json_path = json_path.resolve()
    if not json_path.is_file():
        raise FileNotFoundError(json_path)

    root = decomp_root(repo_root)
    label = slice_label or json_path.stem.replace(".raw", "")
    dest_root = out_dir or (root / "src" / "ghidra" / label)
    dest_root = dest_root.resolve()

    symbols = load_functions_by_entry(root / "symbols/functions.yaml")
    rows = load_ghidra_rows(json_path)

    scaffold_h = root / "src/ghidra_scaffold.h"
    scaffold_h.parent.mkdir(parents=True, exist_ok=True)
    if not scaffold_h.is_file():
        scaffold_h.write_text(GHIDRA_SCAFFOLD_H, encoding="utf-8")

    exported: list[dict] = []
    skipped: list[dict] = []
    used_names: set[str] = set()

    for row in rows:
        entry = int(str(row["entry"]), 16)
        ghidra_name = str(row.get("name") or f"FUN_{entry:08x}")
        symbol = symbols.get(entry, ghidra_name)
        base = safe_filename(symbol)
        fname = base
        n = 2
        while fname in used_names:
            fname = f"{base}_{n}"
            n += 1
        used_names.add(fname)

        out_file = dest_root / f"{fname}.c"
        meta = export_function_file(
            row=row,
            dest=out_file,
            symbol=symbol,
            slice_label=label,
            ghidra_name=ghidra_name,
        )
        if meta is None:
            skipped.append({"entry": row.get("entry"), "name": ghidra_name, "reason": "no_c_body"})
        else:
            meta["path"] = str(out_file.relative_to(root))
            exported.append(meta)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_json": str(json_path),
        "slice": label,
        "dest_dir": str(dest_root.relative_to(root)),
        "exported": exported,
        "skipped": skipped,
        "scaffold_header": str(scaffold_h.relative_to(root)),
    }
    manifest_path = dest_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Export Ghidra JSON decompile output to decomp/src/")
    ap.add_argument(
        "json",
        type=Path,
        help="out/decomp/ghidra/<slice>.json or .raw.json",
    )
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--slice", default=None, help="subdir label under src/ghidra/ (default: json stem)")
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()

    manifest = export_ghidra_json(
        args.json,
        repo_root=args.repo_root.resolve(),
        slice_label=args.slice,
        out_dir=args.out_dir,
    )
    print(
        f"Exported {len(manifest['exported'])} function(s) → {manifest['dest_dir']}/ "
        f"({len(manifest['skipped'])} skipped)"
    )
    if manifest["exported"]:
        for row in manifest["exported"]:
            print(f"  {row['file']}  {row['entry']} {row['symbol']}")


if __name__ == "__main__":
    main()
