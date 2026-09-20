"""ROM layout schema: generate, merge overlays, read/write YAML."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from tools.i960_memory import MAINCPU_SIZE, MAIN_DATA_A

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

LAYOUT_VERSION = 1
COARSE_CHUNK = 0x10_0000  # 1 MiB bands for main_data fill


def _hex_int(value: int | str) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _yaml_parse_scalar(token: str) -> Any:
    token = token.strip()
    if token == "" or token in ("null", "~", "None"):
        return None
    if token in ("true", "True", "yes"):
        return True
    if token in ("false", "False", "no"):
        return False
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    if token.startswith("0x") or token.startswith("0X"):
        return int(token, 16)
    try:
        if any(c in token for c in ".eE") and token.replace(".", "", 1).replace("-", "", 1).replace("e", "", 1).replace("E", "", 1).replace("+", "", 1).isdigit():
            return float(token)
        return int(token)
    except ValueError:
        return token


def _yaml_split_flow(inner: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch in "{[":
            depth += 1
            buf.append(ch)
            continue
        if ch in "}]":
            depth -= 1
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    part = "".join(buf).strip()
    if part:
        parts.append(part)
    return parts


def _yaml_parse_flow(token: str) -> Any:
    token = token.strip()
    if token.startswith("{") and token.endswith("}"):
        out: dict[str, Any] = {}
        for part in _yaml_split_flow(token[1:-1]):
            if ":" not in part:
                continue
            key, val = part.split(":", 1)
            out[key.strip()] = _yaml_parse_flow(val.strip())
        return out
    if token.startswith("[") and token.endswith("]"):
        return [_yaml_parse_flow(p) for p in _yaml_split_flow(token[1:-1])]
    return _yaml_parse_scalar(token)


def _yaml_strip_comment(line: str) -> str:
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


def _load_yaml_subset(text: str) -> Any:
    """Minimal YAML loader for this repo (flow maps, indented maps/lists)."""
    raw_lines = [_yaml_strip_comment(line) for line in text.splitlines()]
    lines = [(len(line) - len(line.lstrip(" ")), line.strip()) for line in raw_lines]
    lines = [(ind, body) for ind, body in lines if body]

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        mapping: dict[str, Any] = {}
        sequence: list[Any] | None = None
        n = len(lines)
        while index < n:
            ind, body = lines[index]
            if ind < indent:
                break
            if ind > indent:
                if sequence is not None and (body.startswith("- ") or body == "-"):
                    ind = indent
                else:
                    raise ValueError(f"unexpected indent at YAML line {body!r}")
            if body.startswith("- ") or body == "-":
                if mapping:
                    raise ValueError("mixed YAML mapping/list")
                if sequence is None:
                    sequence = []
                item = "" if body == "-" else body[2:].strip()
                index += 1
                child_indent = indent + 2
                if not item:
                    child, index = parse_block(index, child_indent)
                    sequence.append(child)
                    continue
                if item.startswith("{") or item.startswith("["):
                    sequence.append(_yaml_parse_flow(item))
                    continue
                if ":" in item:
                    key, rest = item.split(":", 1)
                    entry: dict[str, Any] = {
                        key.strip(): _yaml_parse_flow(rest.strip()) if rest.strip() else None
                    }
                    while index < n:
                        nind, nbody = lines[index]
                        if nind < child_indent or nbody.startswith("-"):
                            break
                        if nind != child_indent:
                            break
                        if ":" not in nbody:
                            break
                        nkey, nrest = nbody.split(":", 1)
                        index += 1
                        nrest = nrest.strip()
                        if nrest:
                            entry[nkey.strip()] = _yaml_parse_flow(nrest)
                        elif index < n and lines[index][0] > child_indent:
                            nested, index = parse_block(index, lines[index][0])
                            entry[nkey.strip()] = nested
                        else:
                            entry[nkey.strip()] = None
                    sequence.append(entry)
                    continue
                sequence.append(_yaml_parse_scalar(item))
                continue
            if sequence is not None:
                break
            if ":" not in body:
                raise ValueError(f"YAML mapping line without colon: {body!r}")
            key, rest = body.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            index += 1
            if rest:
                mapping[key] = _yaml_parse_flow(rest)
                continue
            if index < n and lines[index][0] > indent:
                child, index = parse_block(index, lines[index][0])
                mapping[key] = child
            else:
                mapping[key] = None
        if sequence is not None:
            return sequence, index
        return mapping, index

    if not lines:
        return {}
    data, _ = parse_block(0, lines[0][0])
    return data


def load_yaml_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        data = _load_yaml_subset(text)
        return data if isinstance(data, dict) else {}


def dump_yaml_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if yaml is not None:
        path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def section_dict(
    name: str,
    start: int,
    end: int,
    file_rel: str,
    *,
    fill: int | None = None,
    kind: str = "blob",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "start": f"0x{start:08x}",
        "end": f"0x{end:08x}",
        "file": file_rel,
        "kind": kind,
    }
    if fill is not None:
        row["fill"] = fill
    return row


def maincpu_sections_from_map(section_map: dict[str, Any], decomp_root: Path) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for region in section_map.get("regions", []):
        start = _hex_int(region["start"])
        end = _hex_int(region["end"])
        name = region["name"]
        fill = 0xFF if name == "erase_fill" else None
        rel = f"maincpu/sections/{name}.bin"
        sections.append(section_dict(name, start, end, rel, fill=fill))
    return sections


def partition_ranges(
    image_size: int,
    base_vaddr: int,
    semantic: list[tuple[str, int, int]],
) -> list[tuple[str, int, int]]:
    """Carve disjoint semantic file ranges, fill gaps with coarse chunks."""
    file_semantic: list[tuple[str, int, int]] = []
    for name, vstart, vend in semantic:
        fstart = vstart - base_vaddr
        fend = vend - base_vaddr
        if fstart < 0 or fend > image_size or fstart >= fend:
            continue
        file_semantic.append((name, fstart, fend))
    file_semantic.sort(key=lambda x: x[1])

    disjoint: list[tuple[str, int, int]] = []
    for name, fstart, fend in file_semantic:
        if not disjoint:
            disjoint.append((name, fstart, fend))
            continue
        prev_name, ps, pe = disjoint[-1]
        if fstart < pe:
            disjoint[-1] = (f"{prev_name}__{name}", ps, max(pe, fend))
        else:
            disjoint.append((name, fstart, fend))

    gaps: list[tuple[int, int]] = []
    cursor = 0
    for _name, start, end in disjoint:
        if cursor < start:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < image_size:
        gaps.append((cursor, image_size))

    out = list(disjoint)
    chunk_idx = 0
    for gstart, gend in gaps:
        pos = gstart
        while pos < gend:
            chunk_end = min(pos + COARSE_CHUNK, gend)
            out.append((f"main_data_{chunk_idx:02d}", pos, chunk_end))
            chunk_idx += 1
            pos = chunk_end
    out.sort(key=lambda x: x[1])
    return out


def main_data_sections_from_map(section_map: dict[str, Any], decomp_root: Path) -> list[dict[str, Any]]:
    image_size = _hex_int(section_map.get("rom_bytes", 0xC00000))
    semantic: list[tuple[str, int, int]] = []
    for region in section_map.get("regions", []):
        semantic.append(
            (
                region["name"],
                _hex_int(region["start"]),
                _hex_int(region["end"]),
            )
        )
    sections: list[dict[str, Any]] = []
    for name, fstart, fend in partition_ranges(image_size, MAIN_DATA_A, semantic):
        rel = f"main_data/sections/{name}.bin"
        sections.append(section_dict(name, MAIN_DATA_A + fstart, MAIN_DATA_A + fend, rel))
    return sections


def generate_layout(
    maincpu_map: dict[str, Any],
    main_data_map: dict[str, Any],
    *,
    fill_start: int | None = None,
) -> dict[str, Any]:
    maincpu_sections = maincpu_sections_from_map(maincpu_map, Path("decomp"))
    if fill_start is not None:
        for sec in maincpu_sections:
            if sec["name"] == "erase_fill":
                sec["start"] = f"0x{fill_start:08x}"
                sec["fill"] = 0xFF

    return {
        "version": LAYOUT_VERSION,
        "images": {
            "maincpu": {
                "base": "0x00000000",
                "size": f"0x{MAINCPU_SIZE:08x}",
                "reference": "out/i960/maincpu_deinterleaved.bin",
                "sections": maincpu_sections,
            },
            "main_data": {
                "base": f"0x{MAIN_DATA_A:08x}",
                "size": f"0x{main_data_map.get('rom_bytes', 0xC00000):08x}",
                "reference": "out/decomp/main_data_deinterleaved.bin",
                "sections": main_data_sections_from_map(main_data_map, Path("decomp")),
            },
        },
    }


def merge_layout(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Overlay wins per-image and per-section name."""
    merged = deepcopy(base)
    if not overlay:
        return merged
    for image_name, image_overlay in overlay.get("images", {}).items():
        if image_name not in merged.setdefault("images", {}):
            merged["images"][image_name] = deepcopy(image_overlay)
            continue
        target = merged["images"][image_name]
        for key, value in image_overlay.items():
            if key != "sections":
                target[key] = value
        overlay_sections = {s["name"]: s for s in image_overlay.get("sections", [])}
        if overlay_sections:
            by_name = {s["name"]: s for s in target.get("sections", [])}
            by_name.update(overlay_sections)
            target["sections"] = sorted(by_name.values(), key=lambda s: _hex_int(s["start"]))
    return merged


def load_layout(
    decomp_root: Path,
    *,
    maincpu_map_path: Path,
    main_data_map_path: Path,
    generated_path: Path | None = None,
) -> dict[str, Any]:
    gen_path = generated_path or (decomp_root.parent / "out/decomp/layout.generated.yaml")
    if gen_path.is_file():
        layout = load_yaml_file(gen_path)
    else:
        maincpu_map = json.loads(maincpu_map_path.read_text(encoding="utf-8"))
        main_data_map = json.loads(main_data_map_path.read_text(encoding="utf-8"))
        fill_start = _hex_int(maincpu_map.get("fill_start", "0x0bd568"))
        layout = generate_layout(maincpu_map, main_data_map, fill_start=fill_start)

    overlay_path = decomp_root / "layout.overlay.yaml"
    if overlay_path.is_file():
        layout = merge_layout(layout, load_yaml_file(overlay_path))
    return layout


def write_layout_outputs(layout: dict[str, Any], decomp_root: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    dump_yaml_file(out_dir / "layout.generated.yaml", layout)


def iter_image_sections(layout: dict[str, Any], image_name: str) -> list[dict[str, Any]]:
    return list(layout.get("images", {}).get(image_name, {}).get("sections", []))


def section_bounds(section: dict[str, Any]) -> tuple[int, int]:
    return _hex_int(section["start"]), _hex_int(section["end"])
