"""Local web UI for tagging atlas regions on logical texture sheets.

Start the server, then open http://127.0.0.1:8765/

  python3 -m tools.extract.atlas_tagger

Requires logical sheet PNGs (generated on first request if missing).
"""

from __future__ import annotations

import argparse
import io
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import numpy as np
from PIL import Image

from tools.extract.atlas_catalog import (
    DEFAULT_AUDIT_PATH,
    DEFAULT_CATALOG,
    REPO_ROOT,
    catalog_audit_index_from_report,
    load_catalog,
    load_catalog_audit_index,
)
from tools.extract.texture_verify import _decode_patch_rgba
from tools.extract.textures import decode_logical_sheet, load_sheet_banks_from_main_data
from tools.i960_memory import TEXTURE_SHEET_BANK0_VADDR, TEXTURE_SHEET_BANK1_VADDR
from tools.model2_palette import PaletteState, load_palette_from_main_data
from tools.rom_io import SRALLY_DATA_ROMS, load32_word_region, load_maincpu, resolve_rom_dir

TAGGER_DIR = REPO_ROOT / "catalog" / "atlas_tagger"
PROBE_DIR = REPO_ROOT / "out" / "textures" / "main_data_probe"
BANK_PROBE_NAMES = (
    "bank_02200000_logical.png",
    "bank_02400000_logical.png",
)
BANK_VADDRS = (TEXTURE_SHEET_BANK0_VADDR, TEXTURE_SHEET_BANK1_VADDR)

_SHEET_CACHE: dict[str, tuple[tuple[list[int], list[int]], PaletteState]] = {}


def _load_sheets_and_palette(rom_dir: Path, course_id: str) -> tuple[tuple[list[int], list[int]], PaletteState]:
    key = f"{rom_dir.resolve()}:{course_id}"
    cached = _SHEET_CACHE.get(key)
    if cached is not None:
        return cached
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    sheets = load_sheet_banks_from_main_data(main_data, load_maincpu(rom_dir), course_id)
    palette = load_palette_from_main_data(main_data, course_id=course_id)
    cached = (sheets, palette)
    _SHEET_CACHE[key] = cached
    return cached


def _region_palette_patch(region: dict) -> dict[str, object] | None:
    cb = region.get("colorbase")
    if cb is None:
        return None
    return {
        "x": int(region["x"]),
        "y": int(region["y"]),
        "w": int(region["w"]),
        "h": int(region["h"]),
        "colorbase": int(cb),
        "lumabase": int(region.get("lumabase") or 0),
        "cutout": bool(region.get("cutout")),
        "checker": bool(region.get("checker")),
    }


def render_palette_composite(
    sheet: list[int],
    palette: PaletteState,
    regions: list[dict],
    *,
    overlay: dict | None = None,
) -> np.ndarray:
    """Logical grayscale base with catalog regions tinted per colorbase/lumabase."""
    gray = decode_logical_sheet(sheet)
    rgba = np.zeros((*gray.shape, 4), dtype=np.uint8)
    rgba[..., 0] = gray
    rgba[..., 1] = gray
    rgba[..., 2] = gray
    rgba[..., 3] = 255

    def tint(patch: dict[str, object]) -> None:
        x, y, w, h = int(patch["x"]), int(patch["y"]), int(patch["w"]), int(patch["h"])
        rgba[y : y + h, x : x + w] = _decode_patch_rgba(sheet, palette, patch)

    for region in sorted(regions, key=lambda r: int(r["w"]) * int(r["h"]), reverse=True):
        patch = _region_palette_patch(region)
        if patch is not None:
            tint(patch)
    if overlay is not None:
        patch = _region_palette_patch(overlay)
        if patch is not None:
            tint(patch)
    return rgba


def _parse_overlay(query: dict[str, list[str]]) -> dict | None:
    def one(name: str) -> str | None:
        values = query.get(name)
        return values[0] if values else None

    cb = one("overlay_cb")
    if cb is None:
        return None
    try:
        return {
            "x": int(one("overlay_x") or "0"),
            "y": int(one("overlay_y") or "0"),
            "w": int(one("overlay_w") or "1"),
            "h": int(one("overlay_h") or "1"),
            "colorbase": int(cb),
            "lumabase": int(one("overlay_lb") or "0"),
            "cutout": (one("overlay_cutout") or "0") in ("1", "true", "yes"),
            "checker": (one("overlay_checker") or "0") in ("1", "true", "yes"),
        }
    except ValueError:
        return None


def _ensure_logical_pngs(rom_dir: Path) -> None:
    from tools.extract.textures import decode_logical_sheet

    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    main_data = load32_word_region(rom_dir, SRALLY_DATA_ROMS["main_data"])
    sheets = load_sheet_banks_from_main_data(main_data)
    for index, (name, sheet) in enumerate(zip(BANK_PROBE_NAMES, sheets)):
        path = PROBE_DIR / name
        if path.is_file():
            continue
        gray = decode_logical_sheet(sheet)
        Image.fromarray(gray).save(path)


class AtlasTaggerHandler(BaseHTTPRequestHandler):
    rom_dir: Path = REPO_ROOT
    catalog_path: Path = DEFAULT_CATALOG
    audit_path: Path = DEFAULT_AUDIT_PATH
    course_id: str = "desert"

    def log_message(self, fmt: str, *args) -> None:
        if str(args[1]) not in ("200", "304"):
            super().log_message(fmt, *args)

    def _send_json(self, payload: object, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/catalog":
            if not self.catalog_path.is_file():
                self._send_json({"version": 1, "banks": []}, HTTPStatus.NOT_FOUND)
                return
            self._send_bytes(
                self.catalog_path.read_bytes(),
                "application/json; charset=utf-8",
            )
            return

        if path == "/api/audit":
            self._send_json(load_catalog_audit_index(self.audit_path))
            return

        if path.startswith("/api/sheet/") and path.endswith("/logical.png"):
            part = path.split("/")[3]
            if part not in ("0", "1"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            index = int(part)
            _ensure_logical_pngs(self.rom_dir)
            png = (PROBE_DIR / BANK_PROBE_NAMES[index]).read_bytes()
            self._send_bytes(png, "image/png")
            return

        if path.startswith("/api/sheet/") and path.endswith("/palette.png"):
            part = path.split("/")[3]
            if part not in ("0", "1"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            index = int(part)
            catalog = load_catalog(self.catalog_path) if self.catalog_path.is_file() else {"banks": []}
            banks = catalog.get("banks", [])
            selected_only = (query.get("selected_only", ["0"])[0] in ("1", "true", "yes"))
            if selected_only or index >= len(banks):
                regions: list[dict] = []
            else:
                regions = banks[index].get("regions", [])
            sheets, palette = _load_sheets_and_palette(self.rom_dir, self.course_id)
            overlay = _parse_overlay(query)
            rgba = render_palette_composite(
                sheets[index],
                palette,
                regions,
                overlay=overlay,
            )
            buf = io.BytesIO()
            Image.fromarray(rgba).save(buf, format="PNG")
            self._send_bytes(buf.getvalue(), "image/png")
            return

        if path in ("/", "/index.html"):
            path = "/index.html"

        rel = unquote(path.lstrip("/"))
        file_path = (TAGGER_DIR / rel).resolve()
        if not str(file_path).startswith(str(TAGGER_DIR.resolve())):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_types = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }
        self._send_bytes(file_path.read_bytes(), content_types.get(file_path.suffix, "application/octet-stream"))

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/audit/refresh":
            try:
                from tools.decomp.polygon_palette_audit import build_polygon_palette_audit

                build_polygon_palette_audit(
                    self.rom_dir,
                    self.audit_path.parent,
                    course_id=self.course_id,
                    catalog_path=self.catalog_path,
                )
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self._send_json({"ok": True, **load_catalog_audit_index(self.audit_path)})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/catalog":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            catalog = json.loads(self._read_body().decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return
        if not isinstance(catalog.get("banks"), list):
            self.send_error(HTTPStatus.BAD_REQUEST, "Missing banks array")
            return
        self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
        self.catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        self._send_json({"ok": True, "path": str(self.catalog_path.relative_to(REPO_ROOT))})


def main() -> None:
    parser = argparse.ArgumentParser(description="Atlas region tagging UI (local server)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--rom-dir", type=Path, default=None)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument(
        "--audit",
        type=Path,
        default=DEFAULT_AUDIT_PATH,
        help="polygon_palette_audit.json from tools.decomp.polygon_palette_audit",
    )
    parser.add_argument("--course", default="desert", help="Course palette for tinted preview")
    args = parser.parse_args()

    rom_dir = resolve_rom_dir(args.rom_dir)
    _ensure_logical_pngs(rom_dir)

    handler = AtlasTaggerHandler
    handler.rom_dir = rom_dir
    handler.catalog_path = args.catalog.resolve()
    handler.audit_path = args.audit.resolve()
    handler.course_id = args.course

    server = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/"
    audit_status = "loaded" if handler.audit_path.is_file() else "missing (run polygon-audit)"
    print(f"Atlas tagger at {url}")
    print(f"Catalog: {handler.catalog_path.relative_to(REPO_ROOT)}")
    print(f"Audit: {handler.audit_path.relative_to(REPO_ROOT)} ({audit_status})")
    print(f"Palette preview: {args.course} course (static ROM CGM)")
    print("Drag to select · Alt+drag pan · wheel zoom · Save writes JSON")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
