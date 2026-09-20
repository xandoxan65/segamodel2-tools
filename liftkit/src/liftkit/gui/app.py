"""FastAPI GUI backend — project management + lift/rewrite workbench."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from liftkit.api import available_arches, lift_address, lift_function, lift_slice, rewrite_function
from liftkit.project import catalog
from liftkit.project.workspace import set_project_root

_GUI_WEB = Path(__file__).resolve().parents[3] / "gui-web"
_GUI_DIST = _GUI_WEB / "dist"


def create_app(*, project: Path | None = None):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import FileResponse, HTMLResponse
        from fastapi.staticfiles import StaticFiles
        from pydantic import BaseModel
    except ImportError as exc:
        raise RuntimeError("pip install 'liftkit[gui]'") from exc

    if project is not None:
        set_project_root(project)
        catalog.remember_project(project)

    app = FastAPI(title="liftkit", version="0.1.0")

    class OpenBody(BaseModel):
        path: str

    class InitBody(BaseModel):
        path: str
        name: Optional[str] = None
        arch: str = "i960"

    class LiftBody(BaseModel):
        arch: str = "i960"
        slice: Optional[str] = None
        function: Optional[str] = None
        address: Optional[str] = None
        length: Optional[str] = None
        name: Optional[str] = None

    class RewriteBody(BaseModel):
        arch: str = "i960"
        function: str
        provider: Optional[str] = "echo"
        apply: bool = False

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        summary = asdict(catalog.project_summary())
        return {
            "project": summary["root"],
            "summary": summary,
            "arches": available_arches(),
            "spa": _GUI_DIST.is_dir() and (_GUI_DIST / "index.html").is_file(),
            "recent": catalog.recent_projects(),
        }

    @app.get("/api/project")
    def get_project() -> dict[str, Any]:
        return asdict(catalog.project_summary())

    @app.post("/api/project/open")
    def open_project(body: OpenBody) -> dict[str, Any]:
        try:
            return catalog.open_project(Path(body.path))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/project/init")
    def init_project(body: InitBody) -> dict[str, Any]:
        try:
            return catalog.init_project(Path(body.path), name=body.name, arch=body.arch)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/project/recent")
    def recent() -> list[dict[str, Any]]:
        return catalog.recent_projects()

    @app.get("/api/project/functions")
    def functions(status: Optional[str] = None, q: Optional[str] = None) -> dict[str, Any]:
        rows = catalog.inventory_functions()
        if status:
            rows = [r for r in rows if r.status == status]
        if q:
            ql = q.lower()
            rows = [
                r
                for r in rows
                if ql in r.name.lower()
                or ql in (r.section or "").lower()
                or ql in f"{r.address:x}"
            ]
        return {
            "count": len(rows),
            "functions": [asdict(r) for r in rows],
            "summary": asdict(catalog.project_summary()),
        }

    @app.get("/api/project/functions/{name}")
    def function_detail(name: str) -> dict[str, Any]:
        try:
            return catalog.function_detail(name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/project/slices")
    def slices() -> dict[str, Any]:
        rows = catalog.list_slices()
        return {"count": len(rows), "slices": rows}

    @app.post("/api/lift")
    def api_lift(body: LiftBody) -> dict[str, Any]:
        try:
            if body.function:
                result = lift_function(body.function, arch=body.arch)
            elif body.address is not None:
                if body.length is None:
                    raise ValueError("address requires length")
                result = lift_address(
                    body.address,
                    body.length,
                    arch=body.arch,
                    name=body.name,
                )
            elif body.slice:
                result = lift_slice(body.slice, arch=body.arch, name=body.name)
            else:
                raise ValueError("provide slice, function, or address+length")
        except Exception as exc:  # noqa: BLE001 — surface to UI
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "report": result.report,
            "scaffold_c": result.scaffold_c,
            "lifted_text": result.lifted_text,
            "summary": asdict(catalog.project_summary()),
        }

    @app.post("/api/rewrite")
    def api_rewrite(body: RewriteBody) -> dict[str, Any]:
        try:
            result = rewrite_function(
                body.function,
                arch=body.arch,
                provider=body.provider,
                apply=body.apply,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "provider": result.provider,
            "model": result.model,
            "prompt_hash": result.prompt_hash,
            "draft": result.draft_path,
            "applied": result.applied_path,
            "c_text": result.c_text,
            "summary": asdict(catalog.project_summary()),
        }

    if _GUI_DIST.is_dir() and (_GUI_DIST / "index.html").is_file():
        assets = _GUI_DIST / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/")
        def spa_index() -> FileResponse:
            return FileResponse(_GUI_DIST / "index.html")

    else:

        @app.get("/", response_class=HTMLResponse)
        def index() -> str:
            return _FALLBACK_HTML

    return app


_FALLBACK_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><title>liftkit</title>
<style>
body{font-family:system-ui,sans-serif;background:#14151a;color:#e8e6e3;max-width:40rem;margin:3rem auto;padding:0 1rem}
code{background:#1c1e24;padding:0.15rem 0.35rem;border-radius:4px}
</style></head><body>
<h1>liftkit</h1>
<p>TypeScript UI not built yet. From the liftkit repo:</p>
<pre>cd gui-web &amp;&amp; npm install &amp;&amp; npm run build
python3 -m liftkit gui --project ../decomp</pre>
</body></html>
"""
