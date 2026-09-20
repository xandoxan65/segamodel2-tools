"""AI semantic rewrite providers."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


PROLOGUE_PATH = Path(__file__).resolve().parents[3] / "prompts" / "semantic_rewrite_v1.md"


@dataclass
class RewriteContext:
    arch: str
    name: str
    addr: int | None
    ir_json: dict[str, Any]
    scaffold_c: str
    asm_text: str = ""
    lifted_text: str = ""
    symbols_excerpt: str = ""
    runtime_header_excerpt: str = ""
    session_examples: list[str] = field(default_factory=list)


@dataclass
class RewriteResult:
    c_text: str
    model: str
    provider: str
    prompt_hash: str
    draft_path: str | None = None
    applied_path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class SemanticRewriteProvider(Protocol):
    name: str

    def rewrite(self, ctx: RewriteContext) -> RewriteResult:
        ...


def load_prologue() -> str:
    if PROLOGUE_PATH.is_file():
        return PROLOGUE_PATH.read_text(encoding="utf-8")
    return (
        "You rewrite lifted assembly IR into semantic-equivalent C. "
        "Do not invent control flow or memory ops not present in the IR."
    )


def build_prompt(ctx: RewriteContext) -> tuple[str, str]:
    """Return (system_prologue, user_message)."""
    system = load_prologue()
    system += f"\n\n## Target architecture\n{ctx.arch}\n"
    if ctx.runtime_header_excerpt:
        system += f"\n## Runtime header (excerpt)\n```c\n{ctx.runtime_header_excerpt}\n```\n"
    if ctx.session_examples:
        system += "\n## Prior accepted rewrites\n" + "\n---\n".join(ctx.session_examples)

    import json

    user_parts = [
        f"# Function `{ctx.name}`",
        f"Address: {('0x%x' % ctx.addr) if ctx.addr is not None else 'unknown'}",
        "",
        "## IR (JSON)",
        "```json",
        json.dumps(ctx.ir_json, indent=2)[:120_000],
        "```",
        "",
        "## Deterministic scaffold C (refine this; do not invent a new algorithm)",
        "```c",
        ctx.scaffold_c[:80_000],
        "```",
    ]
    if ctx.asm_text:
        user_parts += ["", "## Disassembly (grounding)", "```asm", ctx.asm_text[:40_000], "```"]
    if ctx.symbols_excerpt:
        user_parts += ["", "## Symbols excerpt", "```yaml", ctx.symbols_excerpt[:8_000], "```"]
    user_parts += [
        "",
        "Respond with a single C translation unit (or function) only. Keep `// @rom` annotations.",
    ]
    return system, "\n".join(user_parts)


def prompt_hash(system: str, user: str) -> str:
    h = hashlib.sha256()
    h.update(system.encode())
    h.update(b"\0")
    h.update(user.encode())
    return h.hexdigest()[:16]


class EchoProvider:
    """Offline provider for tests — returns scaffold with a marker comment."""

    name = "echo"

    def rewrite(self, ctx: RewriteContext) -> RewriteResult:
        system, user = build_prompt(ctx)
        marker = (
            f"/* liftkit semantic rewrite draft (echo provider) "
            f"prompt_hash={prompt_hash(system, user)} */\n"
        )
        return RewriteResult(
            c_text=marker + ctx.scaffold_c,
            model="echo",
            provider=self.name,
            prompt_hash=prompt_hash(system, user),
        )


class OpenAICompatibleProvider:
    """OpenAI-compatible Chat Completions API (set LIFTKIT_API_KEY)."""

    name = "openai"

    def __init__(self, *, model: str | None = None, base_url: str | None = None) -> None:
        self.model = model or os.environ.get("LIFTKIT_MODEL", "gpt-4.1")
        self.base_url = (
            base_url
            or os.environ.get("LIFTKIT_API_BASE", "https://api.openai.com/v1")
        ).rstrip("/")

    def rewrite(self, ctx: RewriteContext) -> RewriteResult:
        api_key = os.environ.get("LIFTKIT_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "LIFTKIT_API_KEY (or OPENAI_API_KEY) is required for provider 'openai'"
            )
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("install liftkit[ai] for live rewrite providers") from exc

        system, user = build_prompt(ctx)
        ph = prompt_hash(system, user)
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        text = data["choices"][0]["message"]["content"]
        text = _strip_fences(text)
        return RewriteResult(
            c_text=text,
            model=self.model,
            provider=self.name,
            prompt_hash=ph,
            raw={"usage": data.get("usage")},
        )


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        t = "\n".join(lines)
    return t


def get_provider(name: str | None = None) -> SemanticRewriteProvider:
    key = (name or os.environ.get("LIFTKIT_PROVIDER") or "echo").lower()
    if key in ("echo", "noop", "dry-run"):
        return EchoProvider()
    if key in ("openai", "openai-compatible"):
        return OpenAICompatibleProvider()
    raise KeyError(f"unknown rewrite provider {key!r}; use echo|openai")
