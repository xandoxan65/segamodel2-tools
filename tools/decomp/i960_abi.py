"""Static ABI inference and JSON export for lifted i960 functions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from tools.decomp.i960_call_sites import CallSiteNote, call_sites_for
from tools.decomp.disasm_parse import Insn, SliceDocument
from tools.decomp.i960_macros import FuncKind, FunctionProfile

_REG = re.compile(r"\b([gr]\d+|fp|sp|g14)\b", re.I)
_ASSIGN_DST = re.compile(r"^\s*([gr]\d+|fp|sp)\s*=")

# Curated ABI for pilot / known libc entry points (verified from disasm).
# link_reg is never a parameter — it is overwritten on leaf_bx entry.
KNOWN_FUNCTION_ABI: dict[str, dict[str, Any]] = {
    "libc_strcpy": {
        "params": [
            {"reg": "g0", "name": "dst", "type": "void *", "pointer": True},
            {"reg": "g1", "name": "src", "type": "const void *", "pointer": True},
        ],
        "returns": [{"reg": "g0", "type": "void *", "pointer": True}],
        "convention": {
            "kind": "leaf_bx",
            "arg_regs": ["g0", "g1"],
            "link": {"reg": "g14", "save_reg": "g2", "clear_on_entry": True, "return_via": "bx"},
        },
    },
    "libc_memcpy": {
        "params": [
            {"reg": "g0", "name": "dst", "type": "void *", "pointer": True},
            {"reg": "g1", "name": "src", "type": "const void *", "pointer": True},
            {"reg": "g2", "name": "len", "type": "u32", "pointer": False},
        ],
        "returns": [],
        "convention": {
            "kind": "leaf_ret",
            "arg_regs": ["g0", "g1", "g2"],
            "link": {"reg": "g14", "return_via": "ret"},
        },
    },
    "libc_printf": {
        "params": [
            {"reg": "g0", "name": "fmt", "type": "const char *", "pointer": True},
            {"reg": "g1", "name": "arg1", "type": "u32", "pointer": False},
            {"reg": "g2", "name": "arg2", "type": "u32", "pointer": False},
        ],
        "returns": [],
        "notes": "Additional varargs marshalled via fp+0x70 / g13 va-block; g1/g2 usage varies by call site.",
        "convention": {
            "kind": "frame",
            "arg_regs": ["g0", "g1", "g2"],
            "link": {"reg": "g14", "save_reg": "g13", "clear_on_entry": True, "return_via": "ret"},
            "callee_scratch": ["r4", "r5"],
        },
    },
}


@dataclass
class AbiParam:
    reg: str
    name: str
    type: str = "u32"
    pointer: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reg": self.reg, "name": self.name, "type": self.type}
        if self.pointer:
            out["pointer"] = True
        return out


@dataclass
class AbiReturn:
    reg: str
    type: str = "u32"
    pointer: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reg": self.reg, "type": self.type}
        if self.pointer:
            out["pointer"] = True
        return out


@dataclass
class AbiLinkConvention:
    """Model 2 i960 call/return link: architectural g14, optional save reg, bx vs ret."""

    reg: str = "g14"
    save_reg: str | None = None
    clear_on_entry: bool = False
    return_via: str = "ret"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reg": self.reg, "return_via": self.return_via}
        if self.save_reg:
            out["save_reg"] = self.save_reg
        if self.clear_on_entry:
            out["clear_on_entry"] = True
        return out

    @classmethod
    def from_json(cls, raw: dict[str, Any] | None) -> AbiLinkConvention:
        if not raw:
            return cls()
        return cls(
            reg=str(raw.get("reg", "g14")),
            save_reg=raw.get("save_reg"),
            clear_on_entry=bool(raw.get("clear_on_entry", False)),
            return_via=str(raw.get("return_via", "ret")),
        )


@dataclass
class AbiConvention:
    """Register-level calling convention for lifted Model 2 maincpu code."""

    model: str = "model2_i960"
    kind: str = "unknown"
    arg_regs: list[str] = field(default_factory=lambda: ["g0", "g1", "g2"])
    link: AbiLinkConvention = field(default_factory=AbiLinkConvention)
    caller_scratch: list[str] = field(default_factory=list)
    callee_scratch: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "model": self.model,
            "kind": self.kind,
            "arg_regs": list(self.arg_regs),
            "link": self.link.to_json(),
        }
        if self.caller_scratch:
            out["caller_scratch"] = list(self.caller_scratch)
        if self.callee_scratch:
            out["callee_scratch"] = list(self.callee_scratch)
        return out

    @classmethod
    def from_json(cls, raw: dict[str, Any] | None) -> AbiConvention | None:
        if not raw:
            return None
        return cls(
            model=str(raw.get("model", "model2_i960")),
            kind=str(raw.get("kind", "unknown")),
            arg_regs=list(raw.get("arg_regs", ["g0", "g1", "g2"])),
            link=AbiLinkConvention.from_json(raw.get("link")),
            caller_scratch=list(raw.get("caller_scratch", [])),
            callee_scratch=list(raw.get("callee_scratch", [])),
        )

    def emit_comment_line(self) -> str:
        parts = [f"kind={self.kind}", f"args {','.join(self.arg_regs)}"]
        link = self.link
        if link.save_reg:
            parts.append(f"link {link.reg}→{link.save_reg} {link.return_via}")
        else:
            parts.append(f"link {link.reg} {link.return_via}")
        if self.caller_scratch:
            parts.append(f"caller {','.join(self.caller_scratch)}")
        if self.callee_scratch:
            parts.append(f"callee {','.join(self.callee_scratch)}")
        return f"/* convention: {'  '.join(parts)} */"


@dataclass
class FunctionAbi:
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    clobbers: list[str] = field(default_factory=list)
    callee_saved: list[str] = field(default_factory=list)
    link_reg: str | None = None
    convention: AbiConvention | None = None
    call_sites: list[CallSiteNote] = field(default_factory=list)
    params: list[AbiParam] = field(default_factory=list)
    returns: list[AbiReturn] = field(default_factory=list)
    notes: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "inputs": self.inputs,
            "outputs": self.outputs,
            "clobbers": self.clobbers,
            "callee_saved": self.callee_saved,
            "link_reg": self.link_reg,
            "convention": self.convention.to_json() if self.convention else None,
            "params": [p.to_json() for p in self.params],
            "returns": [r.to_json() for r in self.returns],
            "notes": self.notes,
            "call_sites": [c.to_json() for c in self.call_sites],
        }

    def to_abi_document(
        self,
        *,
        name: str,
        addr: int,
        kind: str,
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "name": name,
            "addr": f"0x{addr:x}",
            "kind": kind,
            "calling_convention": "i960_gregs",
            "link_reg": self.link_reg,
            "convention": self.convention.to_json() if self.convention else None,
            "params": [p.to_json() for p in self.params],
            "returns": [r.to_json() for r in self.returns],
            "callee_saved": self.callee_saved,
            "clobbers": self.clobbers,
            "call_sites": [c.to_json() for c in self.call_sites],
        }
        if self.notes:
            doc["notes"] = self.notes
        return doc

    def emit_comment_lines(self) -> list[str]:
        lines: list[str] = []
        if self.convention:
            lines.append(self.convention.emit_comment_line())
        if self.params:
            sig_parts = []
            for p in self.params:
                sig_parts.append(f"{p.type} {p.name}={p.reg}")
            ret = ""
            if self.returns:
                ret = f" → {self.returns[0].type} {self.returns[0].reg}"
            elif self.returns == [] and not self.outputs:
                ret = " → void"
            lines.append(f"/* abi: {', '.join(sig_parts)}{ret} */")
        else:
            parts: list[str] = []
            if self.inputs:
                parts.append(f"in {','.join(self.inputs)}")
            if self.outputs:
                parts.append(f"out {','.join(self.outputs)}")
            if self.link_reg:
                parts.append(f"link {self.link_reg}")
            if self.callee_saved:
                parts.append(f"save {','.join(self.callee_saved)}")
            if self.clobbers:
                parts.append(f"clobber {','.join(self.clobbers)}")
            if parts:
                lines.append(f"/* abi: {'  '.join(parts)} */")
        if self.link_reg and self.link_reg not in {p.reg for p in self.params}:
            if not self.convention or self.convention.link.save_reg != self.link_reg:
                lines.append(f"/* link_reg: {self.link_reg} (not a parameter) */")
        if self.notes:
            lines.append(f"/* abi note: {self.notes} */")
        for site in self.call_sites[:3]:
            lines.append(site.emit_comment())
        return lines

    @property
    def has_c_abi(self) -> bool:
        return bool(self.params)

    def c_return_type(self) -> str:
        if not self.returns:
            return "void"
        return self.returns[0].type

    def c_signature(self, name: str) -> str:
        if not self.has_c_abi:
            return f"void {name}(void)"
        params = ", ".join(f"{p.type} {p.name}" for p in self.params)
        return f"{self.c_return_type()} {name}({params})"

    @staticmethod
    def _cast_reg_to_type(reg: str, ctype: str) -> str:
        if ctype in ("void *", "char *"):
            return f"({ctype})(uintptr_t){reg}"
        if ctype == "const void *":
            return f"(const void *)(uintptr_t){reg}"
        if ctype == "const char *":
            return f"(const char *)(uintptr_t){reg}"
        if ctype == "u32":
            return reg
        if ctype.endswith("*"):
            return f"({ctype})(uintptr_t){reg}"
        return f"({ctype}){reg}"

    def param_prologue_lines(self, *, indent: int = 4) -> list[str]:
        pad = " " * indent
        lines: list[str] = []
        for param in self.params:
            if param.pointer or param.type.endswith("*"):
                lines.append(f"{pad}{param.reg} = (uintptr_t){param.name};")
            else:
                lines.append(f"{pad}{param.reg} = (uintptr_t){param.name};")
        return lines

    def format_c_return_stmt(self, *, indent: int = 4, link_reg: str | None = None) -> str:
        pad = " " * indent
        bx_link: str | None = None
        if link_reg is not None:
            bx_link = link_reg
        elif self.convention and self.convention.link.return_via == "bx":
            bx_link = self.convention.link.save_reg or self.link_reg
        elif self.link_reg and (self.convention is None or self.convention.link.return_via == "bx"):
            bx_link = self.link_reg
        if not self.returns:
            if bx_link:
                return (
                    f"{pad}i960_call_indirect({bx_link});\n"
                    f"{pad}return;"
                )
            return f"{pad}return;"
        ret = self.returns[0]
        expr = self._cast_reg_to_type(ret.reg, ret.type)
        if bx_link:
            return (
                f"{pad}i960_call_indirect({bx_link});\n"
                f"{pad}return {expr};"
            )
        return f"{pad}return {expr};"

    def format_c_call_args(self) -> list[str]:
        """Build C argument list from live register values at a call site."""
        return [self._cast_reg_to_type(p.reg, p.type) for p in self.params]


def parse_abi_document(doc: dict[str, Any]) -> FunctionAbi:
    params = [
        AbiParam(
            reg=p["reg"],
            name=p["name"],
            type=p.get("type", "u32"),
            pointer=bool(p.get("pointer", False)),
        )
        for p in doc.get("params", [])
    ]
    returns = [
        AbiReturn(
            reg=r["reg"],
            type=r.get("type", "u32"),
            pointer=bool(r.get("pointer", False)),
        )
        for r in doc.get("returns", [])
    ]
    convention = AbiConvention.from_json(doc.get("convention"))
    link_reg = doc.get("link_reg")
    if link_reg is None and convention and convention.link.save_reg:
        link_reg = convention.link.save_reg
    return FunctionAbi(
        link_reg=link_reg,
        convention=convention,
        params=params,
        returns=returns,
        callee_saved=list(doc.get("callee_saved", [])),
        clobbers=list(doc.get("clobbers", [])),
        notes=doc.get("notes"),
    )


@lru_cache(maxsize=1)
def _abi_catalog_by_addr() -> dict[int, FunctionAbi]:
    from tools.decomp.workspace import DECOMP_ROOT

    path = DECOMP_ROOT / "symbols" / "function_abi.json"
    out: dict[int, FunctionAbi] = {}
    if not path.is_file():
        return out
    raw = json.loads(path.read_text(encoding="utf-8"))
    for entry in raw.get("functions", {}).values():
        addr_s = entry.get("addr", "")
        if not isinstance(addr_s, str) or not addr_s.startswith("0x"):
            continue
        addr = int(addr_s, 16)
        out[addr] = parse_abi_document(entry)
    return out


def lookup_abi_by_addr(addr: int) -> FunctionAbi | None:
    return _abi_catalog_by_addr().get(addr)


def clear_abi_catalog_cache() -> None:
    _abi_catalog_by_addr.cache_clear()


def _collect_stmt_regs(stmts: list[tuple[str, str]]) -> tuple[set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    for kind, text in stmts:
        if kind in ("return", "call", "raw", "data"):
            continue
        for reg in _REG.findall(text):
            token = reg.lower()
            if kind == "branch":
                reads.add(token)
                continue
            m = _ASSIGN_DST.match(text)
            if m:
                writes.add(m.group(1).lower())
                for other in _REG.findall(text.split("=", 1)[1]):
                    reads.add(other.lower())
            else:
                for token in _REG.findall(text):
                    reads.add(token.lower())
    return reads, writes


def _detect_callee_saved(insns: list[Insn]) -> list[str]:
    saved: list[str] = []
    if len(insns) < 2:
        return saved
    pairs: list[tuple[str, str]] = []
    for insn in insns:
        if insn.mnemonic == "movl" and len(insn.operands) == 2:
            src, dst = insn.operands[0].lower(), insn.operands[1].lower()
            if src.startswith("g") and dst.startswith("r"):
                pairs.append((src, dst))
            elif dst.startswith("g") and src.startswith("r"):
                pairs.append((dst, src))
    seen: set[str] = set()
    for g_reg, r_reg in pairs:
        if g_reg in seen:
            continue
        has_save = any(
            i.mnemonic == "movl"
            and len(i.operands) == 2
            and i.operands[0].lower() == g_reg
            and i.operands[1].lower() == r_reg
            for i in insns[: len(insns) // 2 + 1]
        )
        has_restore = any(
            i.mnemonic == "movl"
            and len(i.operands) == 2
            and i.operands[0].lower() == r_reg
            and i.operands[1].lower() == g_reg
            for i in insns[len(insns) // 2 :]
        )
        if has_save and has_restore:
            saved.append(g_reg)
            seen.add(g_reg)
    return sorted(saved)


def _entry_input_regs(
    insns: list[Insn],
    profile: FunctionProfile,
    *,
    early_writes: set[str],
) -> list[str]:
    skip_addrs: set[int] = set()
    if profile.kind == FuncKind.LEAF_BX and len(insns) >= 2:
        skip_addrs.add(insns[0].addr)
        skip_addrs.add(insns[1].addr)

    first_write: dict[str, int] = {}
    first_read: dict[str, int] = {}
    order = 0
    for insn in insns:
        if insn.addr in skip_addrs or insn.mnemonic is None:
            continue
        order += 1
        text_ops = " ".join(insn.operands or [])
        for reg in _REG.findall(text_ops):
            token = reg.lower()
            if token not in first_read:
                first_read[token] = order
        if insn.mnemonic in ("mov", "movl") and len(insn.operands) == 2:
            dst = insn.operands[1].lower()
            if dst not in first_write:
                first_write[dst] = order
        elif insn.mnemonic in ("addo", "add", "subo", "sub", "and", "or", "shro", "shlo") and len(insn.operands) == 3:
            dst = insn.operands[2].lower()
            if dst not in first_write:
                first_write[dst] = order
        elif insn.mnemonic.startswith("ld") and len(insn.operands) == 2:
            dst = insn.operands[1].lower()
            if dst not in first_write:
                first_write[dst] = order

    inputs: list[str] = []
    for reg in [f"g{i}" for i in range(3)]:
        if reg in early_writes and reg == profile.link_reg:
            continue
        if reg in first_read and (reg not in first_write or first_read[reg] <= first_write[reg]):
            inputs.append(reg)
    return inputs


def _exit_output_regs(insns: list[Insn], profile: FunctionProfile) -> list[str]:
    outputs: set[str] = set()
    for idx, insn in enumerate(insns):
        if insn.mnemonic not in ("ret", "bx"):
            continue
        window = insns[max(0, idx - 6) : idx]
        for prev in window:
            if prev.mnemonic == "mov" and len(prev.operands) == 2 and prev.operands[1].lower() == "g0":
                outputs.add("g0")
            if prev.mnemonic == "mov" and len(prev.operands) == 2 and prev.operands[0] in ("0", "0x0") and prev.operands[1].lower() == "g0":
                outputs.add("g0")
    if profile.kind == FuncKind.LEAF_BX and "g0" not in outputs:
        for insn in insns:
            if insn.mnemonic == "mov" and len(insn.operands) == 2 and insn.operands[0] in ("0", "0x0") and insn.operands[1].lower() == "g0":
                outputs.add("g0")
                break
    return sorted(outputs)


def _infer_pointer_regs(insns: list[Insn], input_regs: list[str]) -> set[str]:
    """Mark g* used as address bases for byte/word memory ops before clobber."""
    pointers: set[str] = set()
    aliases: dict[str, str] = {}
    for insn in insns:
        if insn.mnemonic in ("mov", "movl") and len(insn.operands) == 2:
            src, dst = insn.operands[0].lower(), insn.operands[1].lower()
            if src in input_regs:
                aliases[dst] = src
        mn = insn.mnemonic or ""
        if mn in ("ldob", "stob", "ld", "st", "ldq", "stq") and len(insn.operands) == 2:
            mem_op, reg_op = insn.operands[0], insn.operands[1]
            if mn.startswith("ld"):
                base = mem_op.strip("()").split("(")[-1].rstrip(")").lower()
                if base in aliases:
                    pointers.add(aliases[base])
                elif base in input_regs:
                    pointers.add(base)
            else:
                base = reg_op.strip("()").split("(")[-1].rstrip(")").lower()
                if "(" in reg_op:
                    inner = reg_op.split("(")[1].split(")")[0].lower()
                    base = inner
                if base in aliases:
                    pointers.add(aliases[base])
                elif base in input_regs:
                    pointers.add(base)
    return pointers


def _generic_params(
    input_regs: list[str],
    *,
    pointer_regs: set[str],
    link_reg: str | None,
) -> list[AbiParam]:
    params: list[AbiParam] = []
    for i, reg in enumerate(input_regs):
        if reg == link_reg:
            continue
        is_ptr = reg in pointer_regs
        ctype = "void *" if is_ptr else "u32"
        params.append(
            AbiParam(
                reg=reg,
                name=f"arg{i}",
                type=ctype,
                pointer=is_ptr,
            )
        )
    return params


def _apply_known_abi(name: str, abi: FunctionAbi) -> None:
    hint = KNOWN_FUNCTION_ABI.get(name)
    if not hint:
        return
    abi.params = [
        AbiParam(
            reg=p["reg"],
            name=p["name"],
            type=p["type"],
            pointer=bool(p.get("pointer", False)),
        )
        for p in hint.get("params", [])
    ]
    abi.returns = [
        AbiReturn(
            reg=r["reg"],
            type=r["type"],
            pointer=bool(r.get("pointer", False)),
        )
        for r in hint.get("returns", [])
    ]
    abi.notes = hint.get("notes")


def _infer_frame_link_save(insns: list[Insn]) -> str | None:
    for insn in insns[:20]:
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        if insn.operands[0] == "g14":
            return insn.operands[1].lower()
    return None


def _infer_callee_scratch(insns: list[Insn]) -> list[str]:
    scratch: set[str] = set()
    for insn in insns[:40]:
        if insn.mnemonic not in ("mov", "movl") or len(insn.operands) != 2:
            continue
        src, dst = insn.operands[0].lower(), insn.operands[1].lower()
        if dst.startswith("r") and src.startswith("g"):
            scratch.add(dst)
    return sorted(scratch)


def _infer_caller_scratch(call_sites: list[CallSiteNote]) -> list[str]:
    scratch: set[str] = set()
    for site in call_sites:
        for reg in ("g0", "g1", "g2"):
            val = getattr(site, reg)
            if val and re.fullmatch(r"r\d+", val, re.I):
                scratch.add(val.lower())
    return sorted(scratch)


def infer_convention(
    profile: FunctionProfile,
    insns: list[Insn],
    *,
    call_sites: list[CallSiteNote] | None = None,
    params: list[AbiParam] | None = None,
) -> AbiConvention:
    kind = profile.kind.value
    arg_regs = ["g0", "g1", "g2"]
    if params:
        used = [p.reg for p in params if p.reg in arg_regs]
        if used:
            arg_regs = used + [r for r in arg_regs if r not in used]

    link = AbiLinkConvention()
    if profile.kind == FuncKind.LEAF_BX and profile.link_reg:
        link.save_reg = profile.link_reg
        link.clear_on_entry = True
        link.return_via = "bx"
    elif profile.kind == FuncKind.FRAME:
        save = _infer_frame_link_save(insns)
        if save:
            link.save_reg = save
            link.clear_on_entry = True
        link.return_via = "ret"
    else:
        link.return_via = "ret"

    return AbiConvention(
        kind=kind,
        arg_regs=arg_regs,
        link=link,
        caller_scratch=_infer_caller_scratch(call_sites or []),
        callee_scratch=_infer_callee_scratch(insns),
    )


def infer_function_abi(
    doc: SliceDocument,
    profile: FunctionProfile,
    *,
    name: str = "",
    stmt_texts: list[tuple[str, str]] | None = None,
    fn_addr: int | None = None,
) -> FunctionAbi:
    insns = doc.insns
    abi = FunctionAbi(link_reg=profile.link_reg)

    if profile.kind == FuncKind.LEAF_BX and profile.link_reg:
        abi.link_reg = profile.link_reg

    abi.callee_saved = _detect_callee_saved(insns)

    early_writes: set[str] = set()
    if profile.link_reg:
        early_writes.add(profile.link_reg.lower())

    if profile.args:
        abi.inputs = [reg for reg, _ in profile.args[:3] if reg != profile.link_reg]
    else:
        abi.inputs = _entry_input_regs(insns, profile, early_writes=early_writes)

    abi.outputs = _exit_output_regs(insns, profile)

    if stmt_texts:
        _, writes = _collect_stmt_regs(stmt_texts)
        skip = set(abi.inputs) | set(abi.callee_saved) | {"g14", "fp", "sp"}
        if profile.link_reg:
            skip.add(profile.link_reg.lower())
        abi.clobbers = sorted(w for w in writes if w.startswith(("g", "r")) and w not in skip)

    if fn_addr is not None:
        abi.call_sites = call_sites_for(fn_addr)

    _apply_known_abi(name, abi)
    if not abi.params:
        pointer_regs = _infer_pointer_regs(insns, abi.inputs)
        abi.params = _generic_params(abi.inputs, pointer_regs=pointer_regs, link_reg=abi.link_reg)
    if not abi.returns and abi.outputs:
        ptr_out = abi.outputs[0] in _infer_pointer_regs(insns, abi.outputs)
        abi.returns = [
            AbiReturn(
                reg=abi.outputs[0],
                type="void *" if ptr_out else "u32",
                pointer=ptr_out,
            )
        ]

    abi.convention = infer_convention(
        profile,
        insns,
        call_sites=abi.call_sites,
        params=abi.params,
    )
    if name in KNOWN_FUNCTION_ABI and KNOWN_FUNCTION_ABI[name].get("convention"):
        known = AbiConvention.from_json(KNOWN_FUNCTION_ABI[name]["convention"])
        if known:
            if not known.caller_scratch:
                known.caller_scratch = _infer_caller_scratch(abi.call_sites)
            abi.convention = known
    elif not abi.convention.caller_scratch:
        abi.convention.caller_scratch = _infer_caller_scratch(abi.call_sites)
    if abi.convention.link.save_reg and not abi.link_reg:
        abi.link_reg = abi.convention.link.save_reg

    return abi


def write_abi_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def merge_abi_catalog(catalog_path: Path, entry: dict[str, Any]) -> None:
    """Merge one function ABI into symbols/function_abi.json keyed by addr."""
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    catalog: dict[str, Any] = {"version": 1, "functions": {}}
    if catalog_path.is_file():
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("functions"), dict):
            catalog = raw
    key = entry.get("addr", entry.get("name", ""))
    catalog["functions"][key] = entry
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
