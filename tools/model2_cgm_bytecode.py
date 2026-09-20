"""``0x027008`` bytecode emit/walk + ``0x027160`` / ``0x0271D0`` stub-patch simulation.

Static RE only — models descriptor writes @ ``0x01000000``, counter ops, and the
ROM stub-patch helpers that link workram trampolines (``0x005C61C8``,
``0x005C6250``) into descriptor chains before ``0x029958`` runs compiled thunks.

Disasm: ``decomp/disasm/maincpu/maincpu_027008_200.asm``,
``maincpu_0271d0_100.asm``, ``maincpu_026e18_200.asm``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.model2_cgm_emit import EmitCounters, STAGING0_DESC

# Workram return-stub templates (ROM ``lda`` sites only; bytes filled @ init/run).
STUB_61C8 = 0x005C61C8  # ``0x027160`` patches this into descriptor chain
STUB_6250 = 0x005C6250  # ``0x0271D0`` template-byte stream patch
STUB_8964 = 0x005C8964  # ``0x029958`` compile-run entry


@dataclass
class StagingState:
    """``0x20B1A8`` / ``0x20B1AC`` / ``0x20B1B0`` + ``0x01000000`` descriptors."""

    counters: EmitCounters = field(default_factory=EmitCounters)
    tag: int = 0x400  # default from ``0x29A44`` ``26FD8`` with g0=8 → 8<<7
    descriptors: dict[int, int] = field(default_factory=dict)
    stub_patches: list[dict] = field(default_factory=list)

    def desc_index(self) -> int:
        return (self.counters.width << 6) + self.counters.slot

    def write_descriptor(self, g0: int) -> int:
        """``0x0270CC``–``0x027120``: emit descriptor word for opcode byte ``g0``."""
        tag_byte = (int(g0) >> 0) & 0xFF  # ``shlo 24; shro 24`` for low-byte g0
        word = 0xFFFF8000 | (tag_byte & 0xFF) | (self.tag & 0xFFFF)
        idx = self.desc_index()
        self.descriptors[idx] = word & 0xFFFF
        self.counters.slot += 1
        return idx

    def op_27008(self, g0: int) -> None:
        """One ``0x027008`` dispatch (emit @ ``0x05D860`` or walk @ ``0x027130``)."""
        low = g0 & 0xFF
        if low > 31:
            self.write_descriptor(g0)
            return
        if low == 8:
            self.counters.slot = max(0, self.counters.slot - 1)
            return
        if low == 9:
            self.counters.width = low
            return
        if low == 10:
            self.counters.slot, self.counters.width = (
                self.counters.width,
                self.counters.slot,
            )
            return
        # 0 or unknown control: no-op return

    def walk_bytecode(self, bytecode: list[int]) -> list[dict]:
        """``0x027130``: replay ``0x027008`` for each bytecode byte."""
        log: list[dict] = []
        for byte in bytecode:
            before = (self.counters.slot, self.counters.width, self.desc_index())
            self.op_27008(byte)
            log.append(
                {
                    "byte": f"0x{byte & 0xFF:02x}",
                    "before": {"slot": before[0], "width": before[1], "idx": before[2]},
                    "after": {
                        "slot": self.counters.slot,
                        "width": self.counters.width,
                        "idx": self.desc_index(),
                    },
                }
            )
        return log

    def sim_27160(self, count: int) -> None:
        """``0x027160``: zero-fill ``count`` descriptor link halfwords (@ ``g14=0``)."""
        n = int(count) & 0xFF
        if n <= 0:
            return
        for step in range(n):
            idx = self.desc_index()
            self.stub_patches.append(
                {
                    "rom": "0x027160",
                    "patch": "zero_halfword",
                    "return_stub": f"0x{STUB_61C8:08X}",
                    "desc_idx": idx,
                    "slot": self.counters.slot,
                    "width": self.counters.width,
                    "patch_index": step,
                    "count": n,
                }
            )
            if self.counters.slot > 0:
                self.counters.slot -= 1

    def sim_271d0(self, template: bytes) -> None:
        """``0x0271D0``: non-zero template bytes → zero-fill link halfwords (@ ``g14=0``)."""
        for byte in template:
            if byte == 0:
                break
            idx = self.desc_index()
            self.stub_patches.append(
                {
                    "rom": "0x0271D0",
                    "patch": "zero_halfword",
                    "return_stub": f"0x{STUB_6250:08X}",
                    "desc_idx": idx,
                    "template_byte": f"0x{byte:02x}",
                    "slot": self.counters.slot,
                    "width": self.counters.width,
                }
            )
            self.counters.slot += 1

    def sim_27260(self, *, g0: int, g1: int, g2: int, g3: int, g14_link: int = 0) -> None:
        """``0x027260``: batch link patch — ``stos g14`` stores caller return address."""
        tag = (int(g1) & 0xFF) << 7
        link = int(g14_link) & 0xFFFF
        for _outer in range(max(0, int(g3))):
            idx = (int(g0) & 0xFF) + _outer
            for _inner in range(max(0, int(g2))):
                self.stub_patches.append(
                    {
                        "rom": "0x027260",
                        "patch": "link_halfword",
                        "link_value": f"0x{link:04x}",
                        "desc_idx": idx,
                        "tag": f"0x{tag:04x}",
                        "inner": _inner,
                    }
                )

    def infer_upload_chain(self) -> list[dict]:
        """Summarise likely ``0x02A5A0`` entry args from final counters + patches."""
        return [
            {
                "note": "0x02A6E8 wrapper passes outer g0→g2, g1→g3, g4→r6 before call 0x02A5A0",
                "likely_saved_r10": self.counters.width,
                "likely_saved_r9": self.counters.slot,
                "likely_r14_bit0": "set for D/U (merge path @ 0x02A62C)",
                "merge_globals": "filled by 0x02A2E0 from compiled g0/g1/g2/g3",
                "stub_patches": len(self.stub_patches),
            }
        ]


def bind_and_run(
    bytecode: list[int],
    *,
    template_row: bytes = b"",
    stub_27160_count: int = 0,
) -> StagingState:
    """Emit-walk bytecode, then optional ``0x0271D0`` template stub patches."""
    state = StagingState()
    state.walk_bytecode(bytecode)
    if stub_27160_count:
        state.sim_27160(stub_27160_count)
    if template_row:
        state.sim_271d0(template_row)
    return state
