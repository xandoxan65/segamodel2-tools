"""Project catalog unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from liftkit.project import catalog
from liftkit.project.workspace import set_project_root

DECOMP = Path(__file__).resolve().parents[1].parent / "decomp"


@pytest.fixture
def decomp_project():
    if not (DECOMP / "symbols" / "functions.yaml").is_file():
        pytest.skip("decomp corpus missing")
    set_project_root(DECOMP)
    return DECOMP


def test_project_summary(decomp_project):
    s = catalog.project_summary()
    assert s.functions_total > 0
    assert s.has_symbols
    assert s.root == str(decomp_project.resolve())


def test_inventory_has_memcpy(decomp_project):
    rows = catalog.inventory_functions()
    names = {r.name for r in rows}
    assert "libc_memcpy" in names
    memcpy = next(r for r in rows if r.name == "libc_memcpy")
    assert memcpy.has_slice
