"""liftkit — multi-ISA disasm → IR → C uplift toolkit."""

from __future__ import annotations

__version__ = "0.1.0"

from liftkit.api import LiftResult, lift_function, lift_slice, rewrite_function

__all__ = ["LiftResult", "lift_function", "lift_slice", "rewrite_function", "__version__"]
