"""Pixel IT Profile Migrator prototype package.

The repository currently keeps the primary application modules under src/.
Extend the package search path so the transitional top-level prototype can
coexist with the src layout while tests and the CLI are being consolidated.
"""
from pathlib import Path

__version__ = "0.1.0"

_src_package = Path(__file__).resolve().parent.parent / "src" / "pixelit_migrator"
if _src_package.is_dir():
    __path__.append(str(_src_package))
