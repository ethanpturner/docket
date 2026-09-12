"""The version, in one place.

It lives here rather than in `__init__.py` because a record stamps the version that wrote it, and
`disposition.py` cannot import the package root without a cycle. A hardcoded default in the record
class was the alternative, and it drifted: records written by 0.2.0 claimed 0.1.0, which is exactly
the kind of quietly wrong provenance this tool exists to make visible.
"""

from __future__ import annotations

from typing import Final

__all__ = ["__version__"]

__version__: Final = "0.3.0"
