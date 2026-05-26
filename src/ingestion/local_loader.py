"""Local-only ingestion helpers.

The requested scope is parsing + SEPSES mapping + Turtle generation, so this module
does not fetch remote datasets. It only validates local file paths before parsers read them.
"""

from __future__ import annotations

from pathlib import Path


def require_existing_path(path: str | Path) -> Path:
    resolved = Path(path)
    if not resolved.exists():
        raise FileNotFoundError(resolved)
    return resolved
