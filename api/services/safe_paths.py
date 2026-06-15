"""
Path-traversal-safe filesystem join.

Centralises the one correct way to turn untrusted name/path components into a
``Path`` that is provably contained within a trusted base directory. Substring
checks like ``".." in name`` are easy to get wrong and are not recognised as a
sanitiser by static analysis — resolving the candidate and asserting
containment is robust and unambiguous.
"""

from __future__ import annotations

from pathlib import Path


class UnsafePathError(ValueError):
    """Raised when a candidate path escapes its base directory."""


def safe_join(base: Path | str, *parts: str) -> Path:
    """Join ``parts`` onto ``base`` and guarantee the result stays inside ``base``.

    Rejects absolute components and any ``..`` traversal by resolving the final
    path and checking it is the base itself or a descendant of it.

    Raises ``UnsafePathError`` on escape (the caller maps this to HTTP 400).
    """
    base_path = Path(base).resolve()
    candidate = base_path.joinpath(*parts).resolve()
    if candidate != base_path and base_path not in candidate.parents:
        raise UnsafePathError(f"path escapes base directory: {'/'.join(parts)!r}")
    return candidate
