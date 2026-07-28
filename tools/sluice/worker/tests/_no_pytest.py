"""``pytest`` when it is installed, a decorator-compatible stub when it is not.

``scripts/run_tests.sh`` runs each suite as ``python3 <file>`` and the CI job that
invokes it does not install pytest (that is the point — the gate is meant to be
dependency-light). A suite that imports pytest at module scope therefore dies at
import with ``ModuleNotFoundError`` before any check runs, which is exactly how
two dependency-free suites still managed to fail CI.

Import ``pytest`` from here instead::

    from _no_pytest import pytest

Under pytest it *is* pytest, so fixtures, ``parametrize`` and ``importorskip``
behave normally. Standalone, the decorators become no-ops so the module imports
cleanly and its ``__main__`` runner can call the checks directly.
"""

from __future__ import annotations

try:  # pragma: no cover - exercised by whichever path the environment provides
    import pytest  # type: ignore
except ImportError:  # pragma: no cover
    from typing import Any

    def _passthrough(*_args: Any, **_kwargs: Any):
        """Return a decorator that leaves the function untouched."""

        def deco(fn):
            return fn

        # Support both @fixture and @fixture(scope=...) spellings.
        if len(_args) == 1 and callable(_args[0]) and not _kwargs:
            return _args[0]
        return deco

    class _Mark:
        parametrize = staticmethod(_passthrough)
        skipif = staticmethod(_passthrough)
        skip = staticmethod(_passthrough)

    class _PytestStub:
        """The sliver of the pytest API these suites touch."""

        fixture = staticmethod(_passthrough)
        mark = _Mark()

        @staticmethod
        def importorskip(name: str, reason: str | None = None):
            __import__(name)

        @staticmethod
        def skip(reason: str = "", allow_module_level: bool = False):
            raise SystemExit(0)

        class raises:  # noqa: N801 - mirrors pytest's lowercase name
            def __init__(self, expected, **_kw):
                self.expected = expected

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                if exc_type is None:
                    raise AssertionError(f"expected {self.expected.__name__}")
                return issubclass(exc_type, self.expected)

    pytest = _PytestStub()  # type: ignore[assignment]

__all__ = ["pytest"]
