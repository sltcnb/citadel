"""Babel parser base — backward-compatible re-export of the shared contract.

The canonical definition now lives in the standalone ``citadel_contracts``
package so that Babel (parser packs) and Sluice (the loader) depend on the same
contract WITHOUT importing each other. Existing parsers keep working unchanged:

    from babel.base_plugin import BasePlugin, PluginContext, PluginParseError

still resolves — it just forwards to ``citadel_contracts``.

A small path bootstrap makes the import work however this module is loaded
(by the processor's PluginLoader via importlib, or as part of the ``plugins``
package): ``citadel_contracts`` sits one level up from ``plugins/``.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# Ensure the dir that contains the `citadel_contracts` package is importable,
# regardless of how this file was loaded (dev tree: tools/; container: /app).
_contracts_parent = _Path(__file__).resolve().parents[1]
if str(_contracts_parent) not in _sys.path:
    _sys.path.insert(0, str(_contracts_parent))

from citadel_contracts.parser import (  # noqa: E402,F401
    STRUCTURED_ARTIFACTS,
    BasePlugin,
    PluginContext,
    PluginError,
    PluginFatalError,
    PluginParseError,
    classify_os,
    iso_z,
)

__all__ = [
    "BasePlugin",
    "PluginContext",
    "PluginError",
    "PluginParseError",
    "PluginFatalError",
    "STRUCTURED_ARTIFACTS",
    "classify_os",
    "iso_z",
]
