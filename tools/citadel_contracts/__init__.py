"""citadel_contracts — the shared, standalone contract surface for the suite.

This package is the SINGLE SOURCE of the Babel parser contract (BasePlugin +
ForensicEvent helpers). Both Babel (the parser packs) and Sluice (the
intake/processor that loads them) depend ONLY on this package — never on each
other. That is what makes parser packs interchangeable: drop any directory of
modules that subclass ``citadel_contracts.BasePlugin``, point the loader at it,
and the rest of the pipeline is unchanged.

No third-party dependencies; safe to vendor or pip-install into any tool image.
"""

from .parser import (  # noqa: F401
    STRUCTURED_ARTIFACTS,
    BasePlugin,
    PluginContext,
    PluginError,
    PluginFatalError,
    PluginParseError,
    classify_os,
    iso_z,
)
from .validator import (  # noqa: F401
    is_valid_forensic_event,
    validate_forensic_event,
)
from .logship import (  # noqa: F401
    JsonFormatter,
    RedisLogHandler,
    attach_redis_logs,
    log_stream_key,
    setup_json_logging,
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
    "validate_forensic_event",
    "is_valid_forensic_event",
    "attach_redis_logs",
    "log_stream_key",
    "setup_json_logging",
    "RedisLogHandler",
    "JsonFormatter",
]
__version__ = "1.0.0"
