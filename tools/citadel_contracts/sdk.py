"""Thin authoring SDK — write a parser/module in a few lines, not a class.

The contract is still :class:`BasePlugin` / :class:`BaseModule`; this just removes
the boilerplate. A decorator wraps a generator function into a proper plugin
class the loader discovers exactly as before — nothing downstream changes.

    from citadel_contracts.sdk import parser, event

    @parser(name="myapp", extensions=[".log"])
    def parse(ctx):
        for line in ctx.lines():
            if not line.strip():
                continue
            yield event(timestamp=line[:19], message=line)

``parse`` is now a BasePlugin subclass — drop the file in the plugins dir and the
loader picks it up. ``ctx`` gives cheap readers (lines/text/bytes/json/jsonl);
``event(...)`` builds a contract-compliant event dict.
"""
from __future__ import annotations

import json
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any, Callable

from .parser import BasePlugin, PluginContext, iso_z


class Ctx:
    """Convenience wrapper over PluginContext — readers + the source path."""

    def __init__(self, plugin: BasePlugin) -> None:
        self._plugin = plugin
        self.ctx = plugin.ctx
        self.path: Path = plugin.ctx.source_file_path
        self.log = plugin.log

    def text(self, errors: str = "replace") -> str:
        return self.path.read_text(errors=errors)

    def raw_bytes(self) -> bytes:
        return self.path.read_bytes()

    def lines(self, errors: str = "replace") -> Iterator[str]:
        with open(self.path, errors=errors) as fh:
            for line in fh:
                yield line.rstrip("\n")

    def json(self) -> Any:
        return json.loads(self.text())

    def jsonl(self) -> Iterator[dict]:
        for line in self.lines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                yield obj


def event(
    *,
    timestamp: Any = None,
    message: str = "",
    artifact_type: str | None = None,
    timestamp_desc: str = "Event Time",
    host: dict | None = None,
    user: dict | None = None,
    process: dict | None = None,
    network: dict | None = None,
    raw: dict | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a contract-compliant event dict (same shape as make_event)."""
    evt: dict[str, Any] = {
        "timestamp": iso_z(timestamp) if timestamp else "",
        "timestamp_desc": timestamp_desc,
        "message": message or "",
    }
    if artifact_type:
        evt["artifact_type"] = artifact_type
    for k, v in (("host", host), ("user", user), ("process", process), ("network", network)):
        if v:
            evt[k] = v
    evt["raw"] = raw if isinstance(raw, dict) else {}
    if extra:
        evt.update(extra)
    return evt


def parser(
    *,
    name: str,
    extensions: list[str] | None = None,
    mime: list[str] | None = None,
    filenames: list[str] | None = None,
    artifact_type: str | None = None,
    priority: int = 50,
    version: str = "1.0.0",
    can_handle: Callable[[Path, str], bool] | None = None,
) -> Callable[[Callable[[Ctx], Generator]], type[BasePlugin]]:
    """Turn a ``def parse(ctx) -> yields event(...)`` into a BasePlugin subclass.

    Same contract, ~10 lines instead of a class. ``can_handle`` defaults to the
    standard extension/mime/filename match; pass a callable to override.
    """
    def deco(fn: Callable[[Ctx], Generator]) -> type[BasePlugin]:
        _ext = [e.lower() for e in (extensions or [])]
        _mime = list(mime or [])
        _fn = [f.upper() for f in (filenames or [])]

        class _SdkPlugin(BasePlugin):
            PLUGIN_NAME = name
            PLUGIN_VERSION = version
            DEFAULT_ARTIFACT_TYPE = artifact_type or name
            SUPPORTED_EXTENSIONS = _ext
            SUPPORTED_MIME_TYPES = _mime
            PLUGIN_PRIORITY = priority

            @classmethod
            def get_handled_filenames(cls) -> list[str]:
                return list(_fn)

            @classmethod
            def can_handle(cls, file_path: Path, mime_type: str) -> bool:
                if can_handle is not None:
                    return can_handle(file_path, mime_type)
                return super().can_handle(file_path, mime_type)

            def parse(self) -> Generator[dict[str, Any], None, None]:
                gen = fn(Ctx(self))
                if gen is None:
                    return
                for evt in gen:
                    # Default the artifact_type if the author didn't set one.
                    if isinstance(evt, dict):
                        evt.setdefault("artifact_type", self.DEFAULT_ARTIFACT_TYPE)
                    yield evt

        _SdkPlugin.__name__ = f"{name.title().replace('_', '')}Plugin"
        _SdkPlugin.__qualname__ = _SdkPlugin.__name__
        return _SdkPlugin

    return deco
