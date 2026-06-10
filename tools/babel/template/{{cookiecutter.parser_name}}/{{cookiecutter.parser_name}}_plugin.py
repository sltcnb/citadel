"""{{cookiecutter.parser_name}} — Babel parser scaffold.

Generated from tools/babel/template. Implement parse() to yield ForensicEvents.
See ../../sdk/README.md and ../../base_plugin.py for the contract.
"""
from __future__ import annotations

from typing import Any, Generator

from base_plugin import BasePlugin


class {{cookiecutter.parser_name}}Plugin(BasePlugin):
    PLUGIN_NAME = "{{cookiecutter.parser_name}}"
    PLUGIN_VERSION = "0.1.0"
    DEFAULT_ARTIFACT_TYPE = "{{cookiecutter.artifact_type}}"
    SUPPORTED_EXTENSIONS = ["{{cookiecutter.extension}}"]
    SUPPORTED_MIME_TYPES = ["{{cookiecutter.mime_type}}"]
    PLUGIN_PRIORITY = 100

    def parse(self) -> Generator[dict[str, Any], None, None]:
        # TODO: replace this line-per-event stub with real parsing.
        text = self.ctx.source_file_path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            yield {
                "timestamp": "1970-01-01T00:00:00Z",  # TODO: parse the real time
                "message": line,
                "artifact_type": self.DEFAULT_ARTIFACT_TYPE,
                "raw": {"lineno": lineno, "line": line},
            }
