"""
LNK Plugin — parses Windows Shortcut (.lnk) files.
Requires: LnkParse3 (pip install LnkParse3)
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    import LnkParse3

    LNK_AVAILABLE = True
except ImportError:
    LNK_AVAILABLE = False


class LnkPlugin(BasePlugin):
    PLUGIN_NAME = "lnk"
    PLUGIN_VERSION = "1.0.1"
    DEFAULT_ARTIFACT_TYPE = "lnk"
    SUPPORTED_EXTENSIONS = [".lnk"]
    SUPPORTED_MIME_TYPES = ["application/x-ms-shortcut"]
    PLUGIN_PRIORITY = 110  # claim .lnk over any generic text/iptables fallback

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0

    def setup(self) -> None:
        if not LNK_AVAILABLE:
            raise PluginFatalError("LnkParse3 is not installed. Run: pip install LnkParse3")

    def parse(self) -> Generator[dict[str, Any], None, None]:
        try:
            with open(str(self.ctx.source_file_path), "rb") as f:
                lnk = LnkParse3.lnk_file(f)
        except Exception as exc:
            raise PluginFatalError(f"Cannot parse LNK file: {exc}") from exc

        try:
            header = lnk.header
            target_path = ""
            local_path = ""
            working_dir = ""
            arguments = ""
            description = ""
            machine_id = ""

            try:
                target_path = lnk.lnk_header.lnk_target_path or ""
            except Exception:
                pass
            try:
                local_path = lnk.string_data.local_path or ""
            except Exception:
                pass
            try:
                working_dir = lnk.string_data.working_directory or ""
            except Exception:
                pass
            try:
                arguments = lnk.string_data.command_line_arguments or ""
            except Exception:
                pass
            try:
                description = lnk.string_data.description or ""
            except Exception:
                pass

            # Timestamps from header
            created = ""
            modified = ""
            accessed = ""
            try:
                created = str(header.creation_time or "")
                modified = str(header.write_time or "")
                accessed = str(header.access_time or "")
            except Exception:
                pass

            # Try to get machine ID from extra data
            try:
                machine_id = lnk.extra_data.machine_id or ""
            except Exception:
                pass

            effective_path = local_path or target_path or self.ctx.source_file_path.name
            message = f"Shortcut to: {effective_path}"
            if arguments:
                message += f" {arguments}"

            _raw_src = {
                "lnk_filename": self.ctx.source_file_path.name,
                "target_path": target_path,
                "local_path": local_path,
                "working_directory": working_dir,
                "arguments": arguments,
                "description": description,
                "machine_id": machine_id,
                "created_at": created,
                "modified_at": modified,
                "accessed_at": accessed,
            }
            self._records_read += 1
            yield {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "lnk",
                "timestamp": modified or created or None,
                "timestamp_desc": "LNK File Modified",
                "message": message,
                "lnk": {
                    "lnk_filename": self.ctx.source_file_path.name,
                    "target_path": target_path,
                    "local_path": local_path,
                    "working_directory": working_dir,
                    "arguments": arguments,
                    "description": description,
                    "machine_id": machine_id,
                    "created_at": created,
                    "modified_at": modified,
                    "accessed_at": accessed,
                },
                "raw": {"line": json.dumps(_raw_src, default=str)},
            }
        except Exception as exc:
            raise PluginFatalError(f"LNK extraction failed: {exc}") from exc

    def get_stats(self) -> dict[str, Any]:
        return {"records_read": self._records_read}
