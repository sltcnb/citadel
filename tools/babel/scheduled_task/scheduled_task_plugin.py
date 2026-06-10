"""
Windows Scheduled Task plugin — parses UTF-16 XML task definition files
collected by fo-harvester's 'persistence' artifact category.

Files are named after the task (no extension) and stored as UTF-16 LE XML
with a BOM. They live under paths like:
    persistence/tasks/System32/SilentCleanup
    persistence/tasks/SysWOW64/Backup

Routing: utils/file_type.py emits MIME 'application/x-windows-task' for any
file whose path contains a 'tasks' directory component.

Priority 100 — wins over json_file (15) and strings fallback (1).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

try:
    from utils.enrichment import format_trigger, resolve_sid

    _ENRICHMENT = True
except ImportError:
    _ENRICHMENT = False

# Windows Task Scheduler XML namespace (v1.2 — used since Vista)
_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _t(local: str) -> str:
    return f"{{{_NS}}}{local}"


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


class ScheduledTaskPlugin(BasePlugin):
    PLUGIN_NAME = "scheduled_task"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "persistence"
    PLUGIN_PRIORITY = 100
    SUPPORTED_MIME_TYPES = ["application/x-windows-task"]
    SUPPORTED_EXTENSIONS = []

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if mime_type in cls.SUPPORTED_MIME_TYPES:
            return True
        parts = {p.lower() for p in file_path.parts}
        if "tasks" not in parts and "scheduled_tasks" not in parts:
            return False
        try:
            header = file_path.read_bytes()[:32]
            return header[:2] in (b"\xff\xfe", b"\xfe\xff") or b"<?xml" in header
        except Exception:
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            raw_bytes = path.read_bytes()
            if raw_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"):
                text = raw_bytes.decode("utf-16")
            else:
                text = raw_bytes.decode("utf-8", errors="replace")
            root = ET.fromstring(text)
        except Exception as exc:
            raise PluginFatalError(f"Cannot parse task XML '{path.name}': {exc}") from exc

        # ── Task identity ──────────────────────────────────────────────────────
        uri_el = root.find(f"{_t('RegistrationInfo')}/{_t('URI')}")
        task_name = _text(uri_el).lstrip("\\") or path.name

        desc_el = root.find(f"{_t('RegistrationInfo')}/{_t('Description')}")
        desc = _text(desc_el)

        author_el = root.find(f"{_t('RegistrationInfo')}/{_t('Author')}")
        author = _text(author_el)

        # ── Settings ──────────────────────────────────────────────────────────
        enabled_el = root.find(f"{_t('Settings')}/{_t('Enabled')}")
        enabled = _text(enabled_el).lower() != "false"

        # ── Principal (who runs the task) ──────────────────────────────────────
        principal_el = root.find(f".//{_t('Principal')}")
        user_id = ""
        run_level = "LeastPrivilege"
        group_id = ""
        if principal_el is not None:
            user_id = _text(principal_el.find(_t("UserId")))
            run_level = _text(principal_el.find(_t("RunLevel"))) or "LeastPrivilege"
            group_id = _text(principal_el.find(_t("GroupId")))

        # Resolve SID to human name if possible
        principal_raw = user_id or group_id
        if _ENRICHMENT:
            principal_display = resolve_sid(principal_raw) or principal_raw
        else:
            principal_display = principal_raw

        # ── Actions ────────────────────────────────────────────────────────────
        actions: list[dict] = []
        for exec_el in root.findall(f".//{_t('Exec')}"):
            cmd = _text(exec_el.find(_t("Command")))
            args = _text(exec_el.find(_t("Arguments")))
            wdir = _text(exec_el.find(_t("WorkingDirectory")))
            if cmd:
                actions.append({"command": cmd, "arguments": args, "working_dir": wdir})

        for com_el in root.findall(f".//{_t('ComHandler')}"):
            clsid = _text(com_el.find(_t("ClassId")))
            if clsid:
                actions.append({"command": f"COM:{clsid}", "arguments": "", "working_dir": ""})

        # ── Triggers ───────────────────────────────────────────────────────────
        triggers: list[dict] = []
        triggers_el = root.find(_t("Triggers"))
        if triggers_el is not None:
            for trigger in triggers_el:
                tag = trigger.tag.split("}")[-1] if "}" in trigger.tag else trigger.tag
                start = _text(trigger.find(_t("StartBoundary")))
                repeat_interval = _text(trigger.find(f"{_t('Repetition')}/{_t('Interval')}"))
                triggers.append(
                    {
                        "type": tag,
                        "start": start,
                        "repeat_interval": repeat_interval,
                    }
                )

        # ── Build human-readable message ───────────────────────────────────────
        status_str = "ENABLED" if enabled else "DISABLED"

        # Trigger summary
        if triggers and _ENRICHMENT:
            trigger_str = "; ".join(format_trigger(t) for t in triggers[:3])
        elif triggers:
            trigger_str = triggers[0].get("type", "unknown trigger")
        else:
            trigger_str = "no trigger"

        # Action summary
        action_str = (
            "; ".join(
                a["command"] + (f" {a['arguments']}" if a["arguments"] else "") for a in actions
            )
            or "(no action)"
        )

        # Principal display
        run_as_str = principal_display or "unknown account"
        if run_level.lower() == "highestprivilege" and run_as_str:
            run_as_str += " [elevated]"

        # Task name without path prefix for display
        display_name = task_name.split("\\")[-1] if "\\" in task_name else task_name

        message = (
            f"[{status_str}] {display_name} | "
            f"Trigger: {trigger_str} | "
            f"Action: {action_str} | "
            f"Run as: {run_as_str}"
        )

        # MITRE: T1053.005 — Scheduled Task
        mitre = {
            "id": "T1053.005",
            "tactic": "Persistence, Privilege Escalation",
            "technique": "Scheduled Task/Job: Scheduled Task",
        }

        timestamp = datetime.now(UTC).isoformat()

        yield {
            "timestamp": timestamp,
            "timestamp_desc": "Scheduled Task Definition",
            "message": message,
            "artifact_type": "persistence",
            "mitre": mitre,
            "user": {
                "name": principal_display or principal_raw,
                "id": user_id,
            },
            "process": {
                # First exec action, if any
                "name": (actions[0]["command"].split("\\")[-1].split("/")[-1] if actions else ""),
                "command_line": (
                    actions[0]["command"] + " " + actions[0]["arguments"] if actions else ""
                ).strip(),
            },
            "raw": {
                "task_name": task_name,
                "task_path": task_name,
                "description": desc,
                "author": author,
                "enabled": enabled,
                "run_level": run_level,
                "user_id": user_id,
                "group_id": group_id,
                "actions": actions,
                "triggers": triggers,
            },
        }
