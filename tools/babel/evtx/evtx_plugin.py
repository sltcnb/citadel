"""
EVTX Plugin — parses Windows Event Log (.evtx) files.
Requires: python-evtx
"""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from collections.abc import Generator
from typing import Any

try:
    import Evtx.Evtx as evtx_lib

    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, PluginParseError

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _basename(path: str) -> str:
    """Return the file basename for a Windows or Unix path. Empty if no path."""
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _extract_hash(hashes_field: str, algo: str) -> str:
    """Sysmon's Hashes field is like 'MD5=...,SHA1=...,SHA256=...,IMPHASH=...'."""
    if not hashes_field:
        return ""
    for part in hashes_field.split(","):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0].upper() == algo:
            return kv[1].strip().lower()
    return ""


# Maps Windows log level int → human label
LEVEL_MAP = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

# Common Security event ID → description
EVTID_DESC = {
    4624: "Account logon success",
    4625: "Account logon failure",
    4648: "Logon with explicit credentials",
    4688: "Process creation",
    4689: "Process termination",
    4698: "Scheduled task created",
    4702: "Scheduled task modified",
    4720: "User account created",
    4722: "User account enabled",
    4723: "Password change attempt",
    4724: "Password reset attempt",
    4725: "User account disabled",
    4726: "User account deleted",
    4728: "Member added to global group",
    4732: "Member added to local group",
    4738: "User account changed",
    4740: "User account locked out",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4771: "Kerberos pre-auth failed",
    4776: "NTLM authentication attempt",
    4779: "Session disconnected",
    7045: "New service installed",
    1102: "Audit log cleared",
    4104: "PowerShell script block logging",
    4103: "PowerShell module logging",
}


class EvtxPlugin(BasePlugin):
    PLUGIN_NAME = "evtx"
    PLUGIN_PRIORITY = 100
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "evtx"
    SUPPORTED_EXTENSIONS = [".evtx"]
    SUPPORTED_MIME_TYPES = ["application/x-winevt"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0
        self._log_file = None

    def setup(self) -> None:
        if not EVTX_AVAILABLE:
            raise PluginFatalError("python-evtx is not installed. Run: pip install python-evtx")

    def parse(self) -> Generator[dict[str, Any], None, None]:
        try:
            with evtx_lib.Evtx(str(self.ctx.source_file_path)) as log:
                for record in log.records():
                    try:
                        event = self._record_to_event(record)
                        self._records_read += 1
                        yield event
                    except PluginParseError:
                        self._records_skipped += 1
                        self.log.debug("Skipped record %s", record.record_num())
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.warning("Skipped record %s: %s", record.record_num(), exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot open EVTX file: {exc}") from exc

    def _record_to_event(self, record) -> dict[str, Any]:
        try:
            xml_str = record.xml()
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise PluginParseError(f"Bad XML in record: {exc}") from exc

        sys_node = root.find(f"{{{NS}}}System")
        data_node = root.find(f"{{{NS}}}EventData")
        user_data_node = root.find(f"{{{NS}}}UserData")

        def sys_text(tag: str) -> str:
            if sys_node is None:
                return ""
            n = sys_node.find(f"{{{NS}}}{tag}")
            return (n.text or "") if n is not None else ""

        def sys_attr(tag: str, attr: str, default: str = "") -> str:
            if sys_node is None:
                return default
            n = sys_node.find(f"{{{NS}}}{tag}")
            return n.get(attr, default) if n is not None else default

        event_id = int(sys_text("EventID") or 0)
        timestamp = self._normalize_timestamp(sys_attr("TimeCreated", "SystemTime"))
        channel = sys_text("Channel")
        computer = sys_text("Computer")
        provider = sys_attr("Provider", "Name")
        record_id = int(sys_text("EventRecordID") or 0)
        level = int(sys_text("Level") or 0)
        task = int(sys_text("Task") or 0)
        opcode = int(sys_text("Opcode") or 0)
        keywords = sys_attr("Keywords", "Name") or sys_text("Keywords")
        correlation_id = sys_attr("Correlation", "ActivityID")

        # Security Subject SID
        subject_sid = ""
        security_node = sys_node.find(f"{{{NS}}}Security") if sys_node is not None else None
        if security_node is not None:
            subject_sid = security_node.get("UserID", "")

        # EventData key-value pairs
        event_data: dict[str, str] = {}
        if data_node is not None:
            for child in data_node:
                name = child.get("Name") or child.tag.split("}")[-1]
                event_data[name] = child.text or ""
        elif user_data_node is not None:
            # Flatten UserData (nested XML)
            for child in user_data_node:
                for grandchild in child:
                    name = grandchild.tag.split("}")[-1]
                    event_data[name] = grandchild.text or ""

        description = EVTID_DESC.get(event_id, f"EventID {event_id}")
        message = f"{description} on {computer}"
        if channel:
            message += f" [{channel}]"

        # Build a granular process dict — many EventData keys, varying per event
        # ID. Pull from the most-likely source for each canonical field.
        process_path = (
            event_data.get("NewProcessName")
            or event_data.get("Image")
            or event_data.get("ProcessName")
            or ""
        )
        parent_path = event_data.get("ParentProcessName") or event_data.get("ParentImage") or ""
        process_dict = {
            "name": _basename(process_path) or event_data.get("ProcessName", ""),
            "executable_name": _basename(process_path),
            "path": process_path,
            "command_line": event_data.get("CommandLine", "")
            or event_data.get("ProcessCommandLine", ""),
            "pid": self._parse_pid(
                event_data.get("NewProcessId") or event_data.get("ProcessId", "")
            ),
            "ppid": self._parse_pid(event_data.get("ParentProcessId", "")),
            "parent_name": _basename(parent_path),
            "parent_executable": _basename(parent_path),
            "parent_path": parent_path,
            "parent_command_line": event_data.get("ParentCommandLine", ""),
            "parent_pid": self._parse_pid(event_data.get("ParentProcessId", "")),
            "user": event_data.get("User", "") or event_data.get("SubjectUserName", ""),
            "integrity_level": event_data.get("IntegrityLevel", "")
            or event_data.get("MandatoryLabel", ""),
            "logon_id": event_data.get("LogonId", "") or event_data.get("SubjectLogonId", ""),
            "hash_md5": _extract_hash(event_data.get("Hashes", ""), "MD5"),
            "hash_sha1": _extract_hash(event_data.get("Hashes", ""), "SHA1"),
            "hash_sha256": _extract_hash(event_data.get("Hashes", ""), "SHA256"),
        }
        # Strip empty values to keep the document compact
        process_dict = {k: v for k, v in process_dict.items() if v not in ("", None)}

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "evtx",
            "timestamp": timestamp,
            "timestamp_desc": "Event Log Timestamp",
            "message": message,
            "host": {
                "hostname": computer,
            },
            "user": {
                "name": event_data.get("TargetUserName", event_data.get("SubjectUserName", "")),
                "domain": event_data.get(
                    "TargetDomainName", event_data.get("SubjectDomainName", "")
                ),
                "sid": event_data.get(
                    "TargetUserSid", event_data.get("SubjectUserSid", subject_sid)
                ),
                "id": event_data.get("SubjectLogonId", event_data.get("LogonID", "")),
            },
            "process": process_dict,
            "network": {
                "src_ip": event_data.get("IpAddress", "")
                or event_data.get("SourceAddress", "")
                or event_data.get("SourceIp", ""),
                "src_port": self._parse_pid(
                    event_data.get("IpPort", "") or event_data.get("SourcePort", "")
                ),
                "dst_ip": event_data.get("DestinationIp", "") or event_data.get("DestAddress", ""),
                "dst_port": self._parse_pid(
                    event_data.get("DestinationPort", "") or event_data.get("DestPort", "")
                ),
                "protocol": event_data.get("Protocol", ""),
                "workstation": event_data.get("WorkstationName", ""),
            },
            "evtx": {
                "event_id": event_id,
                "channel": channel,
                "provider_name": provider,
                "record_id": record_id,
                "level": level,
                "level_name": LEVEL_MAP.get(level, str(level)),
                "task": task,
                "opcode": opcode,
                "keywords": keywords,
                "computer": computer,
                "correlation_activity_id": correlation_id,
                "event_data": event_data,
                "description": description,
            },
            "raw": {"xml": xml_str},
        }

    @staticmethod
    def _normalize_timestamp(ts: str) -> str:
        """
        Normalize EVTX timestamps to ES-compatible ISO 8601.

        python-evtx formats SystemTime as 'YYYY-MM-DD HH:MM:SS.ffffff'
        (space separator, no timezone suffix). ES strict_date_optional_time
        requires 'YYYY-MM-DDTHH:MM:SS.mmmZ' (T separator, Z suffix, max 3
        fractional digits). This function handles all three issues.
        """
        if not ts:
            return ts

        # 1. Replace space date/time separator with T
        ts = ts.replace(" ", "T", 1)

        # 2. Truncate fractional seconds to milliseconds (3 digits max)
        dot = ts.find(".")
        if dot != -1:
            end = dot + 1
            while end < len(ts) and ts[end].isdigit():
                end += 1
            suffix = ts[end:]  # existing tz suffix (may be empty)
            frac = ts[dot + 1 : end]
            frac = (frac + "000")[:3]  # normalise to exactly 3 digits
            ts = ts[: dot + 1] + frac + suffix

        # 3. Append Z if no timezone info present
        if not (ts.endswith("Z") or "+" in ts[10:] or ts[-3] == ":"):
            ts += "Z"

        return ts

    def _parse_pid(self, pid_str: str) -> int | None:
        if not pid_str:
            return None
        try:
            if pid_str.startswith("0x") or pid_str.startswith("0X"):
                return int(pid_str, 16)
            return int(pid_str)
        except ValueError:
            return None

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
