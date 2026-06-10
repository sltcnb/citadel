"""
Registry Plugin — parses Windows Registry hive files (NTUSER.DAT, SYSTEM, SAM, etc.).
Requires: python-registry (pip install python-registry)

Each key with values yields one or more events:
  • Significant keys (Run, Services, IFEO, …) → one event per relevant value
    with a context-aware message and artifact_type.
  • Service keys with ImagePath → one consolidated service event.
  • All other keys with values → one event per key with a summary message
    that includes the first few value names and data.
"""

from __future__ import annotations

import base64
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    from Registry import Registry

    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

try:
    from utils.enrichment import (
        classify_registry_key,
        decode_service_start,
        decode_service_type,
    )

    _ENRICHMENT = True
except ImportError:
    _ENRICHMENT = False

HIVE_FILENAMES = {
    "NTUSER.DAT",
    "USRCLASS.DAT",
    "SYSTEM",
    "SOFTWARE",
    "SAM",
    "SECURITY",
    "DEFAULT",
    "COMPONENTS",
    "BCD",
    "AMCACHE.HVE",
}

# How many value name=data pairs to show in the generic summary message
_MAX_SUMMARY_VALUES = 4
# Max chars for a single value data string in the message
_MAX_VAL_LEN = 120


def _shorten(s: str, n: int = _MAX_VAL_LEN) -> str:
    s = s.replace("\n", " ").replace("\r", "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _value_payload(val: Any) -> dict[str, Any]:
    """Capture a registry value with FULL fidelity — never truncate.

    Returns a dict with:
      type        — REG_SZ / REG_DWORD / REG_BINARY / REG_MULTI_SZ / …
      data        — Python-native value (str / int / list[str] / etc)
      data_b64    — base64 of raw bytes (REG_BINARY only)
      data_str    — printable summary, also used for searchable indexed text
    """
    try:
        v_type = val.value_type_str()
    except Exception:
        v_type = "REG_UNKNOWN"
    try:
        raw_val = val.value()
    except Exception:
        return {"type": v_type, "data": "", "data_str": "", "error": "value() raised"}

    out: dict[str, Any] = {"type": v_type}
    if isinstance(raw_val, bytes):
        # Binary preserved in full via base64. data_str remains hex preview
        # so it's still searchable and human-glanceable in EventDetail.
        out["data_b64"] = base64.b64encode(raw_val).decode("ascii")
        out["data_len"] = len(raw_val)
        out["data"] = raw_val.hex()
        out["data_str"] = raw_val[:64].hex() + ("…" if len(raw_val) > 64 else "")
    elif isinstance(raw_val, list):
        # REG_MULTI_SZ — keep individual strings
        out["data"] = [str(s) for s in raw_val]
        out["data_str"] = " | ".join(str(s) for s in raw_val)
    elif isinstance(raw_val, int):
        out["data"] = raw_val
        out["data_str"] = str(raw_val)
    else:
        s = str(raw_val)
        out["data"] = s
        out["data_str"] = s
    return out


def _v(values: dict, *names: str) -> str:
    """Return the printable data of the first matching value name (case-insensitive)."""
    nl = {k.lower(): v.get("data_str", v.get("data", "")) for k, v in values.items()}
    for name in names:
        val = nl.get(name.lower())
        if val:
            return val
    return ""


class RegistryPlugin(BasePlugin):
    PLUGIN_NAME = "registry"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "registry"
    SUPPORTED_EXTENSIONS = [".hive"]
    # Windows registry hive (regf) — no IANA type; de-facto forensic MIME.
    SUPPORTED_MIME_TYPES = ["application/x-ms-registry-hive"]

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(HIVE_FILENAMES)

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def setup(self) -> None:
        if not REGISTRY_AVAILABLE:
            raise PluginFatalError(
                "python-registry is not installed. Run: pip install python-registry"
            )

    def parse(self) -> Generator[dict[str, Any], None, None]:
        try:
            reg = Registry.Registry(str(self.ctx.source_file_path))
        except Exception as exc:
            raise PluginFatalError(f"Cannot open registry hive: {exc}") from exc

        # ── 1. Hive-level summary event ──────────────────────────────────────
        # Always emitted. Gives analysts something to find for SAM-like hives
        # whose key values are encrypted/empty and would otherwise yield nothing.
        hive_name = self.ctx.source_file_path.name
        hive_type = _detect_hive_type(reg, hive_name)
        try:
            mtime = datetime.fromtimestamp(
                self.ctx.source_file_path.stat().st_mtime, tz=UTC
            ).isoformat()
        except Exception:
            mtime = datetime.now(UTC).isoformat()
        try:
            top_keys = [sk.name() for sk in reg.root().subkeys()]
        except Exception:
            top_keys = []
        try:
            size_bytes = self.ctx.source_file_path.stat().st_size
        except Exception:
            size_bytes = 0

        self._records_read += 1
        yield {
            "artifact_type": "registry_hive",
            "timestamp": mtime,
            "timestamp_desc": "Hive file mtime",
            "message": f"[Hive: {hive_type}] {hive_name} — {len(top_keys)} top-level keys"
            + (f": {', '.join(top_keys[:8])}" if top_keys else ""),
            "registry_hive": {
                "hive_type": hive_type,
                "filename": hive_name,
                "top_keys": top_keys,
                "size_bytes": size_bytes,
                "root_key_name": _safe(lambda: reg.root().name()) or "",
            },
            "raw": {
                "hive_type": hive_type,
                "filename": hive_name,
                "top_keys": top_keys,
                "size_bytes": size_bytes,
            },
        }

        # ── 2. Walk all keys ─────────────────────────────────────────────────
        for event in self._walk_key(reg.root(), ""):
            yield event

        # ── 3. SAM-specific user extraction ──────────────────────────────────
        # python-registry can read SAM key structure but values under V/F are
        # opaque. The Names subkey, though, holds one subkey per local user —
        # name = username, value-TYPE = RID. Emit one event per user so SAM
        # ingest is genuinely useful instead of just a hive summary.
        if hive_type == "SAM":
            for event in self._extract_sam_users(reg):
                yield event

    # ── Per-key dispatcher ───────────────────────────────────────────────────

    def _walk_key(self, key: Any, path: str) -> Generator[dict[str, Any], None, None]:
        full_path = f"{path}\\{key.name()}" if path else key.name()

        try:
            timestamp = key.timestamp().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        except Exception:
            timestamp = ""

        values: dict[str, dict] = {}
        try:
            for val in key.values():
                try:
                    values[val.name() or "(Default)"] = _value_payload(val)
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Skipped values of %s: %s", full_path, exc)

        if values:
            yield from self._emit(full_path, key, values, timestamp)

        try:
            for subkey in key.subkeys():
                try:
                    yield from self._walk_key(subkey, full_path)
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped subkey %s: %s", full_path, exc)
        except Exception as exc:
            self._records_skipped += 1
            self.log.debug("Skipped subkeys of %s: %s", full_path, exc)

    def _emit(
        self,
        full_path: str,
        key: Any,
        values: dict,
        timestamp: str,
    ) -> Generator[dict[str, Any], None, None]:
        if _ENRICHMENT:
            label, atype, mitre_id = classify_registry_key(full_path)
        else:
            label, atype, mitre_id = "", "registry", ""

        base_registry = {
            "key_path": full_path,
            "key_name": key.name(),
            "last_write_time": timestamp,
            "subkey_count": key.number_of_subkeys(),
            "value_count": key.number_of_values(),
            "values": values,
        }

        # ── Service key (has ImagePath) ──────────────────────────────────────
        if label == "Service" and _v(values, "ImagePath"):
            yield from self._emit_service(
                full_path, key.name(), values, timestamp, base_registry, mitre_id
            )
            return

        # ── AutoRun / per-value persistence keys ────────────────────────────
        if label in (
            "AutoRun",
            "AutoRun Once",
            "AutoRun Services",
            "AutoRun Svc Once",
            "CMD AutoRun",
        ):
            for val_name, val_info in values.items():
                data = _shorten(str(val_info.get("data_str", val_info.get("data", ""))))
                msg = f"[{label}] {val_name} = {data}"
                self._records_read += 1
                yield {
                    "artifact_type": atype,
                    "timestamp": timestamp,
                    "timestamp_desc": "Key Last Write Time",
                    "message": msg,
                    "mitre": {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
                    "registry": {**base_registry, "matched_value": val_name},
                    "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
                }
            return

        # ── IFEO — flag if a Debugger value is present (hijack indicator) ───
        if label == "IFEO":
            debugger = _v(values, "Debugger")
            if debugger:
                msg = f"[IFEO Hijack] {key.name()} — Debugger = {_shorten(debugger)}"
            else:
                # IFEO key but no debugger — likely legitimate; generic summary
                msg = f"[IFEO] {key.name()} — {_generic_value_summary(values)}"
            self._records_read += 1
            yield {
                "artifact_type": atype if debugger else "registry",
                "timestamp": timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message": msg,
                "mitre": {"id": mitre_id, "tactic": "Persistence"}
                if (mitre_id and debugger)
                else {},
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── AppInit / Boot Execute / AppCertDLL — flag the DLL list ─────────
        if label in ("AppInit DLL", "Boot Execute", "AppCertDLL"):
            data_str = _v(values, "AppInit_DLLs", "BootExecute", "(Default)") or str(
                next(iter(values.values())).get("data_str", "")
            )
            msg = f"[{label}] {_shorten(data_str)}"
            self._records_read += 1
            yield {
                "artifact_type": atype,
                "timestamp": timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message": msg,
                "mitre": {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── Recent Docs / MRU — user activity evidence ───────────────────────
        if label in ("Recent Doc", "File Dialog MRU", "App Open MRU"):
            count = len(values)
            sample = ", ".join(
                _shorten(str(v.get("data_str", "")), 60)
                for v in list(values.values())[:3]
                if v.get("data_str") and v.get("data_str") != "(Default)"
            )
            msg = (
                f"[{label}] {count} entries — {sample}" if sample else f"[{label}] {count} entries"
            )
            self._records_read += 1
            yield {
                "artifact_type": atype,
                "timestamp": timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message": msg,
                "mitre": {"id": mitre_id} if mitre_id else {},
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── USB device ────────────────────────────────────────────────────────
        if label == "USB Device":
            friendly = _v(values, "FriendlyName", "DeviceDesc", "(Default)")
            serial = key.name()
            msg = f"[USB] {friendly or serial}"
            if friendly and serial != friendly:
                msg += f" (S/N: {serial})"
            self._records_read += 1
            yield {
                "artifact_type": atype,
                "timestamp": timestamp,
                "timestamp_desc": "Device First Seen",
                "message": msg,
                "mitre": {"id": mitre_id} if mitre_id else {},
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── TCP/IP config ─────────────────────────────────────────────────────
        if label == "TCP/IP Config":
            hostname = _v(values, "Hostname", "ComputerNamePhysicalDnsHostname")
            domain = _v(values, "Domain", "DhcpDomain")
            ip = _v(values, "DhcpIPAddress", "IPAddress")
            parts: list[str] = []
            if hostname:
                parts.append(f"host={hostname}")
            if domain:
                parts.append(f"domain={domain}")
            if ip:
                parts.append(f"ip={ip}")
            detail = ", ".join(parts) if parts else _generic_value_summary(values)
            msg = f"[TCP/IP] {detail}"
            self._records_read += 1
            yield {
                "artifact_type": atype,
                "timestamp": timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message": msg,
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── SAM user account ──────────────────────────────────────────────────
        if label == "SAM User":
            msg = f"[SAM Account] {key.name()}"
            self._records_read += 1
            yield {
                "artifact_type": atype,
                "timestamp": timestamp,
                "timestamp_desc": "Account Last Modified",
                "message": msg,
                "mitre": {"id": mitre_id} if mitre_id else {},
                "registry": base_registry,
                "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
            }
            return

        # ── Generic enriched key event ────────────────────────────────────────
        if label:
            msg = f"[{label}] {full_path} — {_generic_value_summary(values)}"
        else:
            msg = f"[Registry] {full_path} — {_generic_value_summary(values)}"

        self._records_read += 1
        yield {
            "artifact_type": atype,
            "timestamp": timestamp,
            "timestamp_desc": "Key Last Write Time",
            "message": msg,
            "mitre": {"id": mitre_id} if mitre_id else {},
            "registry": base_registry,
            "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
        }

    # ── Service builder ──────────────────────────────────────────────────────

    def _emit_service(
        self,
        full_path: str,
        svc_name: str,
        values: dict,
        timestamp: str,
        base_registry: dict,
        mitre_id: str,
    ) -> Generator[dict[str, Any], None, None]:
        image_path = _shorten(_v(values, "ImagePath"), 200)
        display_name = _v(values, "DisplayName") or svc_name
        start_raw = _v(values, "Start")
        type_raw = _v(values, "Type")
        object_name = _v(values, "ObjectName")  # run-as account

        start_label = decode_service_start(start_raw) if start_raw else ""
        type_label = decode_service_type(type_raw) if type_raw else ""
        account_part = f" as {object_name}" if object_name else ""

        meta_parts = [p for p in [start_label, type_label] if p]
        meta_str = f" [{', '.join(meta_parts)}]" if meta_parts else ""

        msg = f"[Service] {display_name} — {image_path}{meta_str}{account_part}"

        self._records_read += 1
        yield {
            "artifact_type": "persistence",
            "timestamp": timestamp,
            "timestamp_desc": "Service Key Last Write",
            "message": msg,
            "mitre": {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
            "process": {"name": svc_name, "path": image_path},
            "registry": base_registry,
            "raw": {"key_path": full_path, "last_write_time": timestamp, "values": values},
        }

    # ── SAM user extraction ──────────────────────────────────────────────────

    def _extract_sam_users(self, reg: Any) -> Generator[dict[str, Any], None, None]:
        # Try both shapes seen in the wild:
        #   SAM\Domains\Account\Users\Names           (hive root has no "SAM" prefix)
        #   SAM\SAM\Domains\Account\Users\Names       (hive root with extra "SAM")
        names_key = _find_subkey(
            reg.root(), "SAM", "Domains", "Account", "Users", "Names"
        ) or _find_subkey(reg.root(), "Domains", "Account", "Users", "Names")
        if names_key is None:
            self.log.debug("SAM hive: Users\\Names key not found — skipping user extraction")
            return

        try:
            subs = list(names_key.subkeys())
        except Exception as exc:
            self.log.debug("SAM users: subkeys() raised: %s", exc)
            return

        for sk in subs:
            username = sk.name()
            # The default (unnamed) value's TYPE encodes the RID for this user.
            rid_int = None
            try:
                for v in sk.values():
                    if v.name() in ("", "(Default)"):
                        try:
                            rid_int = int(v.value_type())
                        except Exception:
                            rid_int = None
                        break
            except Exception:
                pass
            rid_hex = f"0x{rid_int:08X}" if isinstance(rid_int, int) else ""

            try:
                user_ts = sk.timestamp().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
            except Exception:
                user_ts = ""

            self._records_read += 1
            yield {
                "artifact_type": "user_account",
                "timestamp": user_ts,
                "timestamp_desc": "SAM Names key Last Write",
                "message": f"[SAM Account] {username}" + (f" (RID {rid_hex})" if rid_hex else ""),
                "user": {
                    "name": username,
                    "id": rid_hex,
                },
                "registry": {
                    "key_path": f"SAM\\Domains\\Account\\Users\\Names\\{username}",
                    "key_name": username,
                    "last_write_time": user_ts,
                },
                "raw": {
                    "username": username,
                    "rid": rid_hex,
                    "last_write_time": user_ts,
                    "source": "SAM\\Domains\\Account\\Users\\Names",
                },
            }

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


def _find_subkey(key: Any, *names: str) -> Any:
    """Walk a chain of subkeys by name, case-insensitive. Return the last
    key reached, or None if any step is missing."""
    cur = key
    for n in names:
        target = n.lower()
        try:
            cur = next((sk for sk in cur.subkeys() if sk.name().lower() == target), None)
        except Exception:
            return None
        if cur is None:
            return None
    return cur


def _detect_hive_type(reg: Any, filename: str) -> str:
    """Best-effort hive type identification. Filename is authoritative because
    SAM/SYSTEM/SOFTWARE hives don't carry a self-identifying root key."""
    upper = filename.upper()
    for known in (
        "NTUSER.DAT",
        "USRCLASS.DAT",
        "SYSTEM",
        "SOFTWARE",
        "SAM",
        "SECURITY",
        "DEFAULT",
        "COMPONENTS",
        "BCD",
        "AMCACHE.HVE",
    ):
        if upper == known or upper.endswith("\\" + known):
            return known
    # Fall back to the root key name (only meaningful for NTUSER/UsrClass)
    root_name = _safe(lambda: reg.root().name()) or ""
    if "USER" in root_name.upper():
        return "NTUSER.DAT"
    if "CMI-CREATE" in root_name.upper():
        return "SYSTEM"
    return "UNKNOWN"


def _generic_value_summary(values: dict) -> str:
    """Return a compact 'name=data, ...' summary of the first few values."""
    parts: list[str] = []
    for name, info in list(values.items())[:_MAX_SUMMARY_VALUES]:
        data = _shorten(str(info.get("data_str", "")), 60)
        parts.append(f"{name}={data}" if data else name)
    suffix = (
        f" (+{len(values) - _MAX_SUMMARY_VALUES} more)" if len(values) > _MAX_SUMMARY_VALUES else ""
    )
    return ", ".join(parts) + suffix
