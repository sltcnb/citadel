"""Alert anchors — the concrete observables an alert hands the investigator.

An SMB-drop alert named a source IP, a source port, an account and a host. The
agent identified the IP, never searched the port (which pins the exact logon
session), and let the account mismatch drop out of its conclusion. Nothing in
the loop knew those observables existed, so nothing noticed they were skipped.

This module extracts them from the scenario text and reports, against the
transcript, which ones a tool call has actually touched. The loop shows the
untested ones every turn and refuses a conclusion while any remain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_PORT = re.compile(r"(?i)\b(?:source|src|destination|dest|dst|remote|local)?\s*port\s*[:=]?\s*(\d{2,5})\b")
# "Compte(s) : a, b" / "Account: a" / "User: a" — value runs to end of line.
_ACCOUNT_LINE = re.compile(r"(?im)^\s*(?:comptes?|accounts?|users?|utilisateurs?)\s*:\s*(.+)$")
# Service-style account names (app_x, sa_x, svc_x, adm_x) wherever they appear.
_ACCOUNT_TOKEN = re.compile(r"(?i)\b(?:app|sa|svc|srv|adm|admin)_[a-z0-9][a-z0-9._-]{2,}\b")
_HOST_LINE = re.compile(r"(?im)^\s*(?:machines?|hosts?|hôtes?|computers?|endpoints?)\s*:\s*(.+)$")
_SHARE = re.compile(r"\b([A-Za-z]{1,12}\$)(?=\W|$)")
_FILE = re.compile(r"\b([\w-]{6,}\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|hta|lnk|scr|zip|7z|rar|iso|quq|tmp|dat|bin|msi))\b", re.I)
# Full Windows paths (drive or UNC), taken verbatim — backslashes included.
_PATH = re.compile(r"(?<![\w\\])((?:[A-Za-z]:\\|\\\\[\w.$-]+\\)[^\s\"'<>|*?]+)")
# Join keys: the values that tie an alert to one session / process / trace.
_LOGON_ID = re.compile(r"(?i)\blogon\s*id\s*[:=]?\s*(0x[0-9a-f]{2,16})\b")
_PID = re.compile(r"(?i)\b(?:pid|process\s*id)\s*[:=]?\s*(\d{1,7})\b")
_SESSION_ID = re.compile(r"(?i)\bsession\s*id\s*[:=]?\s*([0-9a-fx{}-]{1,40})\b")
_CORRELATION_ID = re.compile(
    r"(?i)\b(?:correlation|activity)\s*id\s*[:=]?\s*\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?"
)

# Built-in identities that every Windows host shows — not an anchor.
_NOISE_ACCOUNTS = {"nt authority\\system", "system", "local service", "network service"}

_RECIPES = {
    "port": (
        'network.src_port:{v}  → the 4624 with this source port is the logon '
        "session that carried the action: read its TargetUserName and TargetLogonId"
    ),
    "ip": "ioc_sweep / network.src_ip:{v}  → which machine (workstation) and accounts it used",
    "account": (
        'aggregate evtx.event_id with agg_query user.name.keyword:"{v}" OR '
        'evtx.event_data.TargetUserName.keyword:"{v}"  → how it logs on, from where, since when'
    ),
    "host": "host_profile {v}  → what evidence exists for it",
    "share": '*{v}*  → share access events (5140/5145) if that auditing is collected',
    "file": "*{v}*  → any artifact that recorded the file",
    "path": "*{v}*  → any artifact that recorded the path (keep the path verbatim in IOCs)",
    "logon_id": "session_pivot logon_id={v}  → the logon and everything done under it",
    "pid": "search process.pid:{v} OR evtx.event_data.ProcessId:*{v}*  → the process and its parent",
    "session_id": "search *{v}*  → events carrying this session identifier",
    "correlation_id": "search *{v}*  → events sharing this correlation / activity ID",
}

# Kinds that pin one session or trace: a conclusion without them tested cannot
# attribute the alert's action to an actor.
JOIN_KEYS = ("port", "logon_id", "pid", "session_id", "correlation_id")


@dataclass(frozen=True)
class Anchor:
    kind: str
    value: str

    def recipe(self) -> str:
        return _RECIPES[self.kind].format(v=self.value)


def _split_values(line: str) -> list[str]:
    return [v.strip(" .;") for v in re.split(r"[,;]| et | and ", line) if v.strip(" .;")]


def extract_anchors(text: str, limit: int = 16) -> list[Anchor]:
    """Observables named in an alert / scenario, deduplicated, in a stable order."""
    text = text or ""
    found: list[Anchor] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        value = value.strip()
        key = (kind, value.lower())
        if value and key not in seen:
            seen.add(key)
            found.append(Anchor(kind, value))

    for m in _PORT.finditer(text):
        add("port", m.group(1))
    for rx, kind in ((_LOGON_ID, "logon_id"), (_PID, "pid"), (_SESSION_ID, "session_id"),
                     (_CORRELATION_ID, "correlation_id")):
        for m in rx.finditer(text):
            add(kind, m.group(1))
    for ip in _IPV4.findall(text):
        add("ip", ip)
    account_lines = _ACCOUNT_LINE.findall(text)
    for line in account_lines:
        for v in _split_values(line):
            if v.lower() not in _NOISE_ACCOUNTS and len(v) <= 64 and " " not in v.split("\\")[-1]:
                add("account", v.split("\\")[-1])
    if not account_lines:
        # Only when the alert labels no accounts: a narrative mentions plenty of
        # names (who ran a lookup, who was asked) that are not observables.
        for tok in _ACCOUNT_TOKEN.findall(text):
            add("account", tok)
    for line in _HOST_LINE.findall(text):
        for v in _split_values(line):
            if 2 < len(v) <= 64 and " " not in v:
                add("host", v)
    for share in _SHARE.findall(text):
        add("share", share)
    for path in _PATH.findall(text):
        add("path", path.rstrip(".,;:)"))
    for f in _FILE.findall(text):
        # The basename is already covered when its full path was found.
        if not any(a.kind == "path" and a.value.endswith(f) for a in found):
            add("file", f)
    return found[:limit]


def _touched_text(step: dict) -> str:
    """Everything a tool call was asked about — the query side, not the result."""
    parts = []
    for k in ("query", "agg_query", "agg_field", "host", "user", "fo_id", "technique_id", "value"):
        v = step.get(k)
        if v:
            parts.append(str(v))
    for k in ("indicators", "values"):
        v = step.get(k)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
    for k in ("window",):
        v = step.get(k)
        if isinstance(v, dict):
            parts.extend(str(x) for x in v.values())
    return " ".join(parts).lower()


def anchor_status(anchors: list[Anchor], transcript: list[dict]) -> list[tuple[Anchor, int | None]]:
    """For each anchor, the first step whose tool call targeted it (None = untested)."""
    out = []
    for a in anchors:
        hit = None
        needle = a.value.lower()
        for s in transcript:
            if s.get("action") in (None, "conclude", "set_hypotheses", "error", "review"):
                continue
            if needle in _touched_text(s):
                hit = s.get("step")
                break
        out.append((a, hit))
    return out


def render_anchors(status: list[tuple[Anchor, int | None]]) -> str:
    if not status:
        return ""
    lines = [
        "\nALERT ANCHORS — the observables this alert names. Each must be tested "
        "against case data (or explicitly declared untestable, with the reason) "
        "before you conclude:"
    ]
    for a, step in status:
        if step is None:
            lines.append(f"  ✘ {a.kind} {a.value} — UNTESTED. Try: {a.recipe()}")
        else:
            lines.append(f"  ✔ {a.kind} {a.value} (step {step})")
    return "\n".join(lines) + "\n"
