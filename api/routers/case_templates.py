"""
Case templates — pre-canned investigation kits.

Each template defines:
  - tags applied to the case
  - watchlist IOCs to seed
  - alert rule IDs to enable (subset of the global library)
  - report skeleton (markdown stub written into analyst notes)
  - default name prefix

Apply via POST /cases/{case_id}/apply-template?template_id=ransomware.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime

from auth.dependencies import get_current_user, require_admin, require_case_access
from fastapi import APIRouter, Body, Depends, HTTPException, Query

from config import get_redis
from services.redis_mutate import mutate_json

logger = logging.getLogger(__name__)
router = APIRouter(tags=["case-templates"])

# Redis key for the user-defined templates layered over the built-ins below.
CUSTOM_KEY = "fo:case_templates:custom"


TEMPLATES: dict[str, dict] = {
    "ransomware": {
        "id": "ransomware",
        "name": "Ransomware",
        "description": "Pre-canned IOCs + Sigma rules + report skeleton for ransomware engagements.",
        "tags": ["ransomware"],
        "watchlist": [
            {
                "kind": "cmdline",
                "value": "vssadmin delete shadows",
                "label": "Shadow copy deletion",
            },
            {"kind": "cmdline", "value": "wmic shadowcopy delete", "label": "WMIC shadow delete"},
            {"kind": "cmdline", "value": "bcdedit /set safeboot", "label": "Safeboot tampering"},
            {
                "kind": "cmdline",
                "value": "wbadmin delete catalog",
                "label": "Backup catalog deletion",
            },
            {
                "kind": "regex",
                "value": "(\\.locked|\\.encrypted|README_TO_DECRYPT)",
                "label": "Ransom note / encrypted ext",
            },
        ],
        "rule_categories": [
            "sigma_hq/05_lateral_movement",
            "sigma_hq/13_credential_access",
            "sigma_hq/12_impact",
        ],
        "notes": (
            "# Ransomware investigation\n\n"
            "## Containment status\n_TODO_\n\n"
            "## Patient zero\n_TODO — first encrypted host + first execution timestamp_\n\n"
            "## TTPs observed\n- [ ] Initial access vector\n- [ ] Privilege escalation\n- [ ] Lateral movement\n- [ ] Defense evasion\n- [ ] Credential access\n- [ ] Discovery\n- [ ] Impact (encryption, exfiltration)\n\n"
            "## Affected scope\n- Hosts: _TODO_\n- Users: _TODO_\n- Data exposure: _TODO_\n\n"
            "## Recovery actions\n_TODO_\n"
        ),
    },
    "insider_threat": {
        "id": "insider_threat",
        "name": "Insider Threat",
        "description": "Watch for data hoarding, USB use, off-hours access.",
        "tags": ["insider-threat"],
        "watchlist": [
            {"kind": "cmdline", "value": "robocopy", "label": "Robocopy bulk transfer"},
            {"kind": "cmdline", "value": "powershell.*Compress", "label": "Bulk archive (PS)"},
            {"kind": "regex", "value": "(usbstor|portabledevices)", "label": "USB enumeration"},
            {"kind": "domain", "value": "dropbox.com", "label": "Cloud staging"},
            {"kind": "domain", "value": "mega.nz", "label": "Cloud staging (Mega)"},
            {"kind": "domain", "value": "wetransfer.com", "label": "Cloud staging (WeTransfer)"},
        ],
        "rule_categories": ["sigma_hq/09_collection", "sigma_hq/10_exfiltration"],
        "notes": (
            "# Insider threat investigation\n\n"
            "## Suspect identity\n_TODO_\n\n"
            "## Triggering signal\n_TODO_\n\n"
            "## Behaviour timeline\n- [ ] Off-hours access\n- [ ] USB events\n- [ ] Bulk file access / staging\n- [ ] Cloud upload\n- [ ] Outbound email (large attachments)\n\n"
            "## Data scope\n_TODO_\n"
        ),
    },
    "phishing": {
        "id": "phishing",
        "name": "Phishing / BEC",
        "description": "Mailbox rules, attachment macros, follow-on persistence.",
        "tags": ["phishing"],
        "watchlist": [
            {
                "kind": "cmdline",
                "value": "WINWORD.EXE.*-Embedding",
                "label": "Office macro execution",
            },
            {"kind": "cmdline", "value": "powershell.*FromBase64", "label": "Encoded PS payload"},
            {
                "kind": "regex",
                "value": "(Set-Mailbox.*ForwardingSMTPAddress|New-InboxRule)",
                "label": "Mailbox rule manipulation",
            },
        ],
        "rule_categories": ["sigma_hq/01_initial_access", "sigma_hq/02_execution"],
        "notes": (
            "# Phishing investigation\n\n"
            "## Initial vector\n_TODO — sender / subject / attachment hash_\n\n"
            "## Recipients & clicks\n_TODO_\n\n"
            "## Payload chain\n- [ ] Attachment / link analysis\n- [ ] First-stage execution\n- [ ] C2 callback\n- [ ] Persistence implant\n- [ ] Lateral movement\n\n"
            "## Mailbox manipulation\n- [ ] New inbox rules\n- [ ] Forwarding addresses\n- [ ] OAuth grants\n"
        ),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Custom-template store (Redis) layered over the built-in TEMPLATES above.
# Built-ins are read-only; custom templates are editable by admins.
# ─────────────────────────────────────────────────────────────────────────────


def _load_custom() -> dict[str, dict]:
    raw = get_redis().get(CUSTOM_KEY)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_template(tid: str) -> dict | None:
    """Resolve a template id, custom store taking precedence over built-ins.

    A custom entry stored under a *built-in* id is an admin edit of that
    built-in (an "override") — it shadows the shipped definition but the
    built-in remains as the reset target.
    """
    custom = _load_custom()
    if tid in custom:
        is_builtin = tid in TEMPLATES
        return {**custom[tid], "id": tid, "builtin": is_builtin, "overridden": is_builtin}
    if tid in TEMPLATES:
        return {**TEMPLATES[tid], "id": tid, "builtin": True}
    return None


def _all_templates() -> list[dict]:
    """Built-ins (with any admin override applied) first, then pure customs."""
    custom = _load_custom()
    out: list[dict] = []
    for tid, t in TEMPLATES.items():
        if tid in custom:
            out.append({**custom[tid], "id": tid, "builtin": True, "overridden": True})
        else:
            out.append({**t, "id": tid, "builtin": True})
    for tid, t in custom.items():
        if tid not in TEMPLATES:
            out.append({**t, "id": tid, "builtin": False})
    return out


def _slugify(name: str) -> str:
    s = re.sub(r"[^\w\s-]", "", name).strip().lower()
    s = re.sub(r"[\s_]+", "-", s)[:48].strip("-")
    return s or "template"


def _unique_id(name: str, custom: dict[str, dict]) -> str:
    base = _slugify(name)
    candidate = base
    n = 2
    while candidate in custom or candidate in TEMPLATES:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _validate_payload(data: dict) -> dict:
    """Validate + normalize a template create/update body. Raises HTTPException."""
    name = (data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    watchlist_in = data.get("watchlist") or []
    if not isinstance(watchlist_in, list):
        raise HTTPException(status_code=400, detail="watchlist must be a list")
    watchlist: list[dict] = []
    for ioc in watchlist_in:
        if not isinstance(ioc, dict):
            raise HTTPException(status_code=400, detail="watchlist entries must be objects")
        kind = (ioc.get("kind") or "").strip()
        value = (ioc.get("value") or "").strip()
        if not kind or not value:
            raise HTTPException(
                status_code=400, detail="each watchlist entry needs a kind and value"
            )
        watchlist.append(
            {"kind": kind, "value": value, "label": (ioc.get("label") or "").strip() or value}
        )

    def _str_list(v):
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        return []

    return {
        "name": name,
        "description": (data.get("description") or "").strip(),
        "tags": _str_list(data.get("tags")),
        "watchlist": watchlist,
        "rule_categories": _str_list(data.get("rule_categories")),
        "notes": data.get("notes") or "",
    }


@router.get("/case-templates")
def list_templates(_: dict = Depends(get_current_user)):
    return {
        "templates": [
            {
                "id": t["id"],
                "name": t["name"],
                "description": t["description"],
                "watchlist_count": len(t["watchlist"]),
                "tags": t["tags"],
                "builtin": t["builtin"],
                "overridden": bool(t.get("overridden")),
            }
            for t in _all_templates()
        ]
    }


@router.get("/case-templates/{template_id}")
def get_template_full(template_id: str, _: dict = Depends(get_current_user)):
    """Full editable template object (watchlist/rule_categories/notes)."""
    tpl = _get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return {
        "id": tpl["id"],
        "name": tpl["name"],
        "description": tpl.get("description", ""),
        "tags": tpl.get("tags", []),
        "watchlist": tpl.get("watchlist", []),
        "rule_categories": tpl.get("rule_categories", []),
        "notes": tpl.get("notes", ""),
        "builtin": tpl["builtin"],
    }


@router.post("/case-templates")
def create_template(data: dict = Body(...), _: dict = Depends(require_admin)):
    fields = _validate_payload(data)

    def _mutate(cur: dict) -> dict:
        tid = _unique_id(fields["name"], cur)
        cur[tid] = {
            **fields,
            "id": tid,
            "created_at": datetime.now(UTC).isoformat(),
        }
        _mutate.tid = tid  # type: ignore[attr-defined]
        return cur

    store = mutate_json(get_redis(), CUSTOM_KEY, _mutate, {})
    tid = _mutate.tid  # type: ignore[attr-defined]
    return {**store[tid], "builtin": False}


@router.put("/case-templates/{template_id}")
def update_template(template_id: str, data: dict = Body(...), _: dict = Depends(require_admin)):
    # Built-ins are editable: the edit is persisted as an override in the custom
    # store under the built-in's id, shadowing the shipped definition. The
    # built-in itself stays put so the edit can be reset (DELETE the override).
    is_builtin = template_id in TEMPLATES
    fields = _validate_payload(data)

    def _mutate(cur: dict) -> dict:
        if template_id not in cur and not is_builtin:
            raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
        base = cur.get(template_id) or TEMPLATES.get(template_id) or {}
        cur[template_id] = {
            **base,
            **fields,
            "id": template_id,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        return cur

    store = mutate_json(get_redis(), CUSTOM_KEY, _mutate, {})
    return {**store[template_id], "builtin": is_builtin, "overridden": is_builtin}


@router.delete("/case-templates/{template_id}")
def delete_template(template_id: str, _: dict = Depends(require_admin)):
    # For a custom template this deletes it. For a built-in with an override it
    # removes the override = "reset to built-in". A built-in with no override
    # has nothing to delete.
    is_builtin = template_id in TEMPLATES
    if is_builtin and template_id not in _load_custom():
        raise HTTPException(
            status_code=400, detail="built-in template has no edits to reset"
        )

    def _mutate(cur: dict) -> dict:
        if template_id not in cur:
            raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
        del cur[template_id]
        return cur

    mutate_json(get_redis(), CUSTOM_KEY, _mutate, {})
    return {"reset": template_id} if is_builtin else {"deleted": template_id}


@router.get("/cases/{case_id}/case-templates/{template_id}")
def get_template_for_case(
    case_id: str,
    template_id: str,
    _acl: dict = Depends(require_case_access),
):
    """Return the template as an investigation *playbook* for this specific
    case — each watchlist IOC becomes a "check" with a pre-built Lucene query
    AND the live hit count from this case's index. That turns the template
    from "apply opaque magic" into an analyst-friendly checklist they can
    work through, query by query."""
    tpl = _get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    import urllib.error

    from services.elasticsearch import _request as _es_req

    from routers.watchlist import _build_query

    index = f"fo-case-{case_id}-*"

    checks: list[dict] = []
    for ioc in tpl["watchlist"]:
        q = _build_query(ioc["kind"], ioc["value"])
        count: int | None = None
        try:
            res = _es_req(
                "POST",
                f"/{index}/_count",
                {
                    "query": {
                        "query_string": {
                            "query": q,
                            "default_operator": "AND",
                            "allow_leading_wildcard": True,
                            "analyze_wildcard": True,
                            "lenient": True,
                        }
                    }
                },
            )
            count = int(res.get("count", 0))
        except (urllib.error.HTTPError, Exception):
            count = None
        checks.append(
            {
                "label": ioc["label"],
                "kind": ioc["kind"],
                "value": ioc["value"],
                "query": q,
                "result_count": count,
            }
        )

    # Surface non-zero hits first so the analyst's eye lands on actual findings.
    checks.sort(key=lambda c: -(c.get("result_count") or 0))

    return {
        "id": tpl["id"],
        "name": tpl["name"],
        "description": tpl["description"],
        "tags": tpl["tags"],
        "notes": tpl["notes"],
        "checks": checks,
    }


@router.post("/cases/{case_id}/apply-template")
def apply_template(
    case_id: str,
    template_id: str = Query(..., description="ransomware|insider_threat|phishing"),
    case: dict = Depends(require_case_access),
):
    tpl = _get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    r = get_redis()
    # 1) Seed watchlist (global, scoped via label prefix so analysts know which case asked for it)
    seeded = 0
    for ioc in tpl["watchlist"]:
        entry_id = uuid.uuid4().hex
        label = f"[{tpl['name']}] {ioc['label']}"
        from routers.watchlist import _build_query

        q = _build_query(ioc["kind"], ioc["value"])
        entry = {
            "id": entry_id,
            "kind": ioc["kind"],
            "value": ioc["value"],
            "label": label,
            "query": q,
            "created_at": datetime.now(UTC).isoformat(),
            "created_by": f"template:{template_id}",
        }
        r.hset("fo:watchlist", entry_id, json.dumps(entry))
        seeded += 1

    # 2) Append the template tags to the case
    existing_tags = case.get("tags") or []
    if isinstance(existing_tags, str):
        try:
            existing_tags = json.loads(existing_tags)
        except Exception:
            existing_tags = []
    new_tags = list({*existing_tags, *tpl["tags"]})
    r.hset(f"case:{case_id}", "tags", json.dumps(new_tags))

    # 3) Write the report skeleton into analyst notes (don't overwrite if non-empty)
    notes_key = f"case:{case_id}:notes"
    existing_notes = r.get(notes_key)
    if not existing_notes:
        r.set(notes_key, tpl["notes"])

    return {
        "template": tpl["id"],
        "tags_added": tpl["tags"],
        "watchlist_seeded": seeded,
        "notes_seeded": not bool(existing_notes),
    }
