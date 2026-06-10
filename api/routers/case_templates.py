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
import uuid
from datetime import UTC, datetime

from auth.dependencies import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query
from services.cases import get_case

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["case-templates"])


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
            }
            for t in TEMPLATES.values()
        ]
    }


@router.get("/cases/{case_id}/case-templates/{template_id}")
def get_template_for_case(
    case_id: str,
    template_id: str,
    _: dict = Depends(get_current_user),
):
    """Return the template as an investigation *playbook* for this specific
    case — each watchlist IOC becomes a "check" with a pre-built Lucene query
    AND the live hit count from this case's index. That turns the template
    from "apply opaque magic" into an analyst-friendly checklist they can
    work through, query by query."""
    tpl = TEMPLATES.get(template_id)
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
    _: dict = Depends(get_current_user),
):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    tpl = TEMPLATES.get(template_id)
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
