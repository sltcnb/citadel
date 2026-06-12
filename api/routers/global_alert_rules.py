"""
Global Alert Rule Library.

Rules are stored in Redis at fo:alert_rules:_global and are not tied to any
specific case. They can be run on demand against any case's Elasticsearch data
via the /cases/{case_id}/alert-rules/run-library endpoint.

Built-in default rules are loaded from YAML files in tools/sigil/.
Each file covers one MITRE-aligned category and contains a list of rule
definitions. To add new default rules, create or edit YAML files in that
directory — no code changes required.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

try:
    import yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

import redis_keys as rk
from auth.dependencies import get_company_filter, get_current_user
from services.elasticsearch import _request as es_req

from config import get_redis as _redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["global-alert-rules"])

GLOBAL_KEY = rk.GLOBAL_ALERT_RULES
GLOBAL_SEEDED_KEY = rk.GLOBAL_ALERT_RULES_SEEDED

# Sigil detection-rule content (its own repo/submodule at tools/sigil). Path is
# env-configurable so the platform doesn't hard-depend on the tool's location:
#   container → CITADEL_RULES_DIR=/app/sigil (set in the Dockerfile)
#   dev tree  → <repo>/tools/sigil
import os as _os

_RULES_DIR = Path(
    _os.getenv("CITADEL_RULES_DIR") or (Path(__file__).resolve().parents[2] / "tools" / "sigil")
)


# ── YAML rule loader ──────────────────────────────────────────────────────────


def _load_default_rules() -> list[dict]:
    """
    Load built-in detection rules from YAML files in tools/sigil/.

    Each file must have the structure:
        category: <Category Name>
        rules:
          - name: ...
            description: ...
            artifact_type: ...
            query: ...
            threshold: 1

    Falls back to an empty list if PyYAML is unavailable or no files exist.
    """
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — default rules cannot be loaded from YAML files")
        return []
    if not _RULES_DIR.exists():
        logger.warning("Alert rules directory %s not found", _RULES_DIR)
        return []

    from config import settings as _settings

    rules: list[dict] = []
    for path in sorted(_RULES_DIR.glob("**/*.yaml")):
        # Sigma is opt-in — skip the bulky Sigma HQ community rule packs unless
        # enabled. Native/custom rule files still load.
        if not _settings.SIGMA_ENABLED and "sigma_hq" in path.parts:
            continue
        try:
            with path.open() as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict) or "rules" not in data:
                logger.warning("Skipping %s — missing 'rules' key", path.name)
                continue
            category = data.get("category", "")
            for rule in data["rules"]:
                query = rule.get("query", "")

                # sigma_hq files store a raw Sigma detection block instead of a
                # pre-built ES query.  Convert on the fly when query is absent.
                if not query and rule.get("sigma_detection"):
                    try:
                        detection = yaml.safe_load(rule["sigma_detection"])
                        if isinstance(detection, dict):
                            query = _sigma_to_es_query({"detection": detection})
                    except Exception as conv_exc:
                        logger.warning(
                            "sigma_detection conversion failed for '%s' in %s: %s",
                            rule.get("name", "?"),
                            path.name,
                            conv_exc,
                        )

                if not query:
                    logger.debug(
                        "Skipping rule '%s' in %s — no query", rule.get("name", "?"), path.name
                    )
                    continue

                rules.append(
                    {
                        "name": rule.get("name", ""),
                        "category": rule.get("category", category),
                        "description": rule.get("description", ""),
                        "artifact_type": rule.get("artifact_type", ""),
                        "query": query,
                        "threshold": int(rule.get("threshold", 1)),
                        # sigma_detection present → true Sigma rule; plain query → legacy
                        "rule_type": "sigma" if rule.get("sigma_detection") else "legacy",
                    }
                )
        except Exception as exc:
            logger.error("Failed to load alert rules from %s: %s", path.name, exc)
    return rules


_DEFAULT_RULES_CACHE: list[dict] | None = None


def _get_default_rules() -> list[dict]:
    global _DEFAULT_RULES_CACHE
    if _DEFAULT_RULES_CACHE is None:
        _DEFAULT_RULES_CACHE = _load_default_rules()
    return _DEFAULT_RULES_CACHE


# ── Redis helpers ─────────────────────────────────────────────────────────────


def _make_rule(template: dict) -> dict:
    """Stamp a rule template with a fresh id and created_at."""
    return {
        "id": str(uuid.uuid4())[:8],
        "created_at": datetime.utcnow().isoformat(),
        **template,
    }


def _seed_defaults_if_empty(r: redis_lib.Redis) -> None:
    """Populate the library with default rules the very first time it is accessed."""
    if r.get(GLOBAL_SEEDED_KEY):
        return
    existing = json.loads(r.get(GLOBAL_KEY) or "[]")
    if not existing:
        rules = [_make_rule(t) for t in _get_default_rules()]
        r.set(GLOBAL_KEY, json.dumps(rules))
    r.set(GLOBAL_SEEDED_KEY, "1")


def _migrate_rule_types(r: redis_lib.Redis) -> None:
    """Tag rules with correct rule_type using the YAML source as ground truth.
    - User-created rules (rule_type='custom') are never touched.
    - All other rules are re-tagged by matching name against the YAML defaults:
      sigma_detection present → 'sigma', plain query → 'legacy'.
    Tracks completion via fo:alert_rules:migrated_v2."""
    if r.get(rk.GLOBAL_ALERT_RULES_MIGRATED):
        return
    raw = r.get(GLOBAL_KEY)
    if not raw:
        r.set(rk.GLOBAL_ALERT_RULES_MIGRATED, "1")
        return
    # Build name → rule_type map from fresh YAML load
    name_to_type = {d["name"]: d["rule_type"] for d in _get_default_rules()}
    rules = json.loads(raw)
    changed = 0
    for rule in rules:
        if rule.get("rule_type") == "custom":
            continue  # user-created, never touch
        correct = name_to_type.get(rule.get("name"))
        if correct and rule.get("rule_type") != correct:
            rule["rule_type"] = correct
            changed += 1
        elif not rule.get("rule_type") and not correct:
            # Unknown seeded rule — keep as legacy
            rule["rule_type"] = "legacy"
            changed += 1
    if changed:
        r.set(GLOBAL_KEY, json.dumps(rules))
        logger.info("Migration v2: retagged %d rules with correct rule_type", changed)
    r.set(rk.GLOBAL_ALERT_RULES_MIGRATED, "1")


# ── Pydantic models ───────────────────────────────────────────────────────────


class AlertRuleIn(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    artifact_type: str = ""
    query: str
    threshold: int = 1
    sigma_yaml: str = ""  # raw Sigma YAML (optional for legacy rules)
    rule_type: str = "custom"  # 'custom' | 'sigma' | 'legacy'
    companies: list[str] = []  # [] = platform-wide; non-empty = restricted to these companies


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    artifact_type: str | None = None
    query: str | None = None
    threshold: int | None = None
    sigma_yaml: str | None = None
    rule_type: str | None = None
    companies: list[str] | None = None


# ── Library CRUD ──────────────────────────────────────────────────────────────


def _rule_applies_to_company(rule: dict, case_company: str) -> bool:
    """True if rule is unrestricted or explicitly covers case_company."""
    cos = rule.get("companies") or []
    if not cos:
        return True
    return bool(case_company) and case_company in cos


@router.get("/alert-rules/library")
def list_library(current_user: dict = Depends(get_current_user)):
    """Return global alert rules visible to the current user."""
    r = _redis()
    _seed_defaults_if_empty(r)
    _migrate_rule_types(r)
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    company_filter = get_company_filter(current_user)
    if company_filter is not None:

        def _visible(rule: dict) -> bool:
            rule_cos = rule.get("companies") or []
            return not rule_cos or any(c in company_filter for c in rule_cos)

        rules = [rl for rl in rules if _visible(rl)]
    return {"rules": rules}


@router.get("/alert-rules/library/{rule_id}")
def get_library_rule(rule_id: str):
    """Return a single library rule by ID."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("/alert-rules/library/seed", status_code=200)
def seed_library(replace: bool = False):
    """
    Load the built-in default rules into the library.

    replace=false (default) — append any defaults not already present (by name).
    replace=true            — clear the library and reload all defaults fresh.
    """
    global _DEFAULT_RULES_CACHE
    # Always reload from disk so newly added YAML files are picked up without
    # requiring a server restart.
    _DEFAULT_RULES_CACHE = None

    r = _redis()
    defaults = _get_default_rules()
    existing: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")

    if replace:
        rules = [_make_rule(t) for t in defaults]
        r.set(GLOBAL_KEY, json.dumps(rules))
        r.set(GLOBAL_SEEDED_KEY, "1")
        return {"added": len(rules), "total": len(rules)}

    existing_names = {rl["name"].lower() for rl in existing}
    added = []
    for template in defaults:
        if template["name"].lower() not in existing_names:
            new_rule = _make_rule(template)
            existing.append(new_rule)
            added.append(new_rule)
    if added:
        r.set(GLOBAL_KEY, json.dumps(existing))
    r.set(GLOBAL_SEEDED_KEY, "1")
    return {"added": len(added), "total": len(existing)}


@router.post("/alert-rules/sigma/parse")
def parse_sigma_rule(body: dict):
    """
    Parse a Sigma YAML string and return the derived fields WITHOUT creating a rule.
    Used by the frontend edit modal to preview / validate the ES query.
    Returns { name, description, category, artifact_type, query, sigma_level, sigma_tags, sigma_status }.
    """
    from config import settings as _settings
    if not _settings.SIGMA_ENABLED:
        raise HTTPException(status_code=503, detail="Sigma integration is disabled on this instance.")
    if not _YAML_AVAILABLE:
        raise HTTPException(status_code=500, detail="PyYAML is not installed on the server.")
    raw_yaml = body.get("yaml", "")
    if not raw_yaml.strip():
        raise HTTPException(status_code=422, detail="Provide a non-empty 'yaml' key.")
    try:
        sigma = yaml.safe_load(raw_yaml)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"YAML parse error: {exc}")
    if not isinstance(sigma, dict) or not sigma.get("title"):
        raise HTTPException(status_code=422, detail="Sigma rule must have a 'title' field.")
    return {
        "name": sigma.get("title", "Untitled"),
        "description": sigma.get("description", ""),
        "category": _sigma_to_category(sigma),
        "artifact_type": _sigma_to_artifact_type(sigma),
        "query": _sigma_to_es_query(sigma),
        "sigma_level": sigma.get("level", ""),
        "sigma_tags": sigma.get("tags", []),
        "sigma_status": sigma.get("status", ""),
    }


@router.post("/alert-rules/library/sigma", status_code=201)
def import_sigma_rules(body: dict):
    """
    Import one or more Sigma rules into the global alert library.

    Accepts a JSON body with either:
      { "yaml": "<sigma yaml string>" }          — single rule
      { "rules": ["<yaml1>", "<yaml2>", ...] }   — multiple rules

    Each Sigma rule is parsed and converted to an Elasticsearch Lucene query
    using a best-effort field mapper.  Complex Sigma detections (pipes,
    aggregations, near-conditions) are stored as-is with a note to review.

    Returns { "imported": N, "skipped": N, "rules": [...] }
    """
    from config import settings as _settings
    if not _settings.SIGMA_ENABLED:
        raise HTTPException(status_code=503, detail="Sigma integration is disabled on this instance.")
    if not _YAML_AVAILABLE:
        raise HTTPException(status_code=500, detail="PyYAML is not installed on the server.")

    raw_list: list[str] = []
    if "yaml" in body:
        raw_list = [body["yaml"]]
    elif "rules" in body and isinstance(body["rules"], list):
        raw_list = body["rules"]
    else:
        raise HTTPException(status_code=422, detail="Provide 'yaml' or 'rules' key.")

    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    existing_names = {rl["name"].lower() for rl in rules}

    imported, skipped, new_rules, skip_reasons = 0, 0, [], []
    for raw_yaml in raw_list:
        try:
            sigma = yaml.safe_load(raw_yaml)
        except Exception as exc:
            skipped += 1
            skip_reasons.append({"reason": f"YAML parse error: {exc}", "title": None})
            continue

        if not isinstance(sigma, dict):
            skipped += 1
            skip_reasons.append(
                {"reason": "YAML did not produce a mapping (expected a dict)", "title": None}
            )
            continue

        if not sigma.get("title"):
            skipped += 1
            skip_reasons.append(
                {
                    "reason": "Missing required 'title' field — add 'title: <Rule Name>' to your Sigma YAML",
                    "title": None,
                }
            )
            continue

        name = sigma.get("title", "Untitled Sigma Rule")
        if name.lower() in existing_names:
            skipped += 1
            skip_reasons.append(
                {"reason": f"A rule named '{name}' already exists in the library", "title": name}
            )
            continue

        query = _sigma_to_es_query(sigma)
        category = _sigma_to_category(sigma)
        art_type = _sigma_to_artifact_type(sigma)

        new_rule = {
            "id": str(uuid.uuid4())[:8],
            "created_at": datetime.utcnow().isoformat(),
            "name": name,
            "description": sigma.get("description", ""),
            "category": category,
            "artifact_type": art_type,
            "query": query,
            "threshold": 1,
            "rule_type": "sigma",
            "sigma_yaml": raw_yaml,
            "sigma_id": sigma.get("id", ""),
            "sigma_level": sigma.get("level", ""),
            "sigma_tags": sigma.get("tags", []),
            "sigma_status": sigma.get("status", ""),
            "companies": body.get("companies", []),
        }
        rules.append(new_rule)
        existing_names.add(name.lower())
        new_rules.append(new_rule)
        imported += 1

    if new_rules:
        r.set(GLOBAL_KEY, json.dumps(rules))

    return {
        "imported": imported,
        "skipped": skipped,
        "rules": new_rules,
        "skip_reasons": skip_reasons,
    }


# ── Sigma helpers ─────────────────────────────────────────────────────────────

# Sigma field → Elasticsearch field mapping
_SIGMA_FIELD_MAP: dict[str, str] = {
    # Windows Event fields
    "eventid": "evtx.event_id",
    "event_id": "evtx.event_id",
    # Process
    "commandline": "process.command_line",
    "image": "process.executable",
    "parentcommandline": "process.parent.command_line",
    "parentimage": "process.parent.executable",
    "originalfilename": "process.name",
    # User / Identity
    "targetusername": "user.name",
    "subjectusername": "user.name",
    "user": "user.name",
    # Host
    "computer": "host.hostname",
    "hostname": "host.hostname",
    "computername": "host.hostname",
    # Network
    "destinationip": "network.dest_ip",
    "destinationport": "network.dest_port",
    "sourceip": "network.src_ip",
    "sourceport": "network.src_port",
    # Generic
    "message": "message",
    "keywords": "evtx.keywords",
    "channel": "evtx.channel",
    # Registry
    "targetobject": "registry.key",
    "details": "registry.value",
}


def _map_field(field: str) -> str:
    """Map a Sigma field name to its Elasticsearch equivalent."""
    return _SIGMA_FIELD_MAP.get(field.lower(), field.lower())


def _sigma_value_to_es(field: str, value: Any, modifiers: list[str]) -> str:
    """Convert a single Sigma field+value to an ES Lucene clause."""
    es_field = _map_field(field)
    str_val = str(value)

    if "contains" in modifiers:
        return f"{es_field}:*{str_val}*"
    if "startswith" in modifiers:
        return f"{es_field}:{str_val}*"
    if "endswith" in modifiers:
        return f"{es_field}:*{str_val}"
    if "re" in modifiers:
        # Regex — wrap in /<regex>/
        return f"{es_field}:/{str_val}/"
    # Exact / default
    # Escape special Lucene chars in the value
    escaped = re.sub(r'([+\-!(){}\[\]^"~*?:\\\/])', r"\\\1", str_val)
    return f"{es_field}:{escaped}"


def _sigma_selection_to_es(selection: Any) -> str:
    """Convert a Sigma selection dict/list to an ES query string."""
    if isinstance(selection, dict):
        clauses = []
        for raw_field, value in selection.items():
            # Handle field|modifier syntax
            parts = raw_field.split("|")
            field = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            if isinstance(value, list):
                # Multiple values → OR
                sub = " OR ".join(_sigma_value_to_es(field, v, modifiers) for v in value)
                clauses.append(f"({sub})")
            else:
                clauses.append(_sigma_value_to_es(field, value, modifiers))

        return " AND ".join(clauses) if clauses else "*"

    if isinstance(selection, list):
        # List of dicts → OR between them
        return " OR ".join(
            f"({_sigma_selection_to_es(s)})" for s in selection if isinstance(s, dict)
        )

    return "*"


def _sigma_to_es_query(sigma: dict) -> str:
    """
    Best-effort conversion of a Sigma detection block to an ES Lucene query.

    Supports:
      - Simple selections (field: value, field|contains: value, lists)
      - condition: selection  (AND of all fields)
      - condition: selection1 or selection2
      - condition: selection1 and not filter1
    Unsupported constructs produce a query placeholder with a review note.
    """
    detection = sigma.get("detection", {})
    if not detection:
        return f"title:{sigma.get('title', '*')}"

    condition = str(detection.get("condition", "selection")).strip().lower()

    # Build map of named selections → ES clauses
    selection_map: dict[str, str] = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        if key == "timeframe":
            continue
        selection_map[key] = _sigma_selection_to_es(val)

    # Evaluate simple condition expressions
    # Normalise: replace "and not" with a placeholder for negation
    try:
        result = _eval_condition(condition, selection_map)
    except Exception:
        # Fallback: join everything with OR
        result = " OR ".join(f"({v})" for v in selection_map.values() if v and v != "*")
        if not result:
            result = "*"

    return result or "*"


def _eval_condition(condition: str, sel_map: dict[str, str]) -> str:
    """Parse a simple Sigma condition string."""
    import re as _re

    cond = condition.strip()

    # "1 of selection*" / "all of selection*"
    m = _re.match(r"^(1|all) of (\S+)$", cond)
    if m:
        quantifier, pattern = m.groups()
        pattern_re = _re.compile("^" + pattern.replace("*", ".*") + "$")
        matched = [v for k, v in sel_map.items() if pattern_re.match(k)]
        joiner = " OR " if quantifier == "1" else " AND "
        return joiner.join(f"({v})" for v in matched) if matched else "*"

    # Replace "and not" with special token
    parts = _re.split(r"\s+and\s+not\s+", cond)
    if len(parts) == 2:
        include, exclude = parts
        inc_q = _eval_condition(include.strip(), sel_map)
        exc_q = _eval_condition(exclude.strip(), sel_map)
        return f"({inc_q}) AND NOT ({exc_q})"

    # "or" splits
    or_parts = [p.strip() for p in _re.split(r"\s+or\s+", cond)]
    if len(or_parts) > 1:
        clauses = [_eval_condition(p, sel_map) for p in or_parts]
        return " OR ".join(f"({c})" for c in clauses if c)

    # "and" splits
    and_parts = [p.strip() for p in _re.split(r"\s+and\s+", cond)]
    if len(and_parts) > 1:
        clauses = [_eval_condition(p, sel_map) for p in and_parts]
        return " AND ".join(f"({c})" for c in clauses if c)

    # Single selection name
    cond_clean = cond.strip("() ")
    return sel_map.get(cond_clean, cond_clean)


# Sigma logsource product → MITRE category approximation
_SIGMA_CATEGORY_MAP: dict[str, str] = {
    "anti-forensics": "Anti-Forensics",
    "windows": "Execution",
    "linux": "Discovery",
    "macos": "Discovery",
    "network": "Command & Control",
    "web": "Command & Control",
    "firewall": "Command & Control",
    "proxy": "Command & Control",
    "dns": "Command & Control",
}

_SIGMA_LOGSOURCE_CATEGORY_MAP: dict[str, str] = {
    "process_creation": "Execution",
    "process_access": "Execution",
    "network_connection": "Command & Control",
    "dns": "Command & Control",
    "file_event": "Persistence",
    "registry_event": "Persistence",
    "registry_add": "Persistence",
    "registry_set": "Persistence",
    "registry_delete": "Defense Evasion",
    "scheduled_task_creation": "Persistence",
    "service_creation": "Persistence",
    "image_load": "Defense Evasion",
    "driver_load": "Defense Evasion",
    "wmi_event": "Execution",
    "pipe_created": "Lateral Movement",
    "raw_access_read": "Credential Access",
}

_SIGMA_TAG_TACTIC_MAP: dict[str, str] = {
    "attack.defense_evasion": "Defense Evasion",
    "attack.privilege_escalation": "Privilege Escalation",
    "attack.persistence": "Persistence",
    "attack.execution": "Execution",
    "attack.lateral_movement": "Lateral Movement",
    "attack.credential_access": "Credential Access",
    "attack.discovery": "Discovery",
    "attack.command_and_control": "Command & Control",
    "attack.exfiltration": "Exfiltration",
    "attack.collection": "Discovery",
    "attack.initial_access": "Execution",
    "attack.impact": "Anti-Forensics",
}


def _sigma_to_category(sigma: dict) -> str:
    """Derive alert rule category from Sigma tags and logsource."""
    # 1. Check tags for ATT&CK tactics (most reliable)
    for tag in sigma.get("tags", []):
        cat = _SIGMA_TAG_TACTIC_MAP.get(tag.lower())
        if cat:
            return cat

    # 2. Check logsource.category
    ls = sigma.get("logsource", {})
    if isinstance(ls, dict):
        ls_cat = ls.get("category", "").lower()
        cat = _SIGMA_LOGSOURCE_CATEGORY_MAP.get(ls_cat)
        if cat:
            return cat
        product = ls.get("product", "").lower()
        cat = _SIGMA_CATEGORY_MAP.get(product)
        if cat:
            return cat

    return "Other"


def _sigma_to_artifact_type(sigma: dict) -> str:
    """Derive artifact_type from Sigma logsource."""
    ls = sigma.get("logsource", {})
    if not isinstance(ls, dict):
        return ""

    product = ls.get("product", "").lower()
    service = ls.get("service", "").lower()
    category = ls.get("category", "").lower()

    if product == "windows":
        if service in ("security", "system", "application", "sysmon", "powershell"):
            return "evtx"
        return "evtx"
    if product in ("linux", "macos"):
        return "syslog"
    if "network" in category or "dns" in category or product in ("zeek", "suricata"):
        return ""
    if "registry" in category:
        return "registry"
    if "file" in category:
        return ""
    return ""


@router.post("/alert-rules/library", status_code=201)
def create_library_rule(body: AlertRuleIn):
    """Add a new rule to the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    new_rule = {
        "id": str(uuid.uuid4())[:8],
        **body.dict(),
        "created_at": datetime.utcnow().isoformat(),
    }
    rules.append(new_rule)
    r.set(GLOBAL_KEY, json.dumps(rules))
    return new_rule


@router.put("/alert-rules/library/{rule_id}")
def update_library_rule(rule_id: str, body: AlertRuleUpdate):
    """Update an existing rule in the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    updated = None
    for rl in rules:
        if rl["id"] == rule_id:
            patch = body.dict(exclude_none=True)
            rl.update(patch)
            updated = rl
            break
    if updated is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    r.set(GLOBAL_KEY, json.dumps(rules))
    return updated


@router.delete("/alert-rules/library/{rule_id}", status_code=204)
def delete_library_rule(rule_id: str):
    """Remove a rule from the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    r.set(GLOBAL_KEY, json.dumps([rl for rl in rules if rl["id"] != rule_id]))


# ── Run library against a case ────────────────────────────────────────────────


@router.post("/cases/{case_id}/alert-rules/run-library")
def run_library_against_case(case_id: str, rule_types: list[str] = Query(default=[])):
    """
    Execute rules in the global library against the given case's data.
    Optional rule_types filter: 'sigma', 'custom', 'legacy'. Empty = run all.
    Returns a list of matches (rules that fired) with sample events.
    """
    r = _redis()
    data = r.get(GLOBAL_KEY)
    rules: list[dict] = json.loads(data) if data else []

    # Filter rules by case company
    raw_co = r.hget(f"case:{case_id}", "company")
    case_company = (raw_co.decode() if isinstance(raw_co, bytes) else raw_co) or ""
    rules = [rl for rl in rules if _rule_applies_to_company(rl, case_company)]

    if rule_types:

        def _matches_type(rule: dict) -> bool:
            has_sigma = bool(rule.get("sigma_yaml", ""))
            rt = rule.get("rule_type", "")
            if "sigma" in rule_types and (has_sigma or rt == "sigma"):
                return True
            if "custom" in rule_types and rt == "custom":
                return True
            if "legacy" in rule_types and not rt and not has_sigma and rt != "sigma":
                return True
            return False

        rules = [rl for rl in rules if _matches_type(rl)]

    if not rules:
        return {"matches": [], "rules_checked": 0}

    matches: list[dict] = []

    for rule in rules:
        artifact_type = rule.get("artifact_type", "").strip()
        index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"
        body = {
            "query": {
                "query_string": {
                    "query": rule["query"],
                    "default_operator": "AND",
                }
            },
            "size": 5,
            "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        try:
            resp = es_req("POST", f"/{index}/_search", body)
            count = resp["hits"]["total"]["value"]
            if count >= int(rule.get("threshold", 1)):
                matches.append(
                    {
                        "rule": rule,
                        "match_count": count,
                        "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
                    }
                )
        except Exception as exc:
            logger.warning(
                "Alert rule %r failed during check: %s", rule.get("name", rule.get("rule_id")), exc
            )

    # Persist the run so the AI analysis endpoint can find these matches
    run = {
        "ran_at": datetime.now(UTC).isoformat(),
        "rules_checked": len(rules),
        "matches": matches,
        "analyses": {},
    }
    run_key = rk.case_alert_run(case_id)
    r.set(run_key, json.dumps(run))
    r.expire(run_key, 7 * 86400)

    return {"matches": matches, "rules_checked": len(rules)}


@router.post("/cases/{case_id}/alert-rules/library/{rule_id}/run")
def run_single_rule_against_case(case_id: str, rule_id: str):
    """Execute a single rule from the global library against the given case."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    artifact_type = rule.get("artifact_type", "").strip()
    index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"
    body = {
        "query": {
            "query_string": {
                "query": rule["query"],
                "default_operator": "AND",
            }
        },
        "size": 5,
        "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        resp = es_req("POST", f"/{index}/_search", body)
        count = resp["hits"]["total"]["value"]
        match = (
            {
                "rule": rule,
                "match_count": count,
                "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
            }
            if count >= int(rule.get("threshold", 1))
            else None
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "match": match,
        "rules_checked": 1,
        "fired": match is not None,
    }


# ── LLM helpers ───────────────────────────────────────────────────────────────


class GenerateRuleRequest(BaseModel):
    description: str
    context: str = ""


@router.post("/alert-rules/generate-sigma")
def generate_sigma_rule(body: GenerateRuleRequest):
    """Use the configured LLM to generate a Sigma YAML rule from a description."""
    try:
        from routers.llm_config import generate_sigma_yaml  # type: ignore

        yaml_text = generate_sigma_yaml(body.description, body.context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")
    return {"yaml": yaml_text}
