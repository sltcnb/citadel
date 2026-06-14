"""RBAC model — granular permissions, roles, groups (pure, unit-testable).

This module holds the *policy* layer: the permission catalog, the legacy
role -> permission presets (so the original 4 flat roles keep working), and the
PURE resolution functions that compute a user's effective permissions and
company scope from their role + group memberships + per-user grants.

Nothing here touches Redis or FastAPI. The store/persistence lives in
``auth.service`` and the enforcement lives in ``auth.dependencies``; both call
into the pure functions below. Keeping resolution pure makes it trivial to unit
test (see ``auth.test_rbac_model``) and free of I/O on the hot path.
"""

from __future__ import annotations

# ── Permission catalog (granular, namespaced) ──────────────────────────────────
# Each constant is a stable string id "<domain>.<action>". Persist these, not the
# Python names. Add new permissions here and to ALL_PERMISSIONS + the relevant
# role preset(s).

CASES_READ = "cases.read"
CASES_WRITE = "cases.write"
CASES_DELETE = "cases.delete"
CASES_EXPORT = "cases.export"
INGEST_WRITE = "ingest.write"
MODULES_RUN = "modules.run"
RULES_MANAGE = "rules.manage"
CTI_MANAGE = "cti.manage"
EVIDENCE_MANAGE = "evidence.manage"
STUDIO_EDIT = "studio.edit"
SETTINGS_ADMIN = "settings.admin"
USERS_MANAGE = "users.manage"
AUDIT_READ = "audit.read"

ALL_PERMISSIONS: frozenset[str] = frozenset(
    {
        CASES_READ,
        CASES_WRITE,
        CASES_DELETE,
        CASES_EXPORT,
        INGEST_WRITE,
        MODULES_RUN,
        RULES_MANAGE,
        CTI_MANAGE,
        EVIDENCE_MANAGE,
        STUDIO_EDIT,
        SETTINGS_ADMIN,
        USERS_MANAGE,
        AUDIT_READ,
    }
)

# Human-friendly metadata for the catalog endpoint (UI checkbox rendering).
PERMISSION_DESCRIPTIONS: dict[str, str] = {
    CASES_READ: "View cases, timelines, events and search results",
    CASES_WRITE: "Create and edit cases, notes and tags",
    CASES_DELETE: "Delete cases and their data",
    CASES_EXPORT: "Export case data (CSV, reports)",
    INGEST_WRITE: "Ingest evidence / upload data into cases",
    MODULES_RUN: "Run analysis modules and jobs",
    RULES_MANAGE: "Create and manage detection / alert rules",
    CTI_MANAGE: "Manage CTI feeds, IOCs and watchlists",
    EVIDENCE_MANAGE: "Manage evidence sealing and chain of custody",
    STUDIO_EDIT: "Use the Studio / rule editor",
    SETTINGS_ADMIN: "Administer platform settings",
    USERS_MANAGE: "Manage users and groups",
    AUDIT_READ: "Read the audit log",
}


# ── Legacy role -> permission presets ───────────────────────────────────────────
# These keep the original 4 flat roles working unchanged. A user with role
# "analyst" automatically gets the analyst permission set; groups and per-user
# extra_permissions layer ON TOP of this.

_ANALYST_PERMS: frozenset[str] = frozenset(
    {
        CASES_READ,
        CASES_WRITE,
        CASES_EXPORT,
        INGEST_WRITE,
        MODULES_RUN,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    # admin = everything
    "admin": ALL_PERMISSIONS,
    # analyst = read/write/ingest/modules/export
    "analyst": _ANALYST_PERMS,
    # developer = analyst + studio/editor
    "developer": _ANALYST_PERMS | frozenset({STUDIO_EDIT}),
    # guest = read-only
    "guest": frozenset({CASES_READ}),
}

# Presets exposed to the UI so it can pre-fill checkboxes when a role is picked.
ROLE_PERMISSION_PRESETS: dict[str, list[str]] = {
    role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()
}


# ── Group shape helper ──────────────────────────────────────────────────────────


def empty_group(group_id: str, name: str) -> dict:
    """Return a fully-formed group dict with all expected keys.

    Group shape: {id, name, description, roles, permissions, companies, members}.
    """
    return {
        "id": group_id,
        "name": name,
        "description": "",
        "roles": [],
        "permissions": [],
        "companies": [],
        "members": [],
    }


# ── Pure resolution functions ───────────────────────────────────────────────────


def _user_permissions_from_role(user: dict) -> set[str]:
    role = (user or {}).get("role") or "guest"
    return set(ROLE_PERMISSIONS.get(role, frozenset()))


def _coerce_list(value) -> list[str]:
    """Tolerant: accept a real list, or None. (JSON parsing happens upstream in
    service._public, but stay defensive for direct/pure callers.)"""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def effective_permissions(user: dict, groups_index: dict[str, dict]) -> set[str]:
    """Union of: the user's role permissions + every group's role+explicit
    permissions for groups the user belongs to + the user's extra_permissions.

    PURE: takes the user dict and a {group_id: group} map; no I/O. Admin role
    short-circuits to all permissions.
    """
    user = user or {}
    if user.get("role") == "admin":
        return set(ALL_PERMISSIONS)

    perms: set[str] = _user_permissions_from_role(user)

    member_of = set(_coerce_list(user.get("groups")))
    for gid in member_of:
        group = (groups_index or {}).get(gid)
        if not group:
            continue
        # A group can grant permissions via named roles...
        for role in _coerce_list(group.get("roles")):
            perms |= set(ROLE_PERMISSIONS.get(role, frozenset()))
        # ...and/or via explicit granular permissions.
        perms |= {p for p in _coerce_list(group.get("permissions")) if p in ALL_PERMISSIONS}

    # Per-user explicit grants layered on top.
    perms |= {p for p in _coerce_list(user.get("extra_permissions")) if p in ALL_PERMISSIONS}
    return perms


def effective_companies(user: dict, groups_index: dict[str, dict]) -> list[str] | None:
    """Union of user.companies + the company scopes of every group the user is in.

    Returns None when UNRESTRICTED:
      - the user is an admin, or
      - neither the user nor any of their groups declares a company scope
        (empty everywhere == "all companies").

    Otherwise returns the sorted, de-duplicated list the user is confined to.
    PURE.
    """
    user = user or {}
    if user.get("role") == "admin":
        return None

    companies: set[str] = set(_coerce_list(user.get("companies")))
    for gid in set(_coerce_list(user.get("groups"))):
        group = (groups_index or {}).get(gid)
        if not group:
            continue
        companies |= set(_coerce_list(group.get("companies")))

    return sorted(companies) if companies else None
