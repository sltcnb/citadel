"""Groups + RBAC management router — CRUD for groups, the permission catalog,
and a resolved-effective-access view for a user. All write/list endpoints require
the ``users.manage`` permission (admins always pass)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auth import rbac
from auth.dependencies import get_company_filter, require_permission, resolve_effective
from auth.service import (
    VALID_ROLES,
    create_group,
    delete_group,
    get_group,
    get_user,
    groups_index,
    list_groups,
    update_group,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/groups", tags=["groups"])

# Shared dependency: anyone who can manage users can manage groups.
_manage = require_permission(rbac.USERS_MANAGE)


# ── Tenant scoping ────────────────────────────────────────────────────────────
#
# users.manage says "may administer groups", not "may administer EVERY tenant's
# groups". On a multi-tenant deployment a company-scoped manager could
# previously read, rewrite or delete any group in the installation just by
# knowing its id — the group_id went straight from the URL into the store call
# with no ownership check.
#
# A group's own `companies` list is its scope ([] meaning installation-wide).
# A restricted manager may only touch a group whose scope overlaps their own,
# and never an installation-wide group: that is strictly broader than they are.


def _group_scope_error(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _visible_to(group: dict, company_filter: list[str] | None) -> bool:
    """True if a manager limited to ``company_filter`` may see this group."""
    if company_filter is None:  # admin / unrestricted
        return True
    group_companies = group.get("companies") or []
    if not group_companies:
        # Installation-wide group: broader than the caller's own scope.
        return False
    return bool(set(group_companies) & set(company_filter))


def _require_group_scope(group_id: str, company_filter: list[str] | None) -> dict:
    """Load a group and confirm the caller's tenant scope covers it."""
    group = get_group(group_id)
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Group '{group_id}' not found"
        )
    if not _visible_to(group, company_filter):
        # 404, not 403: a scoped manager should not be able to probe for the
        # existence of another tenant's groups.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Group '{group_id}' not found"
        )
    return group


def _require_assignable_scope(
    companies: list[str] | None, company_filter: list[str] | None
) -> None:
    """Reject a write that would place a group outside the caller's own scope."""
    if company_filter is None or companies is None:
        return
    if not companies:
        raise _group_scope_error(
            "Cannot create or move a group to installation-wide scope: your "
            "account is limited to specific companies."
        )
    outside = sorted(set(companies) - set(company_filter))
    if outside:
        raise _group_scope_error(
            f"Cannot scope a group to companies outside your own access: {', '.join(outside)}"
        )


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class GroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str = Field("", max_length=500)
    roles: list[str] = Field(default_factory=list, description="Legacy roles this group grants")
    permissions: list[str] = Field(
        default_factory=list, description="Granular permission ids this group grants"
    )
    companies: list[str] = Field(
        default_factory=list, description="Company scope for members (empty = inherit/all)"
    )
    members: list[str] = Field(default_factory=list, description="Usernames in this group")


class GroupUpdateRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    description: str | None = Field(None, max_length=500)
    roles: list[str] | None = None
    permissions: list[str] | None = None
    companies: list[str] | None = None
    members: list[str] | None = None


# ── Group CRUD endpoints (prefix /groups) ───────────────────────────────────────


@router.get("", summary="List all groups")
async def list_all_groups(current_user: dict = Depends(_manage)):
    flt = get_company_filter(current_user)
    return {"groups": [g for g in list_groups() if _visible_to(g, flt)]}


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a group")
async def create_new_group(body: GroupCreateRequest, current_user: dict = Depends(_manage)):
    _validate_roles(body.roles)
    _require_assignable_scope(body.companies, get_company_filter(current_user))
    try:
        group = create_group(
            name=body.name,
            description=body.description,
            roles=body.roles,
            permissions=body.permissions,
            companies=body.companies,
            members=body.members,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return group


@router.put("/{group_id}", summary="Update a group")
async def update_existing_group(
    group_id: str, body: GroupUpdateRequest, current_user: dict = Depends(_manage)
):
    if body.roles is not None:
        _validate_roles(body.roles)
    flt = get_company_filter(current_user)
    _require_group_scope(group_id, flt)
    _require_assignable_scope(body.companies, flt)
    try:
        group = update_group(
            group_id,
            name=body.name,
            description=body.description,
            roles=body.roles,
            permissions=body.permissions,
            companies=body.companies,
            members=body.members,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return group


@router.delete("/{group_id}", summary="Delete a group")
async def delete_existing_group(group_id: str, current_user: dict = Depends(_manage)):
    _require_group_scope(group_id, get_company_filter(current_user))
    if not delete_group(group_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Group '{group_id}' not found"
        )
    return {"detail": f"Group '{group_id}' deleted"}


def _validate_roles(roles: list[str]) -> None:
    bad = [r for r in (roles or []) if r not in VALID_ROLES]
    if bad:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role(s): {', '.join(bad)}. Must be one of: {', '.join(VALID_ROLES)}",
        )


# A standalone router for routes that should NOT carry the /groups prefix
# (permission catalog + per-user effective view). Registered alongside `router`.
catalog_router = APIRouter(tags=["groups"])


@catalog_router.get("/permissions", summary="Permission catalog + role presets")
async def permissions_catalog(_: dict = Depends(_manage)):
    """Return the full permission catalog (id + description) and the legacy
    role -> permission presets so the UI can render and pre-fill checkboxes."""
    return {
        "permissions": [
            {"id": p, "description": rbac.PERMISSION_DESCRIPTIONS.get(p, "")}
            for p in sorted(rbac.ALL_PERMISSIONS)
        ],
        "roles": list(VALID_ROLES),
        "role_presets": rbac.ROLE_PERMISSION_PRESETS,
    }


@catalog_router.get(
    "/users/{username}/effective", summary="Resolved effective permissions + companies"
)
async def user_effective_access(username: str, _: dict = Depends(_manage)):
    user = get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found"
        )
    resolve_effective(user)
    companies = user.get("_effective_companies")
    return {
        "username": username,
        "role": user.get("role"),
        "permissions": sorted(user.get("_effective_perms") or set()),
        "companies": companies,  # None == unrestricted (all companies)
        "unrestricted": companies is None,
        "groups": [
            g
            for gid, g in groups_index().items()
            if username in (g.get("members") or [])
        ],
    }
