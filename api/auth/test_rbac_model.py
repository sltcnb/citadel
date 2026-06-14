"""Unit tests for the PURE rbac model functions.

No Redis, no FastAPI — every fixture is a plain dict. These exercise the policy
layer: role presets, group unions, extra_permissions unions, company unions,
admin-unrestricted, and guest-minimal.
"""

from __future__ import annotations

from auth import rbac


# ── Role -> permission presets ──────────────────────────────────────────────────


def test_admin_role_has_all_permissions():
    user = {"username": "a", "role": "admin"}
    assert rbac.effective_permissions(user, {}) == set(rbac.ALL_PERMISSIONS)


def test_analyst_preset():
    user = {"username": "a", "role": "analyst"}
    perms = rbac.effective_permissions(user, {})
    assert perms == {
        rbac.CASES_READ,
        rbac.CASES_WRITE,
        rbac.CASES_EXPORT,
        rbac.INGEST_WRITE,
        rbac.MODULES_RUN,
    }
    assert rbac.STUDIO_EDIT not in perms
    assert rbac.USERS_MANAGE not in perms


def test_developer_is_analyst_plus_studio():
    analyst = rbac.effective_permissions({"role": "analyst"}, {})
    dev = rbac.effective_permissions({"role": "developer"}, {})
    assert analyst.issubset(dev)
    assert rbac.STUDIO_EDIT in dev
    assert rbac.STUDIO_EDIT not in analyst


def test_guest_is_minimal():
    perms = rbac.effective_permissions({"role": "guest"}, {})
    assert perms == {rbac.CASES_READ}


def test_unknown_role_grants_nothing():
    assert rbac.effective_permissions({"role": "wat"}, {}) == set()


# ── Group unions ────────────────────────────────────────────────────────────────


def test_group_grants_explicit_permissions():
    groups = {
        "ir": rbac.empty_group("ir", "IR"),
    }
    groups["ir"]["permissions"] = [rbac.RULES_MANAGE, rbac.CTI_MANAGE]
    user = {"role": "guest", "groups": ["ir"]}
    perms = rbac.effective_permissions(user, groups)
    assert rbac.CASES_READ in perms  # from guest role
    assert rbac.RULES_MANAGE in perms  # from group
    assert rbac.CTI_MANAGE in perms


def test_group_grants_via_roles():
    groups = {"sec": rbac.empty_group("sec", "Sec")}
    groups["sec"]["roles"] = ["analyst"]
    user = {"role": "guest", "groups": ["sec"]}
    perms = rbac.effective_permissions(user, groups)
    # guest (cases.read) UNION analyst preset
    assert rbac.INGEST_WRITE in perms
    assert rbac.MODULES_RUN in perms


def test_group_unknown_permission_ignored():
    groups = {"g": rbac.empty_group("g", "G")}
    groups["g"]["permissions"] = ["bogus.permission", rbac.AUDIT_READ]
    perms = rbac.effective_permissions({"role": "guest", "groups": ["g"]}, groups)
    assert "bogus.permission" not in perms
    assert rbac.AUDIT_READ in perms


def test_membership_in_missing_group_is_safe():
    perms = rbac.effective_permissions({"role": "guest", "groups": ["nope"]}, {})
    assert perms == {rbac.CASES_READ}


def test_multiple_groups_union():
    groups = {
        "a": rbac.empty_group("a", "A"),
        "b": rbac.empty_group("b", "B"),
    }
    groups["a"]["permissions"] = [rbac.CASES_WRITE]
    groups["b"]["permissions"] = [rbac.CASES_DELETE]
    perms = rbac.effective_permissions({"role": "guest", "groups": ["a", "b"]}, groups)
    assert {rbac.CASES_READ, rbac.CASES_WRITE, rbac.CASES_DELETE}.issubset(perms)


# ── extra_permissions union ─────────────────────────────────────────────────────


def test_extra_permissions_layered_on_top():
    user = {"role": "guest", "extra_permissions": [rbac.CASES_EXPORT, rbac.AUDIT_READ]}
    perms = rbac.effective_permissions(user, {})
    assert perms == {rbac.CASES_READ, rbac.CASES_EXPORT, rbac.AUDIT_READ}


def test_extra_permissions_unknown_ignored():
    user = {"role": "guest", "extra_permissions": ["nope.nope"]}
    assert rbac.effective_permissions(user, {}) == {rbac.CASES_READ}


def test_full_union_role_group_extra():
    groups = {"g": rbac.empty_group("g", "G")}
    groups["g"]["permissions"] = [rbac.RULES_MANAGE]
    user = {
        "role": "analyst",
        "groups": ["g"],
        "extra_permissions": [rbac.AUDIT_READ],
    }
    perms = rbac.effective_permissions(user, groups)
    assert rbac.CASES_WRITE in perms  # role
    assert rbac.RULES_MANAGE in perms  # group
    assert rbac.AUDIT_READ in perms  # extra


# ── Company scope unions ─────────────────────────────────────────────────────────


def test_admin_companies_unrestricted():
    assert rbac.effective_companies({"role": "admin", "companies": ["x"]}, {}) is None


def test_empty_everywhere_is_unrestricted():
    assert rbac.effective_companies({"role": "analyst"}, {}) is None
    assert rbac.effective_companies({"role": "analyst", "companies": []}, {}) is None


def test_user_companies_only():
    assert rbac.effective_companies({"role": "analyst", "companies": ["acme"]}, {}) == ["acme"]


def test_company_union_with_groups():
    groups = {"g": rbac.empty_group("g", "G")}
    groups["g"]["companies"] = ["globex"]
    user = {"role": "analyst", "companies": ["acme"], "groups": ["g"]}
    assert rbac.effective_companies(user, groups) == ["acme", "globex"]


def test_company_union_dedupes_and_sorts():
    groups = {
        "g1": rbac.empty_group("g1", "G1"),
        "g2": rbac.empty_group("g2", "G2"),
    }
    groups["g1"]["companies"] = ["beta", "acme"]
    groups["g2"]["companies"] = ["acme"]
    user = {"role": "analyst", "companies": ["beta"], "groups": ["g1", "g2"]}
    assert rbac.effective_companies(user, groups) == ["acme", "beta"]


def test_group_only_company_scope():
    groups = {"g": rbac.empty_group("g", "G")}
    groups["g"]["companies"] = ["onlyco"]
    user = {"role": "analyst", "groups": ["g"]}
    assert rbac.effective_companies(user, groups) == ["onlyco"]


# ── Group shape ──────────────────────────────────────────────────────────────────


def test_empty_group_shape():
    g = rbac.empty_group("ir-team", "IR Team")
    assert set(g.keys()) == {
        "id",
        "name",
        "description",
        "roles",
        "permissions",
        "companies",
        "members",
    }
    assert g["id"] == "ir-team"
    assert g["name"] == "IR Team"
    assert g["roles"] == [] and g["permissions"] == [] and g["members"] == []
