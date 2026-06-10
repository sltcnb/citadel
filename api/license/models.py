"""License data models shared between client and gate."""

from __future__ import annotations

from dataclasses import dataclass, field

PLAN_FEATURES: dict[str, dict] = {
    "community": {
        "max_cases": 3,
        "max_users": 2,
        "export": False,
        "ai_assist": False,
        "multitenancy": False,
        "s3_archive": False,
        "alert_rules": True,
        "custom_plugins": True,
    },
    "pro": {
        "max_cases": None,
        "max_users": None,
        "export": True,
        "ai_assist": False,
        "multitenancy": False,
        "s3_archive": True,
        "alert_rules": True,
        "custom_plugins": True,
    },
    "enterprise": {
        "max_cases": None,
        "max_users": None,
        "max_companies": 1,
        "export": True,
        "ai_assist": True,
        "multitenancy": True,
        "s3_archive": True,
        "alert_rules": True,
        "custom_plugins": True,
        "mssp_mode": False,
    },
    # MSSP — many client tenants under one platform. Adds explicit
    # multi-company management (cross-company dashboards, per-company quotas,
    # branded reports). All enterprise features + mssp_mode + no company cap.
    "mssp": {
        "max_cases": None,
        "max_users": None,
        "max_companies": None,
        "export": True,
        "ai_assist": True,
        "multitenancy": True,
        "s3_archive": True,
        "alert_rules": True,
        "custom_plugins": True,
        "mssp_mode": True,
    },
}

PLAN_LABELS = {
    "community": "Community",
    "pro": "Pro",
    "enterprise": "Enterprise",
    "mssp": "MSSP",
}

UPGRADE_PATHS = {
    "community": "pro",
    "pro": "enterprise",
    "enterprise": "mssp",
    "mssp": None,
}


@dataclass
class LicenseInfo:
    valid: bool
    plan: str
    org_name: str
    seats: int
    valid_until: str | None
    features: dict = field(default_factory=dict)
    offline_token: str | None = None
    message: str = ""

    def is_feature_enabled(self, feature: str) -> bool:
        return bool(self.features.get(feature, False))

    def get_limit(self, limit: str) -> int | None:
        """Return None for unlimited, int for capped."""
        return self.features.get(limit)

    @property
    def plan_label(self) -> str:
        return PLAN_LABELS.get(self.plan, self.plan.capitalize())

    @property
    def upgrade_to(self) -> str | None:
        return UPGRADE_PATHS.get(self.plan)


def community_license(
    message: str = "Community edition — no license key configured",
) -> LicenseInfo:
    """The default license — returned whenever no valid CITADEL_LICENSE_KEY
    is present. Always valid, always limited to the Community feature set."""
    return LicenseInfo(
        valid=True,
        plan="community",
        org_name="Community",
        seats=PLAN_FEATURES["community"].get("max_users", 2) or 2,
        valid_until=None,
        features=PLAN_FEATURES["community"],
        message=message,
    )
