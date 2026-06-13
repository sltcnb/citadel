"""Resolution of the Sigma detection-rules opt-out.

Sigma can be disabled at two scopes. Precedence (most specific wins):

    per-case override  >  global runtime setting  >  SIGMA_ENABLED env default

- Global runtime setting lives in Redis at ``rk.GLOBAL_SIGMA_ENABLED`` ("1"/"0").
  Unset means "inherit the SIGMA_ENABLED environment default", so an operator who
  set the env var still gets the expected behaviour until an admin flips the
  runtime toggle.
- Per-case override lives on the case hash field ``sigma_enabled`` ("1"/"0").
  Absent means "inherit the global setting".

All readers fail open to the env default on Redis errors — a flaky Redis must
never silently turn detection off (or on) in a way that diverges from config.
"""

from __future__ import annotations

import redis_keys as rk

from config import get_redis, settings

_CASE_FIELD = "sigma_enabled"


def get_global_sigma_enabled() -> bool:
    """Effective global Sigma switch: Redis override else SIGMA_ENABLED env."""
    try:
        v = get_redis().get(rk.GLOBAL_SIGMA_ENABLED)
    except Exception:
        return settings.SIGMA_ENABLED
    if v is None:
        return settings.SIGMA_ENABLED
    return v != "0"


def set_global_sigma_enabled(enabled: bool) -> bool:
    """Persist the global runtime override. Returns the value set."""
    get_redis().set(rk.GLOBAL_SIGMA_ENABLED, "1" if enabled else "0")
    return enabled


def get_case_sigma_override(case_id: str) -> bool | None:
    """Per-case override: True/False if set, None if the case inherits global."""
    try:
        v = get_redis().hget(f"case:{case_id}", _CASE_FIELD)
    except Exception:
        return None
    if v is None or v == "":
        return None
    return v != "0"


def set_case_sigma_override(case_id: str, enabled: bool | None) -> bool | None:
    """Set (True/False) or clear (None → inherit global) the per-case override."""
    r = get_redis()
    key = f"case:{case_id}"
    if enabled is None:
        r.hdel(key, _CASE_FIELD)
    else:
        r.hset(key, _CASE_FIELD, "1" if enabled else "0")
    return enabled


def sigma_enabled_for_case(case_id: str) -> bool:
    """Effective Sigma switch for a case: per-case override else global."""
    override = get_case_sigma_override(case_id)
    if override is not None:
        return override
    return get_global_sigma_enabled()


def is_sigma_rule(rule: dict) -> bool:
    """True if a library rule is a Sigma rule (by type or by carrying Sigma YAML)."""
    return rule.get("rule_type") == "sigma" or bool(rule.get("sigma_yaml"))
