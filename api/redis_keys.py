"""Centralized Redis key patterns.

All fo: key strings in the application live here.
Simple constants for static keys; functions for parameterized keys.
"""

# ── Auth ──────────────────────────────────────────────────────────────────────
USERS_SET = "fo:users"


def user_key(username: str) -> str:
    return f"fo:user:{username}"


def jwt_revoked(jti: str) -> str:
    return f"fo:revoked:jwt:{jti}"


def login_ratelimit(ip: str) -> str:
    return f"fo:ratelimit:login:{ip}"


# ── Cases ─────────────────────────────────────────────────────────────────────
def case_alert_rules(case_id: str) -> str:
    return f"fo:alert_rules:{case_id}"


def case_alert_run(case_id: str) -> str:
    return f"fo:alert_run:{case_id}"


def case_alert_run_lock(case_id: str) -> str:
    return f"fo:alert_run_lock:{case_id}"


def case_alert_rule_run(case_id: str) -> str:
    return f"fo:alert_rule_run:{case_id}"


def case_notes(case_id: str) -> str:
    return f"fo:notes:{case_id}"


def case_saved_searches(case_id: str) -> str:
    return f"fo:saved_searches:{case_id}"


def case_module_runs(case_id: str) -> str:
    return f"fo:case:{case_id}:module_runs"


# ── Global alert rules ────────────────────────────────────────────────────────
WEBHOOKS = "fo:webhooks"
GLOBAL_ALERT_RULES = "fo:alert_rules:_global"
GLOBAL_ALERT_RULES_SEEDED = "fo:alert_rules:_global:seeded"
GLOBAL_ALERT_RULES_MIGRATED = "fo:alert_rules:migrated_v2"
GLOBAL_SIGMA_RULES = "fo:alert_rules:_global:sigma"
GLOBAL_SIGMA_LAST_SYNC = "fo:alert_rules:_global:sigma:last_sync"

# ── Module runs ───────────────────────────────────────────────────────────────
MALWARE_RUNS = "fo:malware_runs"


def module_run(run_id: str) -> str:
    return f"fo:module_run:{run_id}"


def module_log(run_id: str) -> str:
    return f"fo:module_log:{run_id}"


def module_cancel(run_id: str) -> str:
    return f"fo:module_cancel:{run_id}"


# ── YARA ──────────────────────────────────────────────────────────────────────
YARA_RULES_SET = "fo:yara_rules"


def yara_rule(rule_id: str) -> str:
    return f"fo:yara_rule:{rule_id}"


# ── Config ────────────────────────────────────────────────────────────────────
CUCKOO_CONFIG = "fo:config:cuckoo"
MALWOVERVIEW_CONFIG = "fo:config:malwoverview"

# ── S3 ────────────────────────────────────────────────────────────────────────
S3_IMPORT_CONFIG = "fo:s3_config"
S3_IMPORT_CONFIGS_LIST = "fo:s3_configs:import"
S3_TRIAGE_CONFIG = "fo:s3_triage_config"


def s3_import_config(cfg_id: str) -> str:
    return f"fo:s3_config:{cfg_id}"


# ── CTI ───────────────────────────────────────────────────────────────────────
CTI_FEEDS = "fo:cti:feeds"


def cti_ioc_type(ioc_type: str) -> str:
    return f"fo:cti:iocs:type:{ioc_type}"


def cti_ioc_hash(value: str) -> str:
    return f"fo:cti:iocs:hash:{value}"


def cti_ioc_detail(ioc_id: str) -> str:
    return f"fo:cti:iocs:detail:{ioc_id}"


# ── LLM ───────────────────────────────────────────────────────────────────────
LLM_CONFIG = "fo:llm_config"
LLM_USAGE = "fo:llm:usage"
OPENROUTER_CACHE = "fo:openrouter:models"


def llm_usage_hourly(hour: int) -> str:
    return f"fo:llm:usage:h:{hour}"


def llm_usage_daily(day: int) -> str:
    return f"fo:llm:usage:d:{day}"


# ── Misc ──────────────────────────────────────────────────────────────────────
ARCHIVE_SETTINGS = "fo:archive_settings"
COMPANIES = "fo:companies"
METRICS_HISTORY = "fo:metrics:snapshots"
