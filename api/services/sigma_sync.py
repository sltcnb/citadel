"""Sigma HQ rules synchronization service."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Optional

import redis_keys as rk

from config import get_redis
from services.redis_mutate import mutate_json

try:
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.collection import SigmaCollection

    _SIGMA_AVAILABLE = True
except ImportError:
    _SIGMA_AVAILABLE = False

try:
    import yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

SIGMA_LOCAL_PATH = Path(os.getenv("SIGMA_LOCAL_PATH", "/tmp/sigma_rules"))


class SigmaSyncService:
    """Service for syncing Sigma HQ rules."""

    def __init__(self):
        self.redis = get_redis()
        self.backend = LuceneBackend() if _SIGMA_AVAILABLE else None
        # Synced rules live in the global alert library — every runner
        # (run-library, case check, worker auto-run) reads that key, so rules
        # stored anywhere else would never be evaluated. They keep their
        # sigma_* metadata and are tagged sigma_source=sigma_hq so the
        # /sigma/* endpoints can still find (and clear) them.
        self.library_key = rk.GLOBAL_ALERT_RULES
        self.last_sync_key = rk.GLOBAL_SIGMA_LAST_SYNC

    def sync_sigma_rules(
        self,
        categories: list[str] | None = None,
        tags: list[str] | None = None,
        levels: list[str] | None = None,
    ) -> dict:
        """
        Sync rules from Sigma HQ repository.

        Args:
            categories: Filter by Sigma categories (e.g., ['malware', 'ransomware'])
            tags: Filter by MITRE ATT&CK tags (e.g., ['attack.persistence'])
            levels: Filter by severity (e.g., ['high', 'critical'])

        Returns:
            Sync result with imported/skipped counts
        """
        if not _SIGMA_AVAILABLE:
            raise RuntimeError(
                "Sigma libraries not installed. Run: pip install pysigma pysigma-backend-elasticsearch"
            )

        # Download Sigma rules
        sigma_rules_path = self._download_sigma_rules()

        # Load and filter rules
        logger.info("Loading Sigma rules from %s", sigma_rules_path)
        sigma_collection = SigmaCollection.load_ruleset(
            sigma_rules_path,
            on_beforeload=lambda p: self._should_load_rule(p, categories, tags, levels),
            on_load=lambda p, r: logger.debug("Loaded rule: %s", r.title),
        )

        logger.info("Loaded %d Sigma rules", len(sigma_collection.rules))

        # Convert to Elasticsearch queries
        converted_rules = []
        errors = []

        for rule in sigma_collection.rules:
            try:
                es_query = self.backend.convert(rule)
                converted_rules.append(self._convert_to_internal_format(rule, es_query))
            except Exception as e:
                errors.append({"rule_id": rule.id, "rule_title": rule.title, "error": str(e)})
                logger.warning("Failed to convert rule %s: %s", rule.title, e)

        # Merge into the global alert library (dedup by sigma_id, then by name
        # so a rule already seeded from the bundled YAMLs isn't duplicated).
        self._merge_legacy_store()
        library: list[dict] = json.loads(self.redis.get(self.library_key) or "[]")
        existing_sigma_ids = {r.get("sigma_id") for r in library}
        existing_names = {r.get("name", "").lower() for r in library}
        existing_ids = {r.get("id") for r in library}

        new_rules = []
        for rule in converted_rules:
            if rule["sigma_id"] in existing_sigma_ids or rule["name"].lower() in existing_names:
                continue
            # 8-char random ids can collide with seeded library rules.
            while rule["id"] in existing_ids:
                rule["id"] = str(uuid.uuid4())[:8]
            existing_ids.add(rule["id"])
            existing_names.add(rule["name"].lower())
            existing_sigma_ids.add(rule["sigma_id"])
            new_rules.append(rule)

        if new_rules:
            mutate_json(self.redis, self.library_key, lambda cur: cur + new_rules, [])
        self.redis.set(self.last_sync_key, datetime.now(UTC).isoformat())

        total = len(self.list_rules())
        logger.info("Sync complete: %d new rules, %d total", len(new_rules), total)

        return {
            "imported": len(new_rules),
            "skipped": len(converted_rules) - len(new_rules),
            "errors": len(errors),
            "total_rules": total,
            "error_details": errors[:10],  # First 10 errors only
        }

    def _merge_legacy_store(self) -> None:
        """One-time move of rules synced before they lived in the global library."""
        legacy: list[dict] = json.loads(self.redis.get(rk.GLOBAL_SIGMA_RULES) or "[]")
        if not legacy:
            return

        def _merge(existing: list[dict]) -> list[dict]:
            sigma_ids = {r.get("sigma_id") for r in existing}
            names = {r.get("name", "").lower() for r in existing}
            merged = list(existing)
            for rule in legacy:
                if rule.get("sigma_id") in sigma_ids or rule.get("name", "").lower() in names:
                    continue
                rule = dict(rule)
                rule.setdefault("sigma_source", "sigma_hq")
                rule.setdefault("rule_type", "sigma")
                merged.append(rule)
            return merged

        mutate_json(self.redis, self.library_key, _merge, [])
        self.redis.delete(rk.GLOBAL_SIGMA_RULES)
        logger.info("Migrated %d legacy synced Sigma rules into the global library", len(legacy))

    def list_rules(self) -> list[dict]:
        """Synced Sigma HQ rules, as stored in the global alert library."""
        self._merge_legacy_store()
        library: list[dict] = json.loads(self.redis.get(self.library_key) or "[]")
        return [r for r in library if r.get("sigma_source") == "sigma_hq"]

    def _download_sigma_rules(self) -> Path:
        """Download Sigma HQ rules from GitHub."""
        import tempfile
        import zipfile

        import requests

        SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"

        # Download
        logger.info("Downloading Sigma HQ rules...")
        response = requests.get(SIGMA_REPO_URL, stream=True, timeout=120)
        response.raise_for_status()

        # Extract
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            for chunk in response.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name

        extract_path = SIGMA_LOCAL_PATH / "sigma-master"
        if extract_path.exists():
            import shutil

            shutil.rmtree(extract_path)

        with zipfile.ZipFile(tmp_path, "r") as zip_ref:
            zip_ref.extractall(SIGMA_LOCAL_PATH)

        Path(tmp_path).unlink()

        logger.info("Extracted Sigma rules to %s", extract_path)

        return extract_path / "rules"

    def _should_load_rule(
        self,
        path: Path,
        categories: Optional[List[str]],
        tags: Optional[List[str]],
        levels: Optional[List[str]],
    ) -> bool:
        """Filter rules based on criteria (all provided filters must match)."""
        if path.suffix not in (".yml", ".yaml"):
            return False

        if "deprecated" in path.parts:
            return False

        if not (categories or tags or levels):
            return True

        if not _YAML_AVAILABLE:
            logger.warning("PyYAML not installed — cannot apply sync filters to %s", path)
            return False

        # Filters were requested — read the rule header to evaluate them.
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        if not isinstance(data, dict):
            return False

        if levels and str(data.get("level", "")).lower() not in {
            str(lvl).lower() for lvl in levels
        }:
            return False

        if tags:
            rule_tags = {str(t).lower() for t in data.get("tags") or []}
            if not rule_tags & {str(t).lower() for t in tags}:
                return False

        if categories:
            logsource = data.get("logsource") or {}
            # Sigma categories are either the logsource category or the
            # repository folder the rule ships in (e.g. rules/windows/malware).
            haystack = {str(logsource.get("category", "")).lower()}
            haystack.update(p.lower() for p in path.parts)
            if not haystack & {str(c).lower() for c in categories}:
                return False

        return True

    def _convert_to_internal_format(self, rule, es_query: str) -> Dict:
        """Convert Sigma rule to internal format."""
        # Extract MITRE ATT&CK tags
        mitre_tags = []
        if rule.tags:
            mitre_tags = [str(t) for t in rule.tags if str(t).startswith("attack.")]

        # Map Sigma logsource to artifact_type
        artifact_type = self._map_logsource(rule.logsource)

        # Get query string from ES backend result
        query_str = es_query[0] if isinstance(es_query, list) else str(es_query)

        return {
            "id": str(uuid.uuid4())[:8],
            "sigma_id": rule.id or f"sigma-{uuid.uuid4().hex[:8]}",
            "sigma_source": "sigma_hq",
            "name": rule.title,
            "description": rule.description or "",
            "category": self._get_category(rule),
            "artifact_type": artifact_type,
            "query": query_str,
            "threshold": 1,
            "rule_type": "sigma",
            "sigma_yaml": str(rule.source) if rule.source else "",
            "sigma_level": rule.level.value if rule.level else "",
            "sigma_tags": mitre_tags,
            "sigma_status": rule.status.value if rule.status else "",
            "sigma_author": rule.author or [],
            "sigma_date": rule.date or "",
            "sigma_modified": rule.modified or "",
            "sigma_references": rule.references or [],
            "created_at": datetime.now(UTC).isoformat(),
        }

    def _map_logsource(self, logsource) -> str:
        """Map Sigma logsource to artifact_type."""
        if not logsource:
            return ""

        product = logsource.product.lower() if logsource.product else ""
        service = logsource.service.lower() if logsource.service else ""
        category = logsource.category.lower() if logsource.category else ""

        # Windows Event Logs
        if product == "windows":
            if service in ["security", "system", "application", "powershell", "sysmon"]:
                return "evtx"
            return "evtx"

        # Linux
        if product in ["linux", "ubuntu", "debian", "centos", "rhel"]:
            return "syslog"

        # Network logs
        if category in ["firewall", "proxy", "dns"]:
            return "suricata"

        # Web servers
        if category == "webserver":
            return "syslog"

        # Azure
        if product == "azure":
            return "syslog"

        # macOS
        if product == "macos":
            return "syslog"

        return ""

    def _get_category(self, rule) -> str:
        """Extract category from Sigma rule."""
        # Try MITRE ATT&CK tactic from tags
        if rule.tags:
            tactic_map = {
                "attack.persistence": "Persistence",
                "attack.privilege_escalation": "Privilege Escalation",
                "attack.defense_evasion": "Defense Evasion",
                "attack.credential_access": "Credential Access",
                "attack.discovery": "Discovery",
                "attack.lateral_movement": "Lateral Movement",
                "attack.execution": "Execution",
                "attack.command_and_control": "Command & Control",
                "attack.exfiltration": "Exfiltration",
                "attack.collection": "Collection",
                "attack.initial_access": "Initial Access",
                "attack.impact": "Impact",
            }
            for tag in rule.tags:
                tag_str = str(tag).lower()
                if tag_str in tactic_map:
                    return tactic_map[tag_str]

        # Fallback to logsource category
        if rule.logsource and rule.logsource.category:
            return rule.logsource.category.title()

        return "Other"

    def get_sync_status(self) -> Dict:
        """Get last sync status."""
        last_sync = self.redis.get(self.last_sync_key)
        rule_count = len(self.list_rules())

        return {
            "last_sync": last_sync,
            "sigma_rules_count": rule_count,
            "sigma_available": _SIGMA_AVAILABLE,
        }

    def clear_sigma_rules(self) -> Dict:
        """Clear all synced Sigma rules (from the library and the legacy store)."""
        counts: dict = {}

        def _purge(existing: list[dict]) -> list[dict]:
            kept = [r for r in existing if r.get("sigma_source") != "sigma_hq"]
            counts["cleared"] = len(existing) - len(kept)
            return kept

        mutate_json(self.redis, self.library_key, _purge, [])
        counts["cleared"] += len(json.loads(self.redis.get(rk.GLOBAL_SIGMA_RULES) or "[]"))
        self.redis.delete(rk.GLOBAL_SIGMA_RULES)  # legacy pre-merge store
        self.redis.delete(self.last_sync_key)

        return {"cleared": counts["cleared"]}
