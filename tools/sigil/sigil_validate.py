#!/usr/bin/env python3
"""Sigil rule CI — validate, dedup UUIDs, and lint the rule corpus.

Walks every ``*.yaml`` rule file under ``tools/sigil`` (Citadel-native
packs and the imported ``sigma_hq/`` packs), validates that each file parses
as YAML, that every rule carries its required fields, that no UUID is reused
across the whole corpus, and that rule structure passes a set of lint checks.

Native rules look like::

    category: Anti-Forensics
    rules:
      - name: Windows Event Log Cleared
        description: ...
        artifact_type: evtx
        query: "evtx.event_id:1102 OR evtx.event_id:104"
        threshold: 1

SigmaHQ imports carry a ``sigma_detection`` block instead of ``query`` and may
embed their upstream UUID either as an ``id:`` field or as a
``# sigma_id: <uuid>`` comment (the import script emits the latter).

Run it::

    python tools/sigil/sigil_validate.py            # validate everything
    python tools/sigil/sigil_validate.py --quiet     # only print summary
    python tools/sigil/sigil_validate.py path/to.yaml  # a subset

Exits non-zero when any error is found so CI can gate on it.
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid as _uuid
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dependency of the API
    sys.stderr.write("PyYAML is required: pip install pyyaml\n")
    raise SystemExit(2)

RULES_DIR = Path(__file__).resolve().parent

# Files that live in the rule dirs but are not rule packs.
NON_RULE_FILES = {"brick.yaml", "capabilities.yaml"}

# Required fields for a Citadel-native rule (query-style) ...
NATIVE_REQUIRED = ("name", "description", "artifact_type", "query", "threshold")
# ... and for an imported SigmaHQ rule (detection-block style). `artifact_type`
# is auto-derived from the Sigma logsource at import time and may legitimately
# be absent on some imports (see sigma_hq/README.md), so it is checked as a
# warning rather than a hard requirement for sigma rules.
SIGMA_REQUIRED = ("name", "description", "sigma_detection")
SIGMA_RECOMMENDED = ("artifact_type",)

# A SigmaHQ import line embedding the upstream UUID as a comment.
_SIGMA_ID_RE = re.compile(r"#\s*sigma_id:\s*([0-9a-fA-F-]{36})")
# Severity vocabulary the UI/report/triage rank on (LEVEL_INT in module_task).
_LEVELS = {"critical", "high", "medium", "low", "informational"}

# Keys accepted inside a rule's `correlation:` block (services/rule_eval.py).
_CORRELATION_KEYS = {"group_by", "distinct", "min_distinct", "window"}
_WINDOW_RE = re.compile(r"^\d+[smhd]$")

# Lucene field tokens we expect rule queries to reference.
_FIELD_RE = re.compile(r"\b([a-zA-Z_][\w.]*)\s*:")

# ── Unmatchable-wildcard lint ────────────────────────────────────────────────
# A native rule's query runs as an Elasticsearch ``query_string`` against the
# case indices. On an ANALYZED (``text``) field, each wildcard term is matched
# against ONE indexed token — and the standard analyzer has already split the
# original value on punctuation. So a pattern whose inner text straddles a token
# boundary can never match, however well-formed the rule looks:
#
#     message:*LogonType\:10*       → tokens are [logontype, 10]      → 0 hits, always
#     message:*-EncodedCommand*     → token is  [encodedcommand]      → 0 hits, always
#     process.path:*\\Temp\\*       → tokens are [c, windows, temp]   → 0 hits, always
#
# Verified against Elasticsearch 8.13 (the version docker-compose pins) with the
# real fo-cases index template: the separator set below is measured, not guessed,
# by indexing "aaa<ch>bbb" and asking whether *aaa<ch>bbb* matches.
#
# Case is NOT part of this problem — ES lowercases wildcard terms for the field's
# analyzer, so ``*NTLM*`` matches ``ntlm`` fine.
#
# The fix is one of:
#   * query the structured field the parser already emits
#     (``evtx.event_data.LogonType:10`` rather than a message wildcard), or
#   * wildcard the ``.keyword`` subfield, which is not analyzed
#     (``process.command_line.keyword:*-EncodedCommand*``) — but mind
#     ``ignore_above`` (``message.keyword`` drops values over 1024 chars), or
#   * drop the wildcards and match analyzed terms/phrases
#     (``message:"-EncodedCommand"``).
_TOKEN_SEPARATORS = set("-\\/$=@#%+&|,;!?()[]{}<>~^\"'")

# Fields known to be ``keyword`` (not analyzed) — a wildcard over raw punctuation
# is correct there. Anything ending in ``.keyword`` is handled generically.
_KEYWORD_FIELDS = {
    "artifact_type", "os", "source_file", "ingest_job_id", "fo_id", "case_id",
    "tags", "timestamp_desc", "user.domain", "user.sid", "user.type", "user.id",
    "host.os", "host.os_version", "host.domain", "host.timezone", "host.ip",
    "network.protocol", "network.action", "network.direction", "network.dst_host",
    "file.sha256", "file.sha1", "file.md5", "file.mime_type", "file.extension",
    "registry.value_type", "registry.hive", "evtx.level", "evtx.level_name",
    "evtx.channel", "evtx.provider_name", "evtx.correlation_activity_id",
}

# field:*pattern* / field:pat* / field:*pat — the wildcard term, unquoted.
_WILDCARD_TERM_RE = re.compile(r"([a-zA-Z_][\w.]*)\s*:\s*((?:[^\s()\"]*\*)[^\s()\"]*)")


def _unmatchable_wildcards(query: str) -> list[str]:
    """Return a message per wildcard term that can never match its field.

    Only flags ANALYZED fields: ``.keyword`` subfields and known keyword fields
    are exact-value, so punctuation in their wildcards is legitimate.
    """
    problems: list[str] = []
    for field, term in _WILDCARD_TERM_RE.findall(query):
        if field.endswith(".keyword") or field in _KEYWORD_FIELDS:
            continue
        # Strip the Lucene escapes so we judge the literal the user meant.
        literal = re.sub(r"\\(.)", r"\1", term).replace("*", "").replace("?", "")
        if not literal:
            continue
        hits = sorted({c for c in literal if c in _TOKEN_SEPARATORS})
        if hits:
            problems.append(
                f"wildcard {field}:{term} can never match — {''.join(hits)!r} "
                f"splits the value into separate tokens on an analyzed field; "
                f"use the structured field, {field}.keyword, or a non-wildcard term"
            )
        # A ':' joins letters but splits letter/digit (UAX#29 MidLetter), so
        # 'LogonType:10' tokenises as [logontype, 10] while 'aaa:bbb' does not.
        elif re.search(r"[A-Za-z]:\d|\d:[A-Za-z]", literal):
            problems.append(
                f"wildcard {field}:{term} can never match — ':' between a letter "
                f"and a digit splits the value into separate tokens; use the "
                f"structured field or {field}.keyword"
            )
    return problems


class Finding:
    """A single validator finding (error or warning)."""

    __slots__ = ("level", "file", "rule", "msg")

    def __init__(self, level: str, file: str, rule: str | None, msg: str) -> None:
        self.level = level
        self.file = file
        self.rule = rule
        self.msg = msg

    def __str__(self) -> str:
        loc = self.file if self.rule is None else f"{self.file} :: {self.rule}"
        return f"[{self.level.upper():5}] {loc}: {self.msg}"


def _is_uuid(value: str) -> bool:
    try:
        _uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _balanced_quotes_and_parens(query: str) -> str | None:
    """Return an error message if the Lucene query is structurally broken."""
    if query.count('"') % 2 != 0:
        return "unbalanced double-quotes in query"
    depth = 0
    for ch in query:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return "unbalanced parentheses in query (extra ')')"
    if depth != 0:
        return "unbalanced parentheses in query (missing ')')"
    # A dangling boolean operator usually means a copy/paste truncation.
    stripped = query.strip()
    for op in ("AND", "OR", "NOT"):
        if stripped.endswith(op):
            return f"query ends with dangling operator {op!r}"
        if stripped.startswith(op + " ") and op != "NOT":
            return f"query starts with operator {op!r}"
    return None


def collect_uuids(text: str, parsed: dict | None) -> list[str]:
    """Extract every UUID a file declares (id fields + sigma_id comments)."""
    found: list[str] = list(_SIGMA_ID_RE.findall(text))
    if isinstance(parsed, dict):
        for rule in parsed.get("rules") or []:
            if isinstance(rule, dict):
                rid = rule.get("id") or rule.get("sigma_id")
                if rid and _is_uuid(rid):
                    found.append(str(rid))
    return found


def validate_file(path: Path) -> tuple[list[Finding], int, dict[str, str]]:
    """Validate one rule file.

    Returns (findings, rule_count, {uuid: source-label}).
    """
    findings: list[Finding] = []
    rel = (
        str(path.relative_to(RULES_DIR.parent.parent))
        if RULES_DIR.parent.parent in path.parents
        else str(path)
    )
    text = path.read_text(encoding="utf-8")

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        findings.append(Finding("error", rel, None, f"YAML parse failed: {exc}"))
        return findings, 0, {}

    if not isinstance(parsed, dict):
        findings.append(Finding("error", rel, None, "top-level YAML must be a mapping"))
        return findings, 0, {}

    if "category" not in parsed:
        findings.append(Finding("warn", rel, None, "missing top-level 'category'"))

    rules = parsed.get("rules")
    if not isinstance(rules, list) or not rules:
        findings.append(Finding("error", rel, None, "'rules' must be a non-empty list"))
        return findings, 0, {}

    seen_names: set[str] = set()
    uuids: dict[str, str] = {}

    for idx, rule in enumerate(rules):
        label = None
        if not isinstance(rule, dict):
            findings.append(Finding("error", rel, f"rules[{idx}]", "rule must be a mapping"))
            continue

        label = rule.get("name") or f"rules[{idx}]"

        # name uniqueness within the file
        if rule.get("name"):
            if rule["name"] in seen_names:
                findings.append(Finding("error", rel, label, "duplicate rule name within file"))
            seen_names.add(rule["name"])

        is_sigma = "sigma_detection" in rule
        required = SIGMA_REQUIRED if is_sigma else NATIVE_REQUIRED
        for field in required:
            if field not in rule or rule[field] in (None, ""):
                findings.append(Finding("error", rel, label, f"missing required field {field!r}"))
        if is_sigma:
            for field in SIGMA_RECOMMENDED:
                if field not in rule or rule[field] in (None, ""):
                    findings.append(
                        Finding("warn", rel, label, f"missing recommended field {field!r}")
                    )

        # Severity lint (native rules). Without a level the UI cannot rank a
        # detection, the report cannot order findings, and auto-triage has no
        # basis to prioritise — the rule fires into an undifferentiated pile.
        if not is_sigma:
            lvl = rule.get("level")
            if lvl in (None, ""):
                findings.append(
                    Finding("warn", rel, label, "missing 'level' — detection cannot be ranked")
                )
            elif str(lvl).lower() not in _LEVELS:
                findings.append(
                    Finding(
                        "error", rel, label,
                        f"level {lvl!r} is not one of {'/'.join(sorted(_LEVELS))}",
                    )
                )

        # Correlation lint (native rules). See services/rule_eval.py — a
        # correlation block replaces count>=threshold with "one entity showed an
        # unusual amount of variety", which is what separates a password spray
        # from every failed login in the case.
        if not is_sigma and rule.get("correlation") is not None:
            corr = rule["correlation"]
            if not isinstance(corr, dict):
                findings.append(Finding("error", rel, label, "correlation must be a mapping"))
            else:
                unknown = set(corr) - _CORRELATION_KEYS
                if unknown:
                    findings.append(
                        Finding("error", rel, label,
                                f"unknown correlation key(s): {', '.join(sorted(unknown))}")
                    )
                if not str(corr.get("distinct") or "").strip():
                    findings.append(
                        Finding("error", rel, label, "correlation requires 'distinct'")
                    )
                md = corr.get("min_distinct")
                if not isinstance(md, int) or isinstance(md, bool) or md < 1:
                    findings.append(
                        Finding("error", rel, label,
                                f"correlation min_distinct must be a positive int, got {md!r}")
                    )
                elif md == 1:
                    findings.append(
                        Finding("warn", rel, label,
                                "correlation min_distinct of 1 is equivalent to a plain "
                                "threshold — it adds no discrimination")
                    )
                win = corr.get("window")
                if win is not None and not _WINDOW_RE.match(str(win).strip()):
                    findings.append(
                        Finding("error", rel, label,
                                f"correlation window {win!r} must look like 30s/15m/6h/7d")
                    )

        # threshold lint (native rules)
        if "threshold" in rule:
            thr = rule["threshold"]
            if not isinstance(thr, int) or isinstance(thr, bool) or thr < 1:
                findings.append(
                    Finding("error", rel, label, f"threshold must be a positive int, got {thr!r}")
                )

        # query lint (native rules)
        if not is_sigma and isinstance(rule.get("query"), str):
            err = _balanced_quotes_and_parens(rule["query"])
            if err:
                findings.append(Finding("error", rel, label, err))
            if not _FIELD_RE.search(rule["query"]):
                findings.append(
                    Finding("warn", rel, label, "query references no field:value token")
                )
            # A rule that cannot fire is worse than a missing rule: it reads as
            # coverage. Hard error so CI blocks it.
            for msg in _unmatchable_wildcards(rule["query"]):
                findings.append(Finding("error", rel, label, msg))

        # sigma_detection lint
        if is_sigma and isinstance(rule.get("sigma_detection"), str):
            if "condition" not in rule["sigma_detection"]:
                findings.append(Finding("error", rel, label, "sigma_detection missing 'condition'"))

        # UUID collection (per-rule id field)
        rid = rule.get("id") or rule.get("sigma_id")
        if rid is not None:
            if not _is_uuid(rid):
                findings.append(Finding("error", rel, label, f"id is not a valid UUID: {rid!r}"))
            else:
                uuids.setdefault(str(rid), f"{rel} :: {label}")

    # also harvest sigma_id comments (import script emits these)
    for m in _SIGMA_ID_RE.finditer(text):
        uuids.setdefault(m.group(1), f"{rel} (sigma_id comment)")

    return findings, len(rules), uuids


def discover_files(targets: list[str]) -> list[Path]:
    if targets:
        paths: list[Path] = []
        for t in targets:
            p = Path(t)
            if not p.is_absolute():
                p = (Path.cwd() / p).resolve()
            paths.append(p)
        return paths
    files = [p for p in sorted(RULES_DIR.glob("*.yaml")) if p.name not in NON_RULE_FILES]
    files += sorted((RULES_DIR / "sigma_hq").glob("*.yaml"))
    return files


def run(targets: list[str], quiet: bool = False) -> int:
    files = discover_files(targets)
    if not files:
        sys.stderr.write("no rule files found\n")
        return 1

    all_findings: list[Finding] = []
    total_rules = 0
    uuid_owner: dict[str, str] = {}
    dup_findings: list[Finding] = []

    for path in files:
        if not path.exists():
            all_findings.append(Finding("error", str(path), None, "file not found"))
            continue
        findings, count, uuids = validate_file(path)
        all_findings.extend(findings)
        total_rules += count
        for u, owner in uuids.items():
            if u in uuid_owner:
                dup_findings.append(
                    Finding(
                        "error",
                        owner.split(" :: ")[0],
                        None,
                        f"duplicate UUID {u} (also defined in {uuid_owner[u]})",
                    )
                )
            else:
                uuid_owner[u] = owner

    all_findings.extend(dup_findings)

    errors = [f for f in all_findings if f.level == "error"]
    warns = [f for f in all_findings if f.level == "warn"]

    if not quiet:
        for f in all_findings:
            print(f)

    print(
        f"\nSigil rule CI: {len(files)} file(s), {total_rules} rule(s), "
        f"{len(uuid_owner)} unique UUID(s) — "
        f"{len(errors)} error(s), {len(warns)} warning(s)."
    )
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate + lint the Sigil rule corpus.")
    ap.add_argument("targets", nargs="*", help="specific rule files (default: whole corpus)")
    ap.add_argument("--quiet", "-q", action="store_true", help="only print the summary line")
    args = ap.parse_args(argv)
    return run(args.targets, quiet=args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
