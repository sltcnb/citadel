"""Sigil — Sigma -> Elasticsearch query conversion.

pysigma is the production backend; when it is unavailable this module provides a
documented *subset* converter covering the Sigma detection constructs the Citadel
rule corpus actually uses:

  * selection blocks: a mapping (AND of field matches) or a list of mappings
    (OR of those mappings);
  * field modifiers: ``contains`` / ``startswith`` / ``endswith`` / ``re`` /
    (none = equals);
  * list values: OR of the alternatives;
  * conditions: ``all of selection_*`` / ``1 of selection_*`` / ``X of them`` and
    boolean combinations of named blocks with ``and`` / ``or`` / ``not``.

Native Citadel rules already ship an Elasticsearch ``query`` (Lucene); for those
``convert_rule`` is a pass-through. The output is an ES ``query_string`` query.

    python3 tools/sigil/sigil_convert.py            # convert whole corpus, report
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent
NON_RULE_FILES = {"sample_events"}


def _lucene_value(field: str, modifier: str | None, value) -> str:
    v = str(value)
    # escape Lucene specials that would break the term (minimal, best-effort)
    esc = re.sub(r'([+\-!(){}\[\]^"~:\\/])', r"\\\1", v)
    if modifier == "contains":
        term = f"*{esc}*"
    elif modifier == "startswith":
        term = f"{esc}*"
    elif modifier == "endswith":
        term = f"*{esc}"
    elif modifier == "re":
        return f"{field}:/{v}/"
    else:
        # exact match — quote when it contains whitespace
        return f'{field}:"{v}"' if " " in v else f"{field}:{esc}"
    return f"{field}:{term}"


def _field_match(key: str, value) -> str:
    field, _, modifier = key.partition("|")
    modifier = modifier or None
    if isinstance(value, list):
        alts = [_lucene_value(field, modifier, v) for v in value]
        return "(" + " OR ".join(alts) + ")"
    return _lucene_value(field, modifier, value)


def _block_to_query(block) -> str:
    """A selection block -> a Lucene fragment.

    dict  -> AND of its field matches; list -> OR of its sub-blocks.
    """
    if isinstance(block, list):
        return "(" + " OR ".join(_block_to_query(b) for b in block) + ")"
    if isinstance(block, dict):
        parts = [_field_match(k, v) for k, v in block.items()]
        return "(" + " AND ".join(parts) + ")" if len(parts) > 1 else (parts[0] if parts else "*")
    return "*"


def _resolve_condition(condition: str, blocks: dict[str, str]) -> str:
    cond = condition.strip()

    def group(prefix_match, joiner):
        names = [n for n in blocks if prefix_match(n)]
        if not names:
            return "*"
        return "(" + f" {joiner} ".join(blocks[n] for n in names) + ")"

    m = re.match(r"^all of (\w+)\*$", cond)
    if m:
        return group(lambda n: n.startswith(m.group(1)), "AND")
    m = re.match(r"^(1|any) of (\w+)\*$", cond)
    if m:
        return group(lambda n: n.startswith(m.group(2)), "OR")
    if cond in ("all of them",):
        return "(" + " AND ".join(blocks.values()) + ")"
    if cond in ("1 of them", "any of them"):
        return "(" + " OR ".join(blocks.values()) + ")"

    # boolean expression over named blocks: tokens and/or/not/() + names
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w*]+", cond)
    out = []
    for t in tokens:
        low = t.lower()
        if low in ("and", "or", "not", "(", ")"):
            out.append({"and": "AND", "or": "OR", "not": "NOT"}.get(low, t))
        elif t.endswith("*"):
            names = [n for n in blocks if n.startswith(t[:-1])]
            out.append("(" + " OR ".join(blocks[n] for n in names) + ")" if names else "*")
        elif t in blocks:
            out.append(blocks[t])
        else:
            out.append("*")
    return " ".join(out) if out else "*"


def sigma_detection_to_query(sigma_detection: str) -> str:
    """Convert a Sigma detection block (string or dict) to an ES query_string."""
    det = yaml.safe_load(sigma_detection) if isinstance(sigma_detection, str) else sigma_detection
    if not isinstance(det, dict):
        raise ValueError("sigma_detection is not a mapping")
    condition = det.get("condition", "all of them")
    blocks = {k: _block_to_query(v) for k, v in det.items() if k != "condition"}
    if isinstance(condition, list):  # multiple conditions -> OR
        return "(" + " OR ".join(_resolve_condition(c, blocks) for c in condition) + ")"
    return _resolve_condition(str(condition), blocks)


def _pysigma_convert(rule: dict) -> str | None:
    """Convert via pysigma + the ES/Lucene backend when both are installed.

    Returns None when pysigma (or the backend) is unavailable or the rule can't
    be expressed as a full Sigma document, so the caller falls back to the
    documented subset converter below. This is the production-preferred path."""
    try:
        from sigma.backends.elasticsearch import LuceneBackend  # type: ignore
        from sigma.collection import SigmaCollection  # type: ignore
    except Exception:
        return None
    det = rule.get("sigma_detection")
    if not det:
        return None
    detection = yaml.safe_load(det) if isinstance(det, str) else det
    doc = {
        "title": rule.get("name", "rule"),
        "logsource": rule.get("logsource", {"product": "windows"}),
        "detection": detection,
    }
    try:
        collection = SigmaCollection.from_dicts([doc])
        out = LuceneBackend().convert(collection)
        return out[0] if out else None
    except Exception:
        return None


def convert_rule(rule: dict) -> str:
    """ES query for a rule. Native rules pass their Lucene ``query`` through;
    Sigma rules use pysigma when available, else the subset converter."""
    if rule.get("query"):
        return rule["query"]
    if rule.get("sigma_detection"):
        via_pysigma = _pysigma_convert(rule)
        if via_pysigma is not None:
            return via_pysigma
        return sigma_detection_to_query(rule["sigma_detection"])
    raise ValueError("rule has neither 'query' nor 'sigma_detection'")


def _iter_rules(path: Path):
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = d.get("rules") if isinstance(d, dict) else d
    for r in rules or []:
        if isinstance(r, dict):
            yield r


def convert_all() -> int:
    files = [p for p in sorted(RULES_DIR.glob("*.yaml")) if p.stem not in NON_RULE_FILES]
    files += sorted((RULES_DIR / "sigma_hq").glob("*.yaml"))
    ok = native = sigma = fail = 0
    failures = []
    for f in files:
        for r in _iter_rules(f):
            try:
                convert_rule(r)
                ok += 1
                if r.get("query"):
                    native += 1
                else:
                    sigma += 1
            except Exception as exc:  # noqa: BLE001
                fail += 1
                failures.append(f"{f.name} :: {r.get('name', '?')} :: {exc}")
    print(
        f"Sigil convert: {ok} converted ({native} native passthrough, {sigma} sigma) — {fail} failures"
    )
    for fl in failures[:20]:
        print("  FAIL", fl)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(convert_all())
