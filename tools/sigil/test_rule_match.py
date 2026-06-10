#!/usr/bin/env python3
"""Run native Sigil rules against the sample_events corpus.

Loads a handful of rules from the native rule packs, evaluates each against the
positive and negative ECS corpora via the offline Lucene-subset matcher, and
asserts the expected fire / no-fire outcome.

Runs under pytest (``pytest tools/sigil/test_rule_match.py``) and also
standalone (``python tools/sigil/test_rule_match.py``) so it works in CI
environments that have not installed pytest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sigil_match import query_matches, rule_fires  # noqa: E402

CORPUS = HERE / "sample_events"


def _load_events(name: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (CORPUS / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _load_rule(pack: str, rule_name: str) -> dict:
    data = yaml.safe_load((HERE / pack).read_text(encoding="utf-8"))
    for rule in data["rules"]:
        if rule["name"] == rule_name:
            return rule
    raise AssertionError(f"rule {rule_name!r} not found in {pack}")


def test_event_log_cleared_fires_on_positive():
    rule = _load_rule("01_anti_forensics.yaml", "Windows Event Log Cleared")
    fired, count = rule_fires(rule, _load_events("positive.jsonl"))
    assert fired and count >= 1, f"expected fire, got count={count}"


def test_event_log_cleared_silent_on_negative():
    rule = _load_rule("01_anti_forensics.yaml", "Windows Event Log Cleared")
    fired, count = rule_fires(rule, _load_events("negative.jsonl"))
    assert not fired and count == 0, f"expected no fire, got count={count}"


def test_shadow_copy_deletion_fires_only_on_shadow_tampering():
    rule = _load_rule("01_anti_forensics.yaml", "Shadow Copy Deletion")
    pos_fired, _ = rule_fires(rule, _load_events("positive.jsonl"))
    neg_fired, neg_count = rule_fires(rule, _load_events("negative.jsonl"))
    # Positive corpus has `vssadmin delete shadows`; the negative corpus's only
    # 4688 process-create is a benign `wbadmin get versions` (no vssadmin/wmic,
    # no delete/shadow tokens) so the rule must stay silent.
    assert pos_fired, "shadow-copy-delete rule should fire on positive corpus"
    assert not neg_fired and neg_count == 0, (
        f"shadow-copy-delete must ignore benign backup activity (count={neg_count})"
    )


def test_brute_force_respects_threshold():
    rule = _load_rule("02_authentication.yaml", "Brute Force — Multiple Failed Logons")
    pos_fired, pos_count = rule_fires(rule, _load_events("positive.jsonl"))
    neg_fired, neg_count = rule_fires(rule, _load_events("negative.jsonl"))
    assert pos_count >= 10 and pos_fired, (
        f"positive corpus should clear threshold (count={pos_count})"
    )
    # Negative corpus has a single 4625 — below the threshold of 10.
    assert neg_count == 1 and not neg_fired, (
        f"single failed logon must not fire (count={neg_count})"
    )


def test_query_matcher_primitives():
    ev = {
        "message": "vssadmin delete shadows",
        "evtx": {"event_id": 4688},
        "host": {"name": "WIN-FS01"},
    }
    assert query_matches("evtx.event_id:4688", ev)
    assert query_matches("evtx.event_id:4688 AND message:*delete*", ev)
    assert query_matches("host.name:WIN-FS01 OR host.name:NOPE", ev)
    assert not query_matches("evtx.event_id:1102", ev)
    assert not query_matches("NOT evtx.event_id:4688", ev)


def _main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"PASS {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"\nrule-match tests: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
