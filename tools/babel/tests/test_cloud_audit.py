"""Tests for the declarative cloud/identity mapping engine + cloud_audit parser.

Covers the engine primitives (path access, transforms, templates, detection) and
an end-to-end run of each shipped spec through the actual plugin, so a broken
spec or a regression in the engine fails CI rather than silently dropping events.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from babel.cloud_audit.cloud_audit_plugin import CloudAuditPlugin, _SPECS
from babel.base_plugin import PluginContext
from citadel_contracts import (
    apply_mapping,
    detect_spec,
    get_path,
    iter_records,
    render_template,
)
from citadel_contracts.mapping import MappingSpec, _coerce_ip

# ── Realistic one-record samples per source ────────────────────────────────
CLOUDTRAIL = {
    "Records": [{
        "eventVersion": "1.08", "eventTime": "2024-03-01T12:00:00Z",
        "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.5",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "userName": "alice",
                         "arn": "arn:aws:iam::123:user/alice", "principalId": "AIDA"},
        "userAgent": "aws-cli/2",
    }]
}
OKTA = [{
    "published": "2024-03-01T09:15:00.000Z", "eventType": "user.session.start",
    "displayMessage": "User login to Okta",
    "actor": {"alternateId": "bob@corp.com", "displayName": "Bob"},
    "client": {"ipAddress": "198.51.100.9"},
    "outcome": {"result": "SUCCESS"}, "severity": "INFO",
}]
GCP = {
    "timestamp": "2024-03-01T08:00:00Z", "severity": "NOTICE",
    "protoPayload": {"methodName": "storage.objects.get", "serviceName": "storage.googleapis.com",
                     "resourceName": "projects/_/buckets/b",
                     "authenticationInfo": {"principalEmail": "svc@proj.iam.gserviceaccount.com"},
                     "requestMetadata": {"callerIp": "35.1.2.3:443"}},
}
ENTRA = {
    "createdDateTime": "2024-03-01T07:00:00Z", "userPrincipalName": "carol@corp.com",
    "appDisplayName": "Office 365", "ipAddress": "192.0.2.7",
    "status": {"errorCode": 0, "failureReason": "None"},
}
O365 = {
    "CreationTime": "2024-03-01T06:00:00", "Workload": "Exchange",
    "Operation": "MailItemsAccessed", "UserId": "dave@corp.com",
    "ClientIP": "[2001:db8::1]:50000", "ResultStatus": "Succeeded",
}

ALL_DOCS = {
    "aws_cloudtrail": CLOUDTRAIL,
    "okta_system_log": OKTA,
    "gcp_audit": GCP,
    "azure_signin": ENTRA,
    "o365_audit": O365,
}


# ── Engine primitives ──────────────────────────────────────────────────────
def test_get_path_dotted_and_indexed():
    rec = {"a": {"b": [{"c": 1}, {"c": 2}]}}
    assert get_path(rec, "a.b.1.c") == 2
    assert get_path(rec, "a.b.9.c") is None
    assert get_path(rec, "a.missing") is None


@pytest.mark.parametrize("raw,expected", [
    ("34.38.56.167:57772", "34.38.56.167"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1"),
    ("1.2.3.4", "1.2.3.4"),
])
def test_ip_transform(raw, expected):
    assert _coerce_ip(raw) == expected


def test_render_template_missing_token_is_blank():
    assert render_template("{a} - {b.c}", {"a": "x"}) == "x -"


def test_empty_detect_never_matches():
    spec = MappingSpec.from_dict({"name": "x", "detect": {}})
    assert spec.detect_match({"anything": 1}) is False


# ── Specs load + detect uniquely ────────────────────────────────────────────
def test_all_specs_loaded():
    names = {s.name for s in _SPECS}
    assert {"aws_cloudtrail", "azure_signin", "o365_audit", "gcp_audit", "okta_system_log"} <= names


@pytest.mark.parametrize("expected_name,doc", list(ALL_DOCS.items()))
def test_each_source_detects_to_exactly_one_spec(expected_name, doc):
    for rec in iter_records(doc):
        matches = [s.name for s in _SPECS if s.detect_match(rec)]
        assert matches == [expected_name], f"{expected_name} matched {matches}"


@pytest.mark.parametrize("expected_name,doc", list(ALL_DOCS.items()))
def test_mapping_produces_valid_event(expected_name, doc):
    rec = iter_records(doc)[0]
    spec = detect_spec(rec, _SPECS)
    evt = apply_mapping(rec, spec)
    assert evt["artifact_type"] == expected_name
    assert evt["timestamp"].endswith("Z")
    assert evt["message"]
    assert evt["raw"] is rec
    # network.src_ip, when present, must be a bare address (no :port / brackets)
    src = (evt.get("network") or {}).get("src_ip")
    if src:
        assert ":" not in src or src.count(":") > 1  # IPv4 has no colon; IPv6 has many
        assert "[" not in src


# ── End-to-end through the plugin (file → events) ───────────────────────────
def _run(tmp_path: Path, name: str, doc) -> list[dict]:
    f = tmp_path / f"{name}.json"
    f.write_text(json.dumps(doc))
    assert CloudAuditPlugin.can_handle(f, "application/json"), f"can_handle False for {name}"
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=f, source_minio_url="")
    plugin = CloudAuditPlugin(ctx)
    return list(plugin.parse())


@pytest.mark.parametrize("expected_name,doc", list(ALL_DOCS.items()))
def test_plugin_end_to_end(tmp_path, expected_name, doc):
    events = _run(tmp_path, expected_name, doc)
    assert len(events) == 1
    e = events[0]
    assert e["artifact_type"] == expected_name
    assert e["fo_id"]
    assert e["message"]


def test_plugin_ignores_unknown_json(tmp_path):
    f = tmp_path / "random.json"
    f.write_text(json.dumps({"foo": "bar", "baz": 1}))
    assert CloudAuditPlugin.can_handle(f, "application/json") is False


def test_jsonl_multiple_records(tmp_path):
    f = tmp_path / "trail.jsonl"
    rec = CLOUDTRAIL["Records"][0]
    f.write_text("\n".join(json.dumps(rec) for _ in range(3)))
    assert CloudAuditPlugin.can_handle(f, "application/x-ndjson")
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=f, source_minio_url="")
    events = list(CloudAuditPlugin(ctx).parse())
    assert len(events) == 3
    assert all(e["artifact_type"] == "aws_cloudtrail" for e in events)
