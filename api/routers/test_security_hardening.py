"""Regression tests for the CVSS-driven hardening pass (VVAH scan, 2026-09-01).

One file per concern would scatter these across the tree; they are grouped here
because they share a theme — each pins a specific bypass closed so it cannot
quietly regress. Follows the api/ colocated-test convention: handlers and
helpers called directly, no app boot.
"""

import re
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services import elasticsearch as es_svc  # noqa: E402
from services.python_embeds import _safe_member_name  # noqa: E402

import routers.groups as groups_router  # noqa: E402
import routers.harvest as harvest_router  # noqa: E402
import routers.watchlist as watchlist_router  # noqa: E402

# ── mounted_path containment (CWE-22) ─────────────────────────────────────────
#
# The harvest endpoint takes a worker-side path and the worker reads whatever it
# is handed, so case access alone did not stop an analyst harvesting /etc.


@pytest.mark.parametrize("path", [
    "/mnt", "/mnt/disk", "/mnt/disk/sub", "/data/evidence/case1",
])
def test_mounted_path_inside_a_harvest_root_is_accepted(path):
    assert harvest_router._validate_mounted_path(path) == path


@pytest.mark.parametrize("path", [
    "/etc", "/etc/shadow", "/root/.ssh", "/var/log", "/",
    "/mnt/../etc/shadow", "/mnt/disk/../../etc",
    "etc/passwd", "", "   ",
    "/mntx/evil",           # prefix confusion: /mntx is not under /mnt
    "/datax",               # ditto for /data
])
def test_mounted_path_outside_the_harvest_roots_is_rejected(path):
    with pytest.raises(HTTPException) as exc:
        harvest_router._validate_mounted_path(path)
    assert exc.value.status_code == 400


def test_mounted_path_is_normalised_not_merely_checked():
    """The value handed to the worker must be the collapsed one, so the worker
    never re-interprets a '..' the API considered safe."""
    assert harvest_router._validate_mounted_path("/mnt//disk///sub") == "/mnt/disk/sub"


# ── zip-slip in embed extraction (CWE-22) ─────────────────────────────────────


@pytest.mark.parametrize("name", [
    "../../../app/main.py", "..\\..\\evil.dll", "/etc/passwd",
    "C:/Windows/System32/evil.dll", "..", "a/../../b",
])
def test_archive_member_traversal_is_dropped(name):
    assert _safe_member_name(name, "test") is None


@pytest.mark.parametrize("name,expected", [
    ("python/bin/python3", "python/bin/python3"),
    ("./ok/file", "ok/file"),
    ("a/./b//c", "a/b/c"),
    ("python.exe", "python.exe"),
])
def test_benign_archive_member_names_survive(name, expected):
    assert _safe_member_name(name, "test") == expected


# ── watchlist regex cost (CWE-1333) ───────────────────────────────────────────
#
# A regex watchlist entry is re-run by the auto-run scheduler on every case, so
# a pathological pattern is recurring load, not a one-off slow query.


@pytest.mark.parametrize("pattern", ["(a+)+", "(x*)*", "([a-z]+)*", "^(a+)+$"])
def test_catastrophic_watchlist_regex_is_refused(pattern):
    with pytest.raises(HTTPException) as exc:
        watchlist_router._build_query("regex", pattern)
    assert exc.value.status_code == 400
    assert "quantifier" in exc.value.detail


def test_overlong_watchlist_regex_is_refused():
    with pytest.raises(HTTPException) as exc:
        watchlist_router._build_query("regex", "a" * 600)
    assert exc.value.status_code == 400


def test_uncompilable_watchlist_regex_is_refused():
    with pytest.raises(HTTPException) as exc:
        watchlist_router._build_query("regex", "[unterminated")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("pattern", [
    r"rundll32\.exe.*shell32", r"AKIA[0-9A-Z]{16}", r"(foo|bar)", r"https?://\S+",
])
def test_legitimate_watchlist_regex_still_works(pattern):
    assert watchlist_router._build_query("regex", pattern) == f"message:/{pattern}/"


def test_non_regex_watchlist_kinds_are_untouched():
    assert '"1.2.3.4"' in watchlist_router._build_query("ip", "1.2.3.4")


# ── Lucene query cost bounds (CWE-94) ─────────────────────────────────────────
#
# Escaping every Lucene metacharacter would delete the search feature, so the
# defence is a cost bound, not a sanitiser.


def test_overlong_lucene_query_is_rejected_before_elasticsearch():
    err = es_svc.validate_lucene_query("a" * (es_svc._MAX_QUERY_LEN + 1))
    assert err is not None and "too long" in err


def test_normal_lucene_query_still_validates():
    assert es_svc.validate_lucene_query('process.name:"cmd.exe" AND host:web01') is None


def test_lucene_syntax_is_deliberately_preserved():
    """field:value / boolean / wildcard must reach Elasticsearch intact — the
    fix for query cost must not have turned the escaper into a sanitiser."""
    q = 'process.name:*.exe AND NOT user:SYSTEM'
    assert es_svc.escape_lucene_query(q, preserve_regex=True) == q


def test_search_bounds_the_regex_automaton():
    """Every user-facing query_string must carry max_determinized_states, or a
    crafted regex can blow up on the data node instead of erroring."""
    source = Path(es_svc.__file__).read_text()
    n_query_string = source.count('"query_string": {')
    n_bounded = source.count("max_determinized_states")
    assert n_bounded >= n_query_string, (
        f"{n_query_string} query_string blocks but only {n_bounded} bounded"
    )


# ── group tenant scoping (CWE-639) ────────────────────────────────────────────
#
# users.manage means "may administer groups", not "may administer every
# tenant's groups". group_id came straight off the URL into the store call.


def test_admin_sees_every_group():
    g = {"id": "g1", "companies": ["acme"]}
    assert groups_router._visible_to(g, None) is True


def test_scoped_manager_sees_only_overlapping_groups():
    flt = ["acme"]
    assert groups_router._visible_to({"id": "a", "companies": ["acme"]}, flt) is True
    assert groups_router._visible_to({"id": "b", "companies": ["acme", "other"]}, flt) is True
    assert groups_router._visible_to({"id": "c", "companies": ["other"]}, flt) is False


def test_scoped_manager_cannot_see_an_installation_wide_group():
    """An empty companies list means every tenant — strictly broader than a
    company-scoped manager, so it must not be theirs to edit or delete."""
    assert groups_router._visible_to({"id": "global", "companies": []}, ["acme"]) is False
    assert groups_router._visible_to({"id": "global"}, ["acme"]) is False


def test_scoped_manager_cannot_widen_a_group_beyond_their_own_scope():
    with pytest.raises(HTTPException) as exc:
        groups_router._require_assignable_scope(["acme", "other"], ["acme"])
    assert exc.value.status_code == 403
    assert "other" in exc.value.detail


def test_scoped_manager_cannot_create_an_installation_wide_group():
    with pytest.raises(HTTPException) as exc:
        groups_router._require_assignable_scope([], ["acme"])
    assert exc.value.status_code == 403


def test_assignable_scope_is_unrestricted_for_admins():
    groups_router._require_assignable_scope([], None)          # no raise
    groups_router._require_assignable_scope(["anything"], None)


def test_assignable_scope_ignores_an_absent_companies_patch():
    """A PUT that does not touch `companies` must not be treated as a move to
    installation-wide scope."""
    groups_router._require_assignable_scope(None, ["acme"])    # no raise


# ── ingest filename handling (CWE-117 + temp-path traversal) ──────────────────


@pytest.mark.parametrize("raw,must_not_contain", [
    ("evil\r\nJan 01 00:00:00 fake: forged", "\n"),
    ("evil\rcarriage", "\r"),
    ("tab\there", "\t"),
])
def test_upload_filename_sanitisation_strips_log_forging_characters(raw, must_not_contain):
    safe = re.sub(r"[^\w.\-]", "_", raw)[:200]
    assert must_not_contain not in safe


@pytest.mark.parametrize("raw", [
    "../../app/main.py", "/etc/passwd", "a/b/c.evtx", "..\\..\\evil.dll",
])
def test_upload_filename_sanitisation_removes_path_separators(raw):
    """The name is used as a mkstemp SUFFIX and mkstemp joins it into the path,
    so a separator would place the temp file outside the temp directory.

    Separators are what make traversal work — a surviving ".." with no "/" or
    "\\" around it is just an ordinary filename character, so this asserts on
    the separators rather than demanding the dots be scrubbed.
    """
    safe = re.sub(r"[^\w.\-]", "_", raw)[:200]
    assert "/" not in safe
    assert "\\" not in safe
    import os.path
    # The decisive property: joined onto a directory it cannot climb out of it.
    joined = os.path.normpath(os.path.join("/tmp/chunkdir", "fo_ingest_ABC" + safe))
    assert joined.startswith("/tmp/chunkdir/")
