"""End-to-end pipeline integration test — Babel → Rosetta → Sigil.

Exercises the suite across THREE tool boundaries using only the shared
contracts, fully offline (no ES/Redis/MinIO):

    access.log  --Babel(parse)-->  ForensicEvent
                --Rosetta(normalize)-->  ECS v8 doc
                --Sigil(match)-->  detection

This is the "one integration pipeline" gate: it proves the contracts actually
compose, and catches field-shape drift between tools (e.g. a parser field the
canonicalizer drops). Standalone-runnable + pytest.
"""
import sys
import logging
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# Each tool is its own dir; the test orchestrates across them via contracts.
sys.path.insert(0, str(REPO / "tools"))                 # plugins package (Babel)
sys.path.insert(0, str(REPO / "tools" / "rosetta"))     # rosetta package
sys.path.insert(0, str(REPO / "tools" / "sigil"))   # sigil matcher

from babel.base_plugin import PluginContext            # noqa: E402
from babel.access_log.access_log_plugin import AccessLogPlugin  # noqa: E402
from rosetta.normalize import Normalizer, load_fieldmap  # noqa: E402
import sigil_match                                        # noqa: E402

FIXTURE = REPO / "tools" / "babel" / "tests" / "golden" / "fixtures" / "access.log"


def _babel_parse():
    ctx = PluginContext(case_id="e2e", job_id="e2e", source_file_path=FIXTURE,
                        source_minio_url=f"file://{FIXTURE}", config={},
                        logger=logging.getLogger("e2e"))
    p = AccessLogPlugin(ctx)
    p.setup()
    try:
        return list(p.parse())
    finally:
        p.teardown()


def _rosetta_normalize(events):
    norm = Normalizer(load_fieldmap(None), ecs_version="8.11")
    return [norm.normalize(e) for e in events]


def test_full_pipeline_babel_rosetta_sigil():
    # 1) Babel: parse the web access log into ForensicEvents.
    events = _babel_parse()
    assert events, "Babel produced no events"
    assert all(e["timestamp"].endswith("Z") for e in events), "non-Z timestamp from Babel"

    # 2) Rosetta: canonicalize to ECS. Contract checks across the boundary:
    docs = _rosetta_normalize(events)
    assert all(d["@timestamp"].endswith("Z") for d in docs), "Rosetta @timestamp not Z"
    assert all(d["ecs"]["version"] == "8.11" for d in docs)
    assert all("web" in (d.get("event", {}).get("category") or []) for d in docs)
    # The parser's structured http.*/network.* survived canonicalization (the
    # passthrough fix): this is the exact field-drift an e2e test must catch.
    assert any(d.get("http", {}).get("status_code") == 403 for d in docs), \
        "http.status_code dropped between Babel and Rosetta"
    assert all(d.get("network", {}).get("src_ip") for d in docs), "network.src_ip dropped"

    # 3) Sigil: match ES-style queries against the ECS docs → detections.
    admin_hits = [d for d in docs if sigil_match.query_matches("http.request_path:*admin*", d)]
    forbidden = [d for d in docs if sigil_match.query_matches("http.status_code:403", d)]
    assert admin_hits, "Sigil failed to match /admin path through the pipeline"
    assert forbidden, "Sigil failed to match status 403 through the pipeline"

    # negative control: a query that must NOT fire
    assert not any(sigil_match.query_matches("http.status_code:500", d) for d in docs)


def test_contract_shape_is_stable():
    """Every ECS doc carries the required canonical fields."""
    docs = _rosetta_normalize(_babel_parse())
    for d in docs:
        assert d["@timestamp"] and d["message"] and d["ecs"]["version"]
        assert "citadel" in d and "raw" in d["citadel"]  # raw retained for re-analysis


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name](); n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
