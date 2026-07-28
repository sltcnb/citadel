#!/usr/bin/env python3
"""Ask Elasticsearch whether every native rule query actually parses.

``sigil_validate.py`` is a static linter — it runs in CI without a cluster and
catches what can be reasoned about from the text. It cannot catch everything:
Lucene's ``query_string`` grammar rejects constructs that look perfectly
reasonable, and a rejected query is a rule that can NEVER fire.

Real examples this found in the shipped corpus, all invisible to the static
linter and all silently reported as "0 hits" at runtime:

    http.request_path.ci:*../*        unescaped '/' → read as a regex literal
    syslog.raw_message:*sts:AssumeRole*   unescaped ':' → field separator
    message.ci:*[Reflection.Assembly]*    unescaped brackets → rejected
    message.ci:*" del "*                  a quote inside a wildcard → rejected
    message::*Assembly.Load*              a typo'd double colon → rejected

Run it against any reachable Elasticsearch (a throwaway container is fine — no
data is needed, ``_validate/query`` only parses):

    docker run -d --rm -p 9200:9200 -e discovery.type=single-node \
      -e xpack.security.enabled=false \
      docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    python3 tools/sigil/sigil_esvalidate.py --es http://localhost:9200

Exits non-zero if any query is rejected, so it can gate a release even though it
cannot run in the dependency-light CI job.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install pyyaml\n")
    raise SystemExit(2) from None

HERE = Path(__file__).resolve().parent
REPO = next((p for p in HERE.parents if (p / "elasticsearch").is_dir()), HERE.parents[1])
TEMPLATE = REPO / "elasticsearch" / "index_templates" / "fo-cases-template.json"
NON_RULE_FILES = {"brick.yaml", "capabilities.yaml"}
PROBE_INDEX = "fo-case-esvalidate-evtx"


def _req(es: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        es.rstrip("/") + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {}
    except urllib.error.URLError as exc:
        sys.stderr.write(f"cannot reach Elasticsearch at {es}: {exc}\n")
        raise SystemExit(2) from exc


def _install_template_and_probe(es: str) -> None:
    """Apply the real index template and create one index from it.

    Validation must run against the mappings the platform actually uses — the
    ``.ci`` subfields in particular — or a query referencing them would be judged
    against a dynamically-guessed mapping instead.
    """
    if TEMPLATE.exists():
        status, body = _req(es, "PUT", "/_index_template/fo-cases-template",
                            json.loads(TEMPLATE.read_text()))
        if status >= 300:
            sys.stderr.write(f"failed to install index template: {json.dumps(body)[:300]}\n")
            raise SystemExit(2)
    _req(es, "DELETE", f"/{PROBE_INDEX}")
    _req(es, "POST", f"/{PROBE_INDEX}/_doc?refresh=true",
         {"artifact_type": "evtx", "timestamp": "2026-01-01T00:00:00.000Z",
          "message": "probe"})


def _rules() -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for path in sorted(HERE.glob("**/*.yaml")):
        if path.name in NON_RULE_FILES:
            continue
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            sys.stderr.write(f"{path.name}: YAML parse failed: {exc}\n")
            raise SystemExit(1) from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            continue
        rel = path.relative_to(HERE).as_posix()
        for rule in doc["rules"]:
            if isinstance(rule, dict) and rule.get("query"):
                out.append((rel, str(rule.get("name", "?")), str(rule["query"])))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    ap.add_argument("--quiet", "-q", action="store_true", help="only print the summary")
    args = ap.parse_args(argv)

    _install_template_and_probe(args.es)
    rules = _rules()
    rejected: list[tuple[str, str, str, str]] = []

    for rel, name, query in rules:
        status, body = _req(
            args.es, "POST", f"/{PROBE_INDEX}/_validate/query?explain=true",
            {"query": {"query_string": {"query": query, "default_operator": "AND"}}},
        )
        if status >= 300:
            rejected.append((rel, name, query, json.dumps(body)[:200]))
            continue
        if not body.get("valid"):
            why = (body.get("explanations") or [{}])[0].get("error", "invalid")
            rejected.append((rel, name, query, str(why)[:200]))

    for rel, name, query, why in rejected:
        print(f"[REJECTED] {rel} :: {name}")
        print(f"    query: {query[:160]}")
        print(f"    why:   {why}")

    _req(args.es, "DELETE", f"/{PROBE_INDEX}")
    print(
        f"\nSigil ES validation: {len(rules)} native rule query(ies), "
        f"{len(rejected)} rejected."
    )
    if rejected:
        print("A rejected query can never match — the rule is silently dead.")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
