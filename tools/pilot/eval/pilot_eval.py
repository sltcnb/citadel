#!/usr/bin/env python3
"""Run the Pilot autopilot against scored scenarios and print a scorecard.

    # score a recorded run without any live services (what CI does)
    python3 tools/pilot/eval/pilot_eval.py --replay runs/2026-07-29.json

    # seed a throwaway case and drive the live agent, then score it
    python3 tools/pilot/eval/pilot_eval.py \
        --api http://localhost:8000/api/v1 --token "$TOKEN" \
        --es http://localhost:9200 --save runs/2026-07-29.json

    # list what would run
    python3 tools/pilot/eval/pilot_eval.py --list

Why a replay mode: driving the agent needs an LLM, which costs money, is
nondeterministic, and cannot run in CI. So a live run can be SAVED and later
re-scored offline. That splits the two questions cleanly — "is the agent good?"
needs the LLM; "did I break the scorer?" does not, and is what CI checks.

Exit code is non-zero when any scenario fails its gates, so this can gate a
release once a baseline is agreed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import scoring  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install pyyaml\n")
    raise SystemExit(2) from None

SCENARIO_DIR = HERE / "scenarios"


# ── scenarios ────────────────────────────────────────────────────────────────


def load_scenarios(only: list[str] | None = None) -> list[dict]:
    out = []
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        if not isinstance(doc, dict) or not doc.get("id"):
            raise SystemExit(f"{path.name}: missing 'id'")
        for required in ("scenario", "rubric", "seed"):
            if required not in doc:
                raise SystemExit(f"{path.name}: missing {required!r}")
        doc["_file"] = path.name
        doc["rubric"].setdefault("id", doc["id"])
        if only and doc["id"] not in only:
            continue
        out.append(doc)
    return out


def corpus_ids(scenario: dict) -> set[str]:
    """Every fo_id the scenario seeds — the ground truth for citation grounding."""
    ids = set()
    for entry in scenario.get("seed") or []:
        fid = (entry.get("doc") or {}).get("fo_id")
        if fid:
            ids.add(str(fid))
    return ids


def key_evidence_ids(scenario: dict) -> set[str]:
    return {
        str((e.get("doc") or {}).get("fo_id"))
        for e in (scenario.get("seed") or [])
        if e.get("key") and (e.get("doc") or {}).get("fo_id")
    }


def validate(scenarios: list[dict]) -> list[str]:
    """Structural problems that would make a score meaningless."""
    problems = []
    for s in scenarios:
        declared = {str(k) for k in (s["rubric"].get("key_evidence") or [])}
        marked = key_evidence_ids(s)
        if declared != marked:
            problems.append(
                f"{s['_file']}: rubric.key_evidence {sorted(declared)} does not match "
                f"the seed docs marked `key: true` {sorted(marked)} — one of them is stale"
            )
        seen = set()
        for e in s.get("seed") or []:
            fid = (e.get("doc") or {}).get("fo_id")
            if not fid:
                problems.append(f"{s['_file']}: a seed doc has no fo_id (needed to score)")
            elif fid in seen:
                problems.append(f"{s['_file']}: duplicate seed fo_id {fid!r}")
            else:
                seen.add(fid)
        for e in s.get("seed") or []:
            if not e.get("artifact_type"):
                problems.append(f"{s['_file']}: a seed entry has no artifact_type")
    return problems


# ── HTTP ─────────────────────────────────────────────────────────────────────


def _http(url: str, method: str = "GET", body=None, token: str | None = None, timeout=60):
    req = urllib.request.Request(
        url, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        raise SystemExit(f"{method} {url} → HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach {url}: {exc}") from exc


# ── seeding ──────────────────────────────────────────────────────────────────


def seed_case(es: str, case_id: str, scenario: dict) -> None:
    """Index the scenario's documents into the case's per-artifact indices.

    Straight to Elasticsearch rather than through ingest: the point is to fix the
    evidence exactly, so a scenario measures the AGENT and not a parser.
    """
    template = HERE.parents[2] / "elasticsearch" / "index_templates" / "fo-cases-template.json"
    if template.exists():
        _http(f"{es.rstrip('/')}/_index_template/fo-cases-template", "PUT",
              json.loads(template.read_text()))
    for entry in scenario["seed"]:
        atype = entry["artifact_type"]
        doc = dict(entry["doc"])
        doc.setdefault("artifact_type", atype)
        doc.setdefault("case_id", case_id)
        fid = doc["fo_id"]
        _http(f"{es.rstrip('/')}/fo-case-{case_id}-{atype}/_doc/{fid}?refresh=true", "PUT", doc)


def drop_case_indices(es: str, case_id: str) -> None:
    try:
        _http(f"{es.rstrip('/')}/fo-case-{case_id}-*", "DELETE")
    except SystemExit:
        pass  # nothing to delete


# ── driving the agent ────────────────────────────────────────────────────────


def run_agent(api: str, token: str, case_id: str, scenario: dict,
              poll: float = 3.0, limit: int = 1800) -> dict:
    """Start a background agent run, wait for it, return the persisted run doc."""
    rubric = scenario["rubric"]
    started = _http(
        f"{api.rstrip('/')}/cases/{case_id}/ai/agent/start", "POST",
        {"circumstance": scenario["scenario"],
         "max_steps": int(rubric.get("max_steps") or 20)},
        token=token,
    )
    run_id = started.get("run_id") or started.get("id") or ""
    deadline = time.time() + limit
    while time.time() < deadline:
        active = _http(f"{api.rstrip('/')}/cases/{case_id}/ai/agent/active", token=token)
        state = (active or {}).get("status") or ""
        if state in ("done", "error", "cancelled", ""):
            break
        time.sleep(poll)
    else:
        _http(f"{api.rstrip('/')}/cases/{case_id}/ai/agent/cancel/{run_id}", "POST", token=token)
        raise SystemExit(f"agent run {run_id} exceeded {limit}s")

    results = _http(f"{api.rstrip('/')}/cases/{case_id}/ai/results", token=token)
    runs = results.get("agent_runs") or []
    if not runs:
        raise SystemExit("agent produced no run document")
    return runs[0]  # newest first


# ── in-process mode (inside the API container) ──────────────────────────────


def inprocess_run(case_id: str, scenario: dict, max_steps_cap: int | None = None) -> dict:
    """Seed, run the agent loop in this process, clean up, return the run doc.

    For running inside the API container, where Elasticsearch, Redis and the LLM
    config are reachable without a session token. Side effects a real run has
    beyond its own case are stubbed: module launches, findings persistence and
    the cross-case memory. Import pilot from --pilot-path to compare two
    harness versions against identical data.
    """
    from services.elasticsearch import _request as es

    from pilot import service

    def drop() -> None:
        try:
            for row in es("GET", f"/_cat/indices/fo-case-{case_id}-*?format=json", None) or []:
                es("DELETE", f"/{row['index']}", None)
        except Exception:
            pass
        r = service._redis()
        for k in r.scan_iter(f"case:{case_id}:*"):
            r.delete(k)

    drop()
    for entry in scenario["seed"]:
        doc = dict(entry["doc"])
        doc.setdefault("artifact_type", entry["artifact_type"])
        doc.setdefault("case_id", case_id)
        es("PUT", f"/fo-case-{case_id}-{entry['artifact_type']}/_doc/{doc['fo_id']}?refresh=true", doc)

    service._autolaunch_modules = lambda cid: ""
    # The client-facing report is a separate, slow LLM call that also persists
    # a report document — not what the eval measures.
    service._auto_write_report_from_run = lambda *a, **k: None
    stub = lambda cid, step: {"query_status": "ok", "note": "(eval) not executed"}  # noqa: E731
    for name in ("save_finding", "launch_module"):
        if name in service.AGENT_TOOLS:
            service.AGENT_TOOLS[name] = stub
    try:
        from services import pilot_memory

        pilot_memory.remember = lambda *a, **k: None
    except Exception:
        pass

    cfg = service._get_config(service._redis())
    steps = int(scenario["rubric"].get("max_steps") or 20)
    if max_steps_cap:
        steps = min(steps, max_steps_cap)
    run = {}
    try:
        for ev in service._agent_run(case_id, scenario["scenario"], steps, cfg, None):
            if ev.get("type") == "done":
                run = ev.get("run") or {}
    finally:
        drop()
    return run


# ── before / after ──────────────────────────────────────────────────────────

_COMPARE_COLS = ("verdict", "attribution", "required_content", "unjustified_refuted",
                 "malicious_not_refuted", "exact_iocs", "calibration", "duplicates")


def compare(scenarios: list[dict], before: str, after: str) -> int:
    """Per-scenario metric table for two saved runs files, plus totals."""
    by_id = {s["id"]: s for s in scenarios}

    def load(path: str) -> dict:
        out = {}
        for entry in json.loads(Path(path).read_text()).get("runs", []):
            s = by_id.get(entry["scenario"])
            if s:
                out[s["id"]] = (entry["run"], scoring.score(entry["run"], s["rubric"], corpus_ids(s)))
        return out

    b, a = load(before), load(after)
    mark = lambda m: "-" if m is None else ("✓" if m.passed else "✗")  # noqa: E731
    head = f"{'scenario':24} {'side':6} " + " ".join(f"{c[:10]:>10}" for c in _COMPARE_COLS) + \
        f" {'steps':>5} {'conf':>4} {'unjust.':>7} pass"
    print(head)
    totals = {"before": [0, 0, 0, 0, 0], "after": [0, 0, 0, 0, 0]}
    for sid in [s["id"] for s in scenarios if s["id"] in b or s["id"] in a]:
        for side, data in (("before", b), ("after", a)):
            if sid not in data:
                continue
            run, card = data[sid]
            un = len([h for h in (run.get("final") or {}).get("hypotheses") or []
                      if isinstance(h, dict) and h.get("status") == "refuted"
                      and not any(f in json.dumps(h.get("against_evidence") or []) for f in corpus_ids(by_id[sid]))])
            steps = int(run.get("step_count") or 0)
            dups = sum(1 for st in run.get("steps") or [] if st.get("cached_from_step"))
            t = totals[side]
            t[0] += card.passed
            t[1] += bool(card.get("verdict") and card.get("verdict").passed)
            t[2] += un
            t[3] += dups
            t[4] += steps
            print(f"{sid[:24]:24} {side:6} " + " ".join(f"{mark(card.get(c)):>10}" for c in _COMPARE_COLS)
                  + f" {steps:>5} {str((run.get('final') or {}).get('confidence', '-')):>4} {un:>7} "
                  + ("PASS" if card.passed else "fail"))
    for side, t in totals.items():
        print(f"TOTAL {side:6}: {t[0]} passed, {t[1]} correct verdicts, {t[2]} unjustified refuted, "
              f"{t[3]} duplicate calls, {t[4]} steps")
    return 0


# ── reporting ────────────────────────────────────────────────────────────────


def report(cards: list[scoring.Scorecard], as_json: bool) -> int:
    if as_json:
        print(json.dumps({
            "scenarios": len(cards),
            "passed": sum(1 for c in cards if c.passed),
            "mean_composite": round(
                sum(c.composite for c in cards) / len(cards), 4) if cards else 0.0,
            "cards": [c.as_dict() for c in cards],
        }, indent=2))
    else:
        for c in cards:
            print(c)
            print()
        passed = sum(1 for c in cards if c.passed)
        mean = sum(c.composite for c in cards) / len(cards) if cards else 0.0
        print(f"Autopilot eval: {passed}/{len(cards)} scenario(s) passed, "
              f"mean composite {mean:.2f}")
    return 0 if all(c.passed for c in cards) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", help="API base, e.g. http://localhost:8000/api/v1")
    ap.add_argument("--token", default="", help="bearer token for the API")
    ap.add_argument("--es", help="Elasticsearch base, e.g. http://localhost:9200")
    ap.add_argument("--case-id", default="pilot-eval", help="case id to seed (destructive)")
    ap.add_argument("--only", action="append", help="scenario id (repeatable)")
    ap.add_argument("--replay", help="score a saved runs file instead of driving the agent")
    ap.add_argument("--save", help="write the live runs to this file for later replay")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    ap.add_argument("--check", action="store_true", help="validate scenarios and exit")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--inprocess", action="store_true",
                    help="run inside the API container: seed + drive the agent in this process")
    ap.add_argument("--pilot-path", help="import the pilot package from here (compare versions)")
    ap.add_argument("--max-steps-cap", type=int, help="cap every scenario's step budget")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"),
                    help="score two saved runs files side by side")
    args = ap.parse_args(argv)

    scenarios = load_scenarios(args.only)
    if not scenarios:
        raise SystemExit("no scenarios matched")

    problems = validate(scenarios)
    if args.check or problems:
        for p in problems:
            print(f"[INVALID] {p}", file=sys.stderr)
        if args.check:
            print(f"{len(scenarios)} scenario(s), {len(problems)} problem(s).")
        if problems:
            return 1
        return 0

    if args.list:
        for s in scenarios:
            r = s["rubric"]
            print(f"{s['id']:24} verdict={r.get('incident_confirmed','-'):13} "
                  f"key_evidence={len(r.get('key_evidence') or [])} "
                  f"budget={r.get('max_steps','-')}  {s['_file']}")
        return 0

    if args.compare:
        return compare(scenarios, *args.compare)

    if args.replay:
        saved = json.loads(Path(args.replay).read_text())
        by_id = {s["id"]: s for s in scenarios}
        cards = []
        for entry in saved.get("runs", []):
            s = by_id.get(entry["scenario"])
            if not s:
                print(f"(skipping {entry['scenario']} — no such scenario)", file=sys.stderr)
                continue
            cards.append(scoring.score(entry["run"], s["rubric"], corpus_ids(s)))
        if not cards:
            raise SystemExit("replay file scored nothing")
        return report(cards, args.json)

    if args.inprocess:
        if args.pilot_path:
            sys.path.insert(0, args.pilot_path)
        if Path("/app").is_dir():
            sys.path.insert(1, "/app")  # the API app: config, services, redis_keys
        cards, saved_runs = [], []
        for s in scenarios:
            case_id = f"{args.case_id}-{s['id']}".lower().replace("_", "-")[:60]
            print(f"→ {s['id']}: in-process run on case {case_id}", file=sys.stderr)
            started = time.time()
            run = inprocess_run(case_id, s, args.max_steps_cap)
            print(f"  done in {time.time() - started:.0f}s, {run.get('step_count')} step(s), "
                  f"stopped_reason={run.get('stopped_reason')}", file=sys.stderr)
            saved_runs.append({"scenario": s["id"], "run": run})
            cards.append(scoring.score(run, s["rubric"], corpus_ids(s)))
            if args.save:  # after every scenario: a long run must survive an interruption
                Path(args.save).write_text(json.dumps({"runs": saved_runs}, default=str) + "\n")
        return report(cards, args.json)

    if not (args.api and args.es):
        raise SystemExit("--api and --es are required for a live run (or use --replay)")

    cards, saved_runs = [], []
    for s in scenarios:
        case_id = f"{args.case_id}-{s['id']}"[:60]
        print(f"→ {s['id']}: seeding {len(s['seed'])} doc(s) into case {case_id}",
              file=sys.stderr)
        drop_case_indices(args.es, case_id)
        seed_case(args.es, case_id, s)
        print(f"→ {s['id']}: running agent (budget {s['rubric'].get('max_steps')})",
              file=sys.stderr)
        run = run_agent(args.api, args.token, case_id, s)
        saved_runs.append({"scenario": s["id"], "run": run})
        cards.append(scoring.score(run, s["rubric"], corpus_ids(s)))

    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        Path(args.save).write_text(json.dumps({"runs": saved_runs}, indent=2) + "\n")
        print(f"saved {len(saved_runs)} run(s) to {args.save}", file=sys.stderr)
    return report(cards, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
