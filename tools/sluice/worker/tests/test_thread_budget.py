"""Parser thread pools must be sized to the container's CPU quota, not the host's.

``os.cpu_count()`` reports the HOST's cores and ignores the cgroup quota, so a
``cpus: 4`` container on a 16-core host still reports 16. Rust/Go tools size
their worker pools from that number: Hayabusa (rayon) spawns 16 threads to share
4 cores' worth of quota, the scheduler throttles the whole cgroup every period,
and the run takes longer than a correctly-sized one while looking CPU-starved.

These tests pin the budget arithmetic, the override, and — the mistake this
caught during development — that the fallback concurrency here matches the
default the worker is actually started with in docker-compose.yml. If those two
drift, the budget is computed against a slot count that does not exist.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_WORKER_ROOT = Path(__file__).resolve().parents[1]
if str(_WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKER_ROOT))

import resource_limits as rl  # noqa: E402

_COMPOSE = _WORKER_ROOT.parents[2] / "docker-compose.yml"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("PARSER_THREADS", "MODULE_CONCURRENCY"):
        monkeypatch.delenv(var, raising=False)


def test_explicit_override_wins(monkeypatch):
    monkeypatch.setenv("PARSER_THREADS", "7")
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: 2.0)
    assert rl.parser_thread_budget() == 7


@pytest.mark.parametrize(
    "quota,concurrency,expected",
    [
        (4.0, 1, 4),   # whole quota to one task
        (4.0, 2, 2),   # split across two slots
        (4.0, 4, 1),
        (1.0, 2, 1),   # never below 1
        (0.5, 1, 1),   # sub-core quota still yields a usable pool
        (16.0, 1, 16),
    ],
)
def test_quota_is_split_across_worker_slots(monkeypatch, quota, concurrency, expected):
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: quota)
    assert rl.parser_thread_budget(concurrency=concurrency) == expected


def test_falls_back_to_host_cores_when_unconstrained(monkeypatch):
    """Outside a cgroup (bare metal, dev laptop) there is no quota to read."""
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: None)
    monkeypatch.setattr(rl.os, "cpu_count", lambda: 8)
    assert rl.parser_thread_budget(concurrency=2) == 4


def test_bad_override_is_ignored(monkeypatch):
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: 4.0)
    for bad in ("", "  ", "0", "-3", "many"):
        monkeypatch.setenv("PARSER_THREADS", bad)
        assert rl.parser_thread_budget(concurrency=1) == 4, f"{bad!r} should not be honoured"


def test_env_caps_every_known_pool(monkeypatch):
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: 4.0)
    env = rl.thread_capped_env({"PATH": "/bin"})
    for var in ("RAYON_NUM_THREADS", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        assert env[var] == "4", f"{var} not capped"
    assert env["PATH"] == "/bin", "the base environment must be preserved"


def test_env_never_clobbers_an_explicit_value(monkeypatch):
    """An operator who pinned RAYON_NUM_THREADS keeps their value."""
    monkeypatch.setattr(rl, "cgroup_cpu_quota", lambda: 8.0)
    env = rl.thread_capped_env({"RAYON_NUM_THREADS": "1"})
    assert env["RAYON_NUM_THREADS"] == "1"


def test_cgroup_quota_reads_v2_and_v1(monkeypatch, tmp_path):
    """'max' in cgroup v2 means unlimited, not a parse error."""
    calls = {}

    def fake_open(path, *a, **k):
        calls["path"] = path
        if path in calls.get("missing", ()):
            raise OSError("no such file")
        return type("F", (), {"read": lambda self: calls["content"],
                              "__enter__": lambda self: self,
                              "__exit__": lambda *_: False})()

    monkeypatch.setattr("builtins.open", fake_open)
    calls["content"] = "400000 100000"
    assert rl.cgroup_cpu_quota() == 4.0
    calls["content"] = "max 100000"
    assert rl.cgroup_cpu_quota() is None


def test_compose_default_matches_code_fallback():
    """The regression this test exists for: resource_limits fell back to a
    concurrency of 2 while docker-compose started the worker with 1, so every
    parser was given half the threads it could have used."""
    compose = _COMPOSE.read_text()
    m = re.search(r"--concurrency=\$\{MODULE_CONCURRENCY:-(\d+)\}", compose)
    assert m, "MODULE_CONCURRENCY default not found in docker-compose.yml"
    compose_default = int(m.group(1))

    src = (_WORKER_ROOT / "resource_limits.py").read_text()
    m = re.search(r'os\.getenv\("MODULE_CONCURRENCY",\s*"(\d+)"\)', src)
    assert m, "MODULE_CONCURRENCY fallback not found in resource_limits.py"
    code_default = int(m.group(1))

    assert compose_default == code_default, (
        f"docker-compose starts the module worker with concurrency "
        f"{compose_default} but resource_limits assumes {code_default}; the "
        f"thread budget would be computed against the wrong slot count"
    )


def test_hayabusa_runs_with_the_capped_env():
    """The budget is worthless if the subprocess does not receive it."""
    src = (_WORKER_ROOT / "tasks" / "module_task.py").read_text()
    hayabusa = src[src.index("def _run_hayabusa") : src.index("def _parse_hayabusa")]
    assert "thread_capped_env" in hayabusa, "hayabusa must run with the capped environment"
    assert re.search(r"env=_env", hayabusa), "the env must be passed to subprocess.run"


# ── Standalone runner (scripts/run_tests.sh invokes `python3 <file>`) ─────────
def _main() -> int:
    failed = 0
    checks: list[tuple[str, object]] = [
        ("compose_default_matches_code_fallback", test_compose_default_matches_code_fallback),
        ("hayabusa_runs_with_the_capped_env", test_hayabusa_runs_with_the_capped_env),
    ]
    # Arithmetic checks, done directly (no fixtures needed).
    import os

    os.environ.pop("PARSER_THREADS", None)
    os.environ.pop("MODULE_CONCURRENCY", None)
    real_quota = rl.cgroup_cpu_quota
    try:
        for quota, conc, exp in ((4.0, 1, 4), (4.0, 2, 2), (4.0, 4, 1), (1.0, 2, 1), (16.0, 1, 16)):
            rl.cgroup_cpu_quota = lambda q=quota: q
            got = rl.parser_thread_budget(concurrency=conc)
            if got != exp:
                print(f"FAIL quota={quota} conc={conc}: expected {exp}, got {got}")
                failed += 1
        rl.cgroup_cpu_quota = lambda: 4.0
        env = rl.thread_capped_env({"PATH": "/bin"})
        if env.get("RAYON_NUM_THREADS") != "4":
            print(f"FAIL RAYON_NUM_THREADS not capped: {env.get('RAYON_NUM_THREADS')}")
            failed += 1
        if rl.thread_capped_env({"RAYON_NUM_THREADS": "1"})["RAYON_NUM_THREADS"] != "1":
            print("FAIL explicit RAYON_NUM_THREADS was clobbered")
            failed += 1
        os.environ["PARSER_THREADS"] = "7"
        if rl.parser_thread_budget() != 7:
            print("FAIL PARSER_THREADS override not honoured")
            failed += 1
        os.environ.pop("PARSER_THREADS")
    finally:
        rl.cgroup_cpu_quota = real_quota

    total = len(checks) + 9
    for name, fn in checks:
        try:
            fn()  # type: ignore[operator]
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            failed += 1
    if failed:
        print(f"{total - failed}/{total} passed, {failed} failed")
        return 1
    print(f"{total}/{total} passed (thread budget = cgroup quota / MODULE_CONCURRENCY)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
