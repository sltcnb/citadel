"""The worker's time limits must stay ordered, or module runs fail unexplainably.

A Hayabusa run over a large EVTX corpus failed with a bare
``SoftTimeLimitExceeded()``: Celery's ``task_soft_time_limit`` was 3600s while the
per-parser wall budget was 7200s and hayabusa's own subprocess timeout was also
exactly 3600s. So a long run could only ever be killed by Celery — and because
that exception carries no message, the analyst saw nothing actionable.

These tests pin the ordering that makes that failure impossible:

    per-tool timeout  <  parser wall budget  <  soft task limit  <  hard task limit  <=  visibility

The defaults are read out of the source rather than by importing the modules,
because ``celery`` is not installed in the CI jobs that run this suite — an
import-guarded test here would skip everywhere and gate nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _no_pytest import pytest  # noqa: E402 — works under pytest AND standalone

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_CELERY_APP = _WORKER_ROOT / "celery_app.py"
_MODULE_TASK = _WORKER_ROOT / "tasks" / "module_task.py"


def _env_default(text: str, var: str) -> int:
    """The literal default in ``os.getenv("VAR", "N")``."""
    m = re.search(rf'os\.getenv\(\s*"{re.escape(var)}"\s*,\s*"(\d+)"\s*\)', text)
    assert m, f"no os.getenv default found for {var}"
    return int(m.group(1))


def _limits() -> dict[str, int]:
    celery_src = _CELERY_APP.read_text()
    task_src = _MODULE_TASK.read_text()
    return {
        "soft": _env_default(celery_src, "CELERY_SOFT_TIME_LIMIT"),
        "hard": _env_default(celery_src, "CELERY_TIME_LIMIT"),
        "parser": _env_default(
            (_WORKER_ROOT / "resource_limits.py").read_text(), "PARSER_WALL_TIMEOUT_SEC"
        ),
        "hayabusa": _env_default(task_src, "HAYABUSA_TIMEOUT_SEC"),
    }


@pytest.fixture(scope="module")
def limits() -> dict[str, int]:
    return _limits()


def test_soft_limit_exceeds_parser_wall_budget(limits):
    """The regression itself: a parser allowed 2 h under a 1 h task limit could
    never finish, and died without a usable error."""
    assert limits["soft"] > limits["parser"], (
        f"task_soft_time_limit default ({limits['soft']}s) must exceed "
        f"PARSER_WALL_TIMEOUT_SEC ({limits['parser']}s) — otherwise Celery kills "
        f"parsers the resource limiter is still allowing to run"
    )


def test_hard_limit_above_soft_limit(limits):
    assert limits["hard"] > limits["soft"], (
        f"CELERY_TIME_LIMIT ({limits['hard']}s) must exceed "
        f"CELERY_SOFT_TIME_LIMIT ({limits['soft']}s) so a task gets the chance to "
        f"record why it stopped before being SIGKILLed"
    )


def test_hayabusa_timeout_below_soft_limit(limits):
    """Hayabusa must lose the race to its OWN timeout, which explains itself."""
    assert limits["hayabusa"] < limits["soft"], (
        f"HAYABUSA_TIMEOUT_SEC ({limits['hayabusa']}s) must stay below the soft task "
        f"limit ({limits['soft']}s) so a slow run reports hayabusa's own error "
        f"instead of an anonymous SoftTimeLimitExceeded()"
    )


def test_visibility_timeout_tracks_hard_limit(limits):
    """A visibility timeout below the hard limit makes the broker redeliver a
    still-running task, so the same module executes twice."""
    src = _CELERY_APP.read_text()
    m = re.search(r'"visibility_timeout":\s*(.+?),\s*\n', src)
    assert m, "visibility_timeout not found in broker_transport_options"
    expr = m.group(1)
    if expr.strip().isdigit():
        assert int(expr) >= limits["hard"], (
            f"hard-coded visibility_timeout ({expr}) is below CELERY_TIME_LIMIT "
            f"({limits['hard']}s)"
        )
    else:
        # Derived from the same env var as the hard limit — cannot drift apart.
        assert "CELERY_TIME_LIMIT" in expr, (
            "visibility_timeout should derive from CELERY_TIME_LIMIT so the two "
            f"cannot diverge; got: {expr}"
        )


def test_startup_guard_exists(limits):
    """A misconfiguration must be reported at worker boot, not discovered by a
    failed two-hour module run."""
    src = _CELERY_APP.read_text()
    assert "_check_time_limits" in src
    for knob in ("PARSER_WALL_TIMEOUT_SEC", "task_soft_time_limit", "visibility_timeout"):
        assert knob in src, f"startup guard does not check {knob}"


def test_softtimelimit_failure_message_is_actionable():
    """``str(SoftTimeLimitExceeded())`` is empty, so the run must not record a
    blank error — it must name the limit that was hit and the knob to change."""
    src = _MODULE_TASK.read_text()
    assert "SoftTimeLimitExceeded" in src, "the empty-message case must be handled explicitly"
    assert "CELERY_SOFT_TIME_LIMIT" in src, "the message must name the knob to raise"
    assert "no message" in src, "other message-less exceptions must still get a class name"


def test_hayabusa_timeout_error_is_actionable():
    src = _MODULE_TASK.read_text()
    assert "HAYABUSA_TIMEOUT_SEC" in src, "the per-tool budget must be tunable"
    m = re.search(r"Hayabusa timed out after \{_HAYABUSA_TIMEOUT\}s\.(.*?)\"", src, re.S)
    assert m, "hayabusa timeout error should report the actual budget and next step"


# ── Standalone runner ────────────────────────────────────────────────────────
# scripts/run_tests.sh invokes each suite as `python3 <file>`, so the checks must
# also work without pytest installed.
def _main() -> int:
    lim = _limits()
    checks = [
        ("soft_limit_exceeds_parser_wall_budget", lambda: test_soft_limit_exceeds_parser_wall_budget(lim)),
        ("hard_limit_above_soft_limit", lambda: test_hard_limit_above_soft_limit(lim)),
        ("hayabusa_timeout_below_soft_limit", lambda: test_hayabusa_timeout_below_soft_limit(lim)),
        ("visibility_timeout_tracks_hard_limit", lambda: test_visibility_timeout_tracks_hard_limit(lim)),
        ("startup_guard_exists", lambda: test_startup_guard_exists(lim)),
        ("softtimelimit_failure_message_is_actionable", test_softtimelimit_failure_message_is_actionable),
        ("hayabusa_timeout_error_is_actionable", test_hayabusa_timeout_error_is_actionable),
    ]
    failed = 0
    for name, fn in checks:
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    total = len(checks)
    if failed:
        print(f"{total - failed}/{total} passed, {failed} failed")
        return 1
    print(
        f"{total}/{total} passed "
        f"(hayabusa {lim['hayabusa']}s < parser {lim['parser']}s "
        f"< soft {lim['soft']}s < hard {lim['hard']}s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
