"""Unit tests for the CPU/memory/wall-clock sandbox around parser/module
execution (resource_limits.py). Runs real child processes (fork) so these
exercise the actual resource.setrlimit enforcement, not a mock."""

from __future__ import annotations

import time

import pytest
import resource_limits

# ── Happy path ────────────────────────────────────────────────────────────────


def test_normal_task_passes_through_result():
    def add(a, b):
        return a + b

    assert resource_limits.run_limited(add, 2, 3) == 5


def test_normal_task_with_kwargs():
    def greet(name, greeting="hello"):
        return f"{greeting} {name}"

    assert resource_limits.run_limited(greet, "case", greeting="hi") == "hi case"


def test_exception_in_task_reraised_as_runtime_error():
    def boom():
        raise ValueError("bad input")

    with pytest.raises(RuntimeError, match="bad input"):
        resource_limits.run_limited(boom)


# ── CPU-time limit (RLIMIT_CPU) ────────────────────────────────────────────────


def test_cpu_bomb_is_terminated_and_reported():
    def cpu_burn():
        x = 0
        for i in range(10**9):
            x += i
        return x

    with pytest.raises(resource_limits.ResourceLimitExceeded, match="RLIMIT_CPU|SIGXCPU|SIGKILL"):
        resource_limits.run_limited(cpu_burn, cpu_seconds=1, timeout=15)


# ── Memory limit (RLIMIT_AS) ───────────────────────────────────────────────────


def test_memory_bomb_is_terminated_and_reported():
    def mem_bomb():
        blocks = []
        for _ in range(10000):
            blocks.append(bytearray(50 * 1024 * 1024))  # 50 MB chunks
        return len(blocks)

    # RLIMIT_AS enforcement is platform-dependent (reliably kills the child on
    # Linux via SIGKILL/SIGSEGV or a Python-level MemoryError; some platforms
    # under-enforce it). Either way the wrapper must never let the bomb run
    # unbounded — it always ends in ResourceLimitExceeded, via the memory cap
    # or the wall-clock backstop.
    with pytest.raises(resource_limits.ResourceLimitExceeded):
        resource_limits.run_limited(
            mem_bomb, mem_bytes=200 * 1024 * 1024, cpu_seconds=30, timeout=15
        )


# ── Wall-clock timeout ──────────────────────────────────────────────────────────


def test_wall_clock_timeout_is_terminated_and_reported():
    def hang():
        time.sleep(30)
        return "done"

    with pytest.raises(resource_limits.ResourceLimitExceeded, match="wall-clock timeout"):
        resource_limits.run_limited(hang, cpu_seconds=60, timeout=1)


# ── preexec_limits / subprocess_run_limited ────────────────────────────────────


def test_preexec_limits_returns_callable():
    apply_fn = resource_limits.preexec_limits(cpu_seconds=5, mem_bytes=1024**3, nproc=8)
    assert callable(apply_fn)


def test_subprocess_run_limited_normal_command():
    proc = resource_limits.subprocess_run_limited(
        ["python3", "-c", "print('ok')"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_subprocess_run_limited_timeout():
    with pytest.raises(resource_limits.ResourceLimitExceeded, match="wall-clock timeout"):
        resource_limits.subprocess_run_limited(
            ["python3", "-c", "import time; time.sleep(10)"],
            timeout=1,
            capture_output=True,
            text=True,
        )


def test_subprocess_run_limited_cpu_bomb():
    with pytest.raises(resource_limits.ResourceLimitExceeded):
        resource_limits.subprocess_run_limited(
            ["python3", "-c", "x = 0\nwhile True:\n x += 1"],
            cpu_seconds=1,
            timeout=15,
            capture_output=True,
            text=True,
        )


# ── Config defaults are env-overridable ────────────────────────────────────────


def test_defaults_are_positive_and_sane():
    assert resource_limits.DEFAULT_CPU_SECONDS > 0
    assert resource_limits.DEFAULT_MEMORY_BYTES > 0
    assert resource_limits.DEFAULT_WALL_TIMEOUT_SEC > 0
    assert resource_limits.DEFAULT_NPROC > 0
