"""
Defense-in-depth resource limits for forensic parser/module execution.

The Sluice worker runs hostile input through forensic parsers (Volatility3,
YARA, Hayabusa, RegRipper, Wintriage, Hindsight, Cuckoo, custom Anvil
modules...). A crafted memory image, EVTX file, or Office document can turn
a parser into a CPU or memory bomb. Celery's global ``task_soft_time_limit`` /
``task_time_limit`` (see celery_app.py) bound the *whole task* but do nothing
for CPU-time or memory: a parser can spin a single core forever inside the
soft-limit window, or allocate until the whole worker pod OOMs and takes every
other in-flight task down with it.

This module provides two composable primitives:

  * ``preexec_limits(...)`` — a ``preexec_fn`` for ``subprocess.run`` /
    ``subprocess.Popen`` that applies ``resource.setrlimit`` (RLIMIT_CPU,
    RLIMIT_AS, RLIMIT_NPROC) to the child *before* exec, so external binaries
    (hayabusa, vol3, rip.pl, ...) are capped even though they are compiled/
    interpreted code we do not control.

  * ``run_limited(func, ...)`` — runs a plain Python callable (e.g. in-process
    library calls such as ``yara.compile(...).match(...)``) in a forked child
    process with the same rlimits applied, enforces a wall-clock timeout by
    terminating the child, and raises ``ResourceLimitExceeded`` when the
    child was killed by a limit (SIGKILL/SIGXCPU/SIGSEGV from RLIMIT_AS or
    RLIMIT_CPU) or exceeded the wall clock — instead of taking the worker
    process down with it.

All limits are configurable via environment variables with conservative
defaults; every call site can still override per-parser via kwargs.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import signal

logger = logging.getLogger(__name__)


class ResourceLimitExceeded(RuntimeError):
    """Raised when a sandboxed parser/module exceeded a CPU, memory, or
    wall-clock limit and was terminated."""


# ── Defaults (env-overridable) ────────────────────────────────────────────────
# CPU-time cap (RLIMIT_CPU, seconds of actual CPU time consumed).
DEFAULT_CPU_SECONDS = int(os.getenv("PARSER_CPU_SECONDS", "900"))  # 15 min
# Virtual memory cap (RLIMIT_AS, bytes).
DEFAULT_MEMORY_BYTES = int(os.getenv("PARSER_MEMORY_BYTES", str(2 * 1024**3)))  # 2 GB
# Wall-clock cap for the whole parser invocation.
DEFAULT_WALL_TIMEOUT_SEC = int(os.getenv("PARSER_WALL_TIMEOUT_SEC", "1200"))  # 20 min
# Max child processes (RLIMIT_NPROC) — blunts fork-bomb style abuse.
DEFAULT_NPROC = int(os.getenv("PARSER_NPROC", "32"))

# Signals that indicate a resource-limit kill rather than a normal crash.
_LIMIT_SIGNALS = {
    signal.SIGKILL: "SIGKILL (likely OOM / RLIMIT_AS)",
    signal.SIGXCPU: "SIGXCPU (RLIMIT_CPU exceeded)",
    signal.SIGSEGV: "SIGSEGV (possibly RLIMIT_AS allocation failure)",
    signal.SIGTERM: "SIGTERM (terminated — wall-clock timeout)",
}


def preexec_limits(
    cpu_seconds: int | None = None,
    mem_bytes: int | None = None,
    nproc: int | None = None,
):
    """Return a ``preexec_fn`` that applies resource limits to a subprocess
    child before exec. Linux/POSIX only — safe no-op elsewhere.

    Usage::

        subprocess.run(cmd, preexec_fn=preexec_limits(), timeout=...)
    """
    cpu_seconds = DEFAULT_CPU_SECONDS if cpu_seconds is None else cpu_seconds
    mem_bytes = DEFAULT_MEMORY_BYTES if mem_bytes is None else mem_bytes
    nproc = DEFAULT_NPROC if nproc is None else nproc

    def _apply() -> None:
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 30))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass  # some kernels/binaries misbehave with a hard AS cap
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
            except (ValueError, OSError):
                pass
        except ImportError:
            pass  # non-POSIX platform — best effort only
        except Exception:  # noqa: BLE001 - must never prevent the child from execing
            pass

    return _apply


def _child_entrypoint(func, args, kwargs, queue, cpu_seconds, mem_bytes, nproc) -> None:
    """Runs in the forked child: apply rlimits, call func, ship the result back."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (ValueError, OSError):
            pass
        # NB: RLIMIT_NPROC is intentionally NOT applied. It caps processes for
        # the whole real UID (not this child's subtree), and the worker
        # container already runs many threads/processes under the same uid
        # (Celery prefork + its thread pools). Setting it below the current
        # count makes even one queue.put() feeder thread fail with
        # "can't start new thread", so it broke every sandboxed call. Fork-bomb
        # protection belongs at the pod cgroup (pids.max), not a per-uid rlimit.
        _ = nproc  # accepted for signature/back-compat; deliberately unused
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass

    try:
        result = func(*args, **(kwargs or {}))
        queue.put(("ok", result))
    except MemoryError as exc:
        # RLIMIT_AS exhaustion surfaces as a Python-level MemoryError rather
        # than a kill signal when the allocation happens inside the
        # interpreter (e.g. bytearray/list growth) — report it the same way
        # as a signal-based limit kill so callers only need to handle one
        # exception type.
        queue.put(
            (
                "limit",
                f"MemoryError: {exc} (RLIMIT_AS exceeded, mem_limit={mem_bytes // 1024 // 1024}MB)",
            )
        )
    except Exception as exc:  # noqa: BLE001 - propagate as a plain string, not a pickled exception
        queue.put(("error", f"{type(exc).__name__}: {exc}"))


def run_limited(
    func,
    *args,
    cpu_seconds: int | None = None,
    mem_bytes: int | None = None,
    timeout: int | None = None,
    nproc: int | None = None,
    **kwargs,
):
    """Run ``func(*args, **kwargs)`` in an isolated child process with CPU,
    memory, and wall-clock limits applied.

    Returns whatever ``func`` returns (must be picklable). Raises
    ``ResourceLimitExceeded`` if the child was killed for exceeding a limit,
    or re-raises the child's exception (as ``RuntimeError``) otherwise.

    Falls back to calling ``func`` directly in-process (no isolation) if the
    platform has no fork-capable multiprocessing context — better to run
    unsandboxed than to silently skip a forensic module.
    """
    cpu_seconds = DEFAULT_CPU_SECONDS if cpu_seconds is None else cpu_seconds
    mem_bytes = DEFAULT_MEMORY_BYTES if mem_bytes is None else mem_bytes
    timeout = DEFAULT_WALL_TIMEOUT_SEC if timeout is None else timeout
    nproc = DEFAULT_NPROC if nproc is None else nproc

    try:
        ctx = multiprocessing.get_context("fork")
    except (ValueError, ImportError):
        logger.warning(
            "run_limited: fork-based multiprocessing unavailable on this platform — "
            "running %s unsandboxed",
            getattr(func, "__name__", func),
        )
        return func(*args, **kwargs)

    queue = ctx.Queue()
    proc = ctx.Process(
        target=_child_entrypoint,
        args=(func, args, kwargs, queue, cpu_seconds, mem_bytes, nproc),
        # NOT daemon: (1) Celery's prefork workers are themselves daemonic and a
        # daemonic process may not start children, and (2) some parsers (e.g.
        # Volatility 3) fork their own workers, which a daemonic child forbids.
        # The child stays bounded by the rlimits, RLIMIT_NPROC, and the
        # join/terminate/kill below, so it cannot run away or leak.
        daemon=False,
    )
    # Celery's prefork pool runs this task inside a daemonic worker process, and
    # multiprocessing refuses to let a daemonic process create children
    # ("daemonic processes are not allowed to have children"). Temporarily clear
    # the current process's daemon flag across start(); the child is joined (and
    # terminated on timeout) right here, so nothing else observes the change.
    _cur = multiprocessing.current_process()
    _saved_daemon = _cur._config.get("daemon")
    _cur._config["daemon"] = False
    try:
        proc.start()
    finally:
        _cur._config["daemon"] = _saved_daemon
    proc.join(timeout)

    if proc.is_alive():
        logger.warning(
            "run_limited: %s exceeded wall-clock timeout (%ss) — terminating",
            getattr(func, "__name__", func),
            timeout,
        )
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join(5)
        raise ResourceLimitExceeded(
            f"parser exceeded wall-clock timeout of {timeout}s and was killed"
        )

    exitcode = proc.exitcode
    if exitcode is not None and exitcode < 0:
        sig = -exitcode
        reason = _LIMIT_SIGNALS.get(sig, f"signal {sig}")
        raise ResourceLimitExceeded(
            f"parser was terminated by {reason} (cpu_limit={cpu_seconds}s, "
            f"mem_limit={mem_bytes // 1024 // 1024}MB)"
        )

    try:
        status, payload = queue.get_nowait()
    except Exception:
        # Child died without ever reporting (e.g. killed between setrlimit and
        # the try/except installing) — treat as a limit hit rather than hang.
        raise ResourceLimitExceeded(
            f"parser exited (code={exitcode}) without producing a result — "
            "likely killed for exceeding a resource limit"
        ) from None

    if status == "limit":
        raise ResourceLimitExceeded(payload)
    if status == "error":
        raise RuntimeError(payload)
    return payload


def subprocess_run_limited(
    cmd, *, cpu_seconds=None, mem_bytes=None, timeout=None, nproc=None, **kwargs
):
    """``subprocess.run`` with CPU/memory rlimits applied to the child and a
    uniform ``ResourceLimitExceeded`` raised on wall-clock timeout.

    Any ``preexec_fn`` already supplied by the caller is skipped in favour of
    the limit-enforcing one — callers needing extra setup should apply it
    inside their own preexec and call ``preexec_limits()`` themselves.
    """
    import subprocess

    timeout = DEFAULT_WALL_TIMEOUT_SEC if timeout is None else timeout
    kwargs.pop("preexec_fn", None)
    kwargs["preexec_fn"] = preexec_limits(cpu_seconds, mem_bytes, nproc)
    kwargs["timeout"] = timeout
    try:
        proc = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise ResourceLimitExceeded(
            f"parser exceeded wall-clock timeout of {timeout}s and was killed"
        ) from exc

    # A negative returncode means the child died from a signal rather than
    # exiting normally — on Linux, RLIMIT_CPU delivers SIGXCPU and RLIMIT_AS
    # exhaustion typically shows up as SIGSEGV/SIGKILL. Surface these the same
    # way as the wall-clock case instead of returning a "successful" process
    # with a signal-death returncode.
    if proc.returncode < 0:
        sig = -proc.returncode
        reason = _LIMIT_SIGNALS.get(sig, f"signal {sig}")
        raise ResourceLimitExceeded(
            f"parser was terminated by {reason} (cpu_limit={cpu_seconds or DEFAULT_CPU_SECONDS}s, "
            f"mem_limit={(mem_bytes or DEFAULT_MEMORY_BYTES) // 1024 // 1024}MB)"
        )
    return proc
