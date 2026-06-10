"""
Anvil — typed analyzer interface and structured result schema.

Every analyzer ("module") in this directory is a standalone deep analyzer that
Citadel's processor sandbox invokes via a module-level ``run()`` function with
the signature::

    run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir)

Historically each module returned a bare ``list[dict]`` of "hits". That is
loosely typed and inconsistent across the 12+ analyzers. This module defines:

  * :class:`BaseModule` — a typed abstract interface (``name``,
    ``estimated_runtime``, :meth:`validate` pre-flight, :meth:`run` -> Result).
  * :class:`Result` / :class:`Finding` / :class:`Artifact` — a structured,
    self-validating result schema with ``findings`` / ``artifacts`` / ``metrics``.

Back-compat is preserved: ``Result.to_dict()`` serialises to
``{"hits": [...], "artifacts": [...], "metrics": {...}}`` and each Finding
serialises to the legacy hit-dict shape (``level`` / ``rule_title`` /
``description`` / ...). The processor sandbox reads ``result.get("hits", [])``,
so a retrofitted module that returns ``result.to_dict()`` behaves identically to
one that returned a bare ``list`` of hit-dicts.

A JSON Schema for :class:`Result` ships alongside as ``result.schema.json`` and
is enforced by :meth:`Result.validate_schema` (best-effort; skips silently when
``jsonschema`` is unavailable).
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ── Severity vocabulary ─────────────────────────────────────────────────────
# Mirrors the levels the existing analyzers and the Timeline UI already use.
LEVELS = ("critical", "high", "medium", "low", "informational")
_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

SCHEMA_PATH = Path(__file__).with_name("result.schema.json")


# ── Structured result schema ────────────────────────────────────────────────
@dataclass
class Finding:
    """A single analyzer observation.

    Serialises to the legacy "hit" dict consumed by the processor/Timeline:
    ``level`` + ``rule_title`` + ``description`` are the load-bearing keys;
    everything in :attr:`extra` is merged in at the top level for fidelity.
    """

    level: str
    rule_title: str
    description: str = ""
    file: str | None = None
    techniques: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            self.level = "informational"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "level": self.level,
            "level_int": _LEVEL_INT[self.level],
            "rule_title": self.rule_title,
            "description": self.description,
        }
        if self.file is not None:
            d["file"] = self.file
        if self.techniques:
            d["techniques"] = list(self.techniques)
        # extra keys are flattened to stay backward-compatible with consumers
        # that read bespoke fields (e.g. strings' "string_value", grep's "pattern").
        for k, v in self.extra.items():
            d.setdefault(k, v)
        return d


@dataclass
class Artifact:
    """A file/blob produced by the analyzer (dump, report, extracted payload)."""

    name: str
    kind: str = "file"  # file | report | extracted | log
    path: str | None = None  # local path inside the sandbox work dir
    minio_key: str | None = None  # object-store key when uploaded
    sha256: str | None = None
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Result:
    """Structured analyzer output.

    Attributes
    ----------
    module : str
        The analyzer name (``BaseModule.name``).
    findings : list[Finding]
        Observations; serialised to ``hits`` for back-compat.
    artifacts : list[Artifact]
        Files/blobs the analyzer produced.
    metrics : dict
        Free-form numeric/string telemetry (counts, durations, files scanned).
    status : str
        ``ok`` | ``skipped`` | ``error`` — coarse run outcome.
    error : str | None
        Populated when ``status == "error"``.
    """

    module: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    error: str | None = None

    # ── builders ────────────────────────────────────────────────────────────
    def add(self, finding: Finding) -> Result:
        self.findings.append(finding)
        return self

    def add_finding(
        self, level: str, rule_title: str, description: str = "", **extra: Any
    ) -> Result:
        file = extra.pop("file", None)
        techniques = extra.pop("techniques", []) or []
        return self.add(
            Finding(
                level=level,
                rule_title=rule_title,
                description=description,
                file=file,
                techniques=list(techniques),
                extra=extra,
            )
        )

    def add_artifact(self, artifact: Artifact) -> Result:
        self.artifacts.append(artifact)
        return self

    # ── serialisation ─────────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "error": self.error,
            "hits": [f.to_dict() for f in self.findings],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "metrics": dict(self.metrics),
        }

    @property
    def hits(self) -> list[dict[str, Any]]:
        """Legacy accessor used by callers that expect a list of hit dicts."""
        return [f.to_dict() for f in self.findings]

    # ── validation ────────────────────────────────────────────────────────────
    def validate_schema(self) -> None:
        """Validate against ``result.schema.json``.

        Raises ``jsonschema.ValidationError`` on a non-conforming Result.
        Silently returns when ``jsonschema`` is not installed so production
        analyzer runs never fail purely for lack of a dev dependency.
        """
        try:
            import jsonschema  # type: ignore
        except Exception:
            return
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(instance=self.to_dict(), schema=schema)


# ── Typed analyzer interface ─────────────────────────────────────────────────
@dataclass
class RunContext:
    """Everything an analyzer needs to execute one run.

    Mirrors the positional/keyword arguments the processor sandbox passes to the
    module-level ``run()`` so a :class:`BaseModule` can be driven directly or via
    the legacy entry point.
    """

    run_id: str
    case_id: str
    source_files: list[dict[str, Any]]
    params: dict[str, Any] = field(default_factory=dict)
    minio_client: Any = None
    redis_client: Any = None
    tmp_dir: Path = field(default_factory=lambda: Path("."))


class BaseModule(ABC):
    """Abstract base for an Anvil analyzer.

    Subclasses declare metadata as class attributes and implement
    :meth:`analyze`. :meth:`run` wraps :meth:`analyze` with pre-flight
    :meth:`validate`, timing into ``metrics`` and uniform error handling, always
    returning a :class:`Result`.
    """

    #: Human-readable analyzer name (kept in sync with module-level MODULE_NAME).
    name: str = "Unnamed analyzer"
    #: One-line description.
    description: str = ""
    #: File extensions this analyzer accepts (empty = any).
    input_extensions: list[str] = []
    #: Exact filenames this analyzer targets (empty = any).
    input_filenames: list[str] = []
    #: Rough wall-clock budget in seconds for one run (UI/scheduling hint).
    estimated_runtime: int = 60

    # ── pre-flight ────────────────────────────────────────────────────────────
    def validate(self, ctx: RunContext) -> Result | None:
        """Pre-flight check.

        Return ``None`` to proceed, or a terminal :class:`Result` (typically
        ``status="skipped"``) to short-circuit — e.g. when the backing binary is
        not installed or no source files were supplied. Override to add checks.
        """
        if not ctx.source_files:
            return Result(module=self.name, status="skipped").add_finding(
                "informational",
                f"{self.name}: no source files",
                "No source files were supplied to analyze.",
            )
        return None

    # ── analysis ───────────────────────────────────────────────────────────────
    @abstractmethod
    def analyze(self, ctx: RunContext) -> Result:
        """Do the work and return a structured :class:`Result`."""
        raise NotImplementedError

    # ── orchestration ──────────────────────────────────────────────────────────
    def run(self, ctx: RunContext) -> Result:
        started = time.monotonic()
        pre = self.validate(ctx)
        if pre is not None:
            pre.metrics.setdefault("duration_s", round(time.monotonic() - started, 3))
            return pre
        try:
            result = self.analyze(ctx)
        except Exception as exc:  # uniform failure surface
            result = Result(module=self.name, status="error", error=str(exc))
        result.metrics.setdefault("duration_s", round(time.monotonic() - started, 3))
        result.metrics.setdefault("files_in", len(ctx.source_files))
        return result

    # ── legacy entry point ──────────────────────────────────────────────────────
    @classmethod
    def as_run(cls):
        """Build a module-level ``run(...)`` callable bound to this analyzer.

        The processor sandbox calls ``run()`` with keyword args and reads
        ``result.get("hits", [])``; this returns ``Result.to_dict()`` which keeps
        that contract while exposing the richer structured payload.
        """
        inst = cls()

        def run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
            ctx = RunContext(
                run_id=run_id,
                case_id=case_id,
                source_files=list(source_files or []),
                params=dict(params or {}),
                minio_client=minio_client,
                redis_client=redis_client,
                tmp_dir=Path(tmp_dir),
            )
            return inst.run(ctx).to_dict()

        return run


# ── shared helpers reused by retrofitted analyzers ───────────────────────────
def severity_int(level: str) -> int:
    return _LEVEL_INT.get(level, 1)


def result_from_hits(name: str, hits: Any, **metrics: Any) -> Result:
    """Build a structured :class:`Result` from a legacy bare hit-list.

    Each hit dict's load-bearing keys (``level`` / ``rule_title``|``title`` /
    ``description`` / ``file`` / ``techniques``) map onto a :class:`Finding`;
    every other key is preserved verbatim in ``extra`` so bespoke fields
    (strings' ``string_value`` / ``id`` / ``details_raw``, grep's ``pattern`` …)
    survive the round-trip unchanged.
    """
    res = Result(module=name)
    if isinstance(hits, dict):  # already a Result-shaped dict
        res.status = hits.get("status", "ok")
        res.error = hits.get("error")
        res.metrics.update(hits.get("metrics", {}))
        hits = hits.get("hits", [])
    for h in hits or []:
        h = dict(h)
        level = h.pop("level", "informational")
        title = h.pop("rule_title", None) or h.pop("title", "") or ""
        desc = h.pop("description", "")
        h.pop("level_int", None)
        file = h.pop("file", None)
        techniques = h.pop("techniques", []) or []
        res.add(
            Finding(
                level=level,
                rule_title=title,
                description=desc,
                file=file,
                techniques=list(techniques),
                extra=h,
            )
        )
    res.metrics.update(metrics)
    return res


def wrap_legacy(
    name: str,
    legacy_run: Any,
    *,
    description: str = "",
    input_extensions: list[str] | None = None,
    input_filenames: list[str] | None = None,
    estimated_runtime: int = 60,
) -> type[BaseModule]:
    """Adapt a legacy module-level ``run(...)`` into a typed :class:`BaseModule`.

    Lets all 12 analyzers expose the typed interface without rewriting their
    analysis logic: the subclass's :meth:`analyze` invokes the original
    free-function and packs its hit-list into a :class:`Result`. Pair with
    ``run = wrap_legacy(...).as_run()`` so the module-level entry point is
    unchanged for the processor sandbox.
    """

    class _LegacyAdapter(BaseModule):
        # analyze defined in-body so ABCMeta sees the override and the class
        # is concrete (assigning analyze after creation leaves it abstract).
        def analyze(self, ctx: RunContext) -> Result:
            out = legacy_run(
                ctx.run_id,
                ctx.case_id,
                ctx.source_files,
                ctx.params,
                ctx.minio_client,
                ctx.redis_client,
                str(ctx.tmp_dir),
            )
            return result_from_hits(name, out)

    _LegacyAdapter.name = name
    _LegacyAdapter.description = description
    _LegacyAdapter.input_extensions = list(input_extensions or [])
    _LegacyAdapter.input_filenames = list(input_filenames or [])
    _LegacyAdapter.estimated_runtime = estimated_runtime
    _LegacyAdapter.__name__ = name.split()[0].replace("/", "") + "Module"
    return _LegacyAdapter


def iter_local_files(ctx: RunContext, *, bucket: str) -> Iterable[tuple[str, Path, dict]]:
    """Yield ``(filename, local_path, source_file)`` for each downloadable input.

    Centralises the download boilerplate every analyzer repeats: resolve a
    filename, skip entries without a ``minio_key``, fetch into ``tmp_dir``.
    Download failures are skipped (the caller may log).
    """
    for sf in ctx.source_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key:
            continue
        local_path = ctx.tmp_dir / filename
        if ctx.minio_client is not None:
            try:
                ctx.minio_client.fget_object(bucket, minio_key, str(local_path))
            except Exception:
                continue
        yield filename, local_path, sf
