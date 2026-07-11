"""Unit tests for the Anvil typed analyzer interface and result schema.

Run from the repo root:
    python -m pytest tools/anvil/test_base_module.py -q
or directly:
    python tools/anvil/test_base_module.py
"""

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from base import (  # noqa: E402
    SCHEMA_PATH,
    Artifact,
    BaseModule,
    Finding,
    Result,
    RunContext,
)


# ── A tiny in-tree analyzer exercising the full interface ────────────────────
class _DemoModule(BaseModule):
    name = "Demo"
    description = "demo"
    input_extensions = [".bin"]
    estimated_runtime = 5

    def analyze(self, ctx: RunContext) -> Result:
        r = Result(module=self.name)
        r.add_finding(
            "high",
            "demo finding",
            "found something",
            file="a.bin",
            techniques=["T1059"],
            custom_key="v",
        )
        r.add_artifact(Artifact(name="dump.bin", kind="extracted", size=10))
        r.metrics["scanned"] = 1
        return r


def _load(stem: str):
    """Load a sibling *_module.py the way the processor sandbox does."""
    path = HERE / f"{stem}_module.py"
    spec = importlib.util.spec_from_file_location(f"_fo_{stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeMinio:
    """Pretends a downloaded file already exists; touch it so paths are real."""

    def fget_object(self, bucket, key, dest):
        Path(dest).write_bytes(b"\x00demo")


def test_result_to_dict_shape():
    ctx = RunContext(
        run_id="r", case_id="c", source_files=[{"minio_key": "k", "filename": "a.bin"}]
    )
    out = _DemoModule().run(ctx).to_dict()
    assert out["module"] == "Demo"
    assert out["status"] == "ok"
    assert isinstance(out["hits"], list) and len(out["hits"]) == 1
    hit = out["hits"][0]
    # legacy back-compat keys preserved
    assert hit["level"] == "high"
    assert hit["level_int"] == 4
    assert hit["rule_title"] == "demo finding"
    assert hit["custom_key"] == "v"  # extra flattened
    assert hit["techniques"] == ["T1059"]
    assert out["artifacts"][0]["name"] == "dump.bin"
    assert "duration_s" in out["metrics"]


def test_validate_skips_without_files():
    ctx = RunContext(run_id="r", case_id="c", source_files=[])
    out = _DemoModule().run(ctx).to_dict()
    # A module with nothing to analyze is a run-status condition surfaced on the
    # run card (status="error" with a message), not a timeline finding.
    assert out["status"] == "error"
    assert out["error"]


def test_demo_result_conforms_to_schema():
    import jsonschema  # noqa: F811

    ctx = RunContext(
        run_id="r", case_id="c", source_files=[{"minio_key": "k", "filename": "a.bin"}]
    )
    result = _DemoModule().run(ctx)
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(instance=result.to_dict(), schema=schema)
    # also via the helper
    result.validate_schema()


def test_retrofitted_grep_result_conforms_to_schema(tmp_path):
    """A real retrofitted analyzer (grep_search) produces a schema-valid Result."""
    import jsonschema

    grep = _load("grep_search")
    # grep is present on macOS/Linux; the module's run() returns Result.to_dict()
    out = grep.run(
        run_id="r",
        case_id="c",
        source_files=[{"minio_key": "k", "filename": "sample.txt"}],
        params={"patterns": [r"http://[^\s]+"]},
        minio_client=_FakeMinio(),
        redis_client=None,
        tmp_dir=tmp_path,
    )
    assert isinstance(out, dict)
    assert "hits" in out and "metrics" in out
    assert out["module"] == "Grep / Pattern Search"
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(instance=out, schema=schema)


def test_retrofitted_modules_keep_legacy_run_signature():
    """Sandbox compatibility: each retrofit exposes a module-level run() and constants."""
    for stem, expected_name in (
        ("capa", "CAPA"),
        ("floss", "FLOSS"),
        ("grep_search", "Grep / Pattern Search"),
    ):
        mod = _load(stem)
        assert callable(mod.run)
        assert mod.MODULE_NAME == expected_name
        assert isinstance(mod.INPUT_EXTENSIONS, list)
        # a skipped/empty run still returns the legacy {"hits": [...]} envelope
        out = mod.run("r", "c", [], {}, None, None, ".")
        assert isinstance(out, dict) and "hits" in out


def test_finding_normalises_bad_level():
    assert Finding(level="bogus", rule_title="x").to_dict()["level"] == "informational"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
