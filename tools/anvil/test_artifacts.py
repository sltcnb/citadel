"""Verify typed Result.artifacts[] survives serialization + the sandbox envelope.

Standalone-runnable. Mirrors the normalization in tasks/_module_sandbox.py so the
contract (hits + artifacts + metrics + status) is checked without a subprocess.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import Artifact, BaseModule, Result, RunContext  # noqa: E402


class _Producer(BaseModule):
    name = "artifact-producer"

    def validate(self, ctx):
        return None

    def analyze(self, ctx: RunContext) -> Result:
        r = Result(module=self.name)
        r.add_finding("medium", "found something", "see dump")
        r.add_artifact(
            Artifact(
                name="dump.bin",
                kind="extracted",
                minio_key="cases/c/modules/r/dump.bin",
                sha256="a" * 64,
                size=1024,
            )
        )
        r.metrics["files_scanned"] = 3
        return r


def _sandbox_envelope(result_dict):
    """Replicate tasks/_module_sandbox.py result normalization."""
    if isinstance(result_dict, dict):
        hits = [h for h in result_dict.get("hits", []) if isinstance(h, dict)]
        artifacts = [a for a in (result_dict.get("artifacts") or []) if isinstance(a, dict)]
        metrics = result_dict.get("metrics") or {}
        status = result_dict.get("status", "ok")
    else:
        hits, artifacts, metrics, status = result_dict, [], {}, "ok"
    return {"hits": hits, "artifacts": artifacts, "metrics": metrics, "status": status}


def test_result_serializes_artifacts():
    d = _Producer().run(RunContext(run_id="r", case_id="c", source_files=[])).to_dict()
    assert d["artifacts"], "artifacts dropped in to_dict"
    a = d["artifacts"][0]
    assert a["name"] == "dump.bin" and a["sha256"] == "a" * 64 and a["minio_key"]


def test_sandbox_envelope_preserves_artifacts():
    d = _Producer().run(RunContext(run_id="r", case_id="c", source_files=[])).to_dict()
    env = _sandbox_envelope(d)
    assert len(env["artifacts"]) == 1
    assert env["artifacts"][0]["kind"] == "extracted"
    assert env["metrics"]["files_scanned"] == 3
    assert env["status"] == "ok"


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
