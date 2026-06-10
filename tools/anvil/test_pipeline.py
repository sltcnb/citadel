"""Tests for the Anvil DAG pipeline. Runnable standalone: `python3 test_pipeline.py`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import BaseModule, Result, RunContext  # noqa: E402
from pipeline import Node, Pipeline  # noqa: E402


class _Producer(BaseModule):
    name = "producer"

    def validate(self, ctx):  # no source-file requirement for this synthetic node
        return None

    def analyze(self, ctx: RunContext) -> Result:
        r = Result(module=self.name)
        r.add_finding("low", "produced", "seed", token="ABC")
        return r


class _Consumer(BaseModule):
    name = "consumer"

    def validate(self, ctx):
        return None

    def analyze(self, ctx: RunContext) -> Result:
        upstream = ctx.params.get("upstream", {})
        r = Result(module=self.name)
        # Prove the downstream node sees the upstream Result.
        prod = upstream.get("p")
        token = prod.findings[0].extra.get("token") if prod and prod.findings else None
        r.add_finding("medium", "consumed", f"saw token={token}", saw=token)
        return r


def test_toposort_orders_dependencies():
    pipe = Pipeline(
        [
            Node("c", _Consumer(), depends_on=["p"]),
            Node("p", _Producer()),
        ]
    )
    assert pipe.order == ["p", "c"], pipe.order


def test_cycle_rejected():
    try:
        Pipeline(
            [
                Node("a", _Producer(), depends_on=["b"]),
                Node("b", _Producer(), depends_on=["a"]),
            ]
        )
    except ValueError as e:
        assert "cycle" in str(e)
    else:
        raise AssertionError("cycle not detected")


def test_dag_runs_and_passes_data_downstream():
    pipe = Pipeline(
        [
            Node("p", _Producer()),
            Node("c", _Consumer(), depends_on=["p"]),
        ]
    )
    ctx = RunContext(run_id="r", case_id="c", source_files=[])
    results = pipe.run(ctx)
    assert set(results) == {"p", "c"}
    # the consumer actually received the producer's token
    assert results["c"].findings[0].extra["saw"] == "ABC"
    merged = pipe.to_dict(results)
    assert merged["pipeline"] == ["p", "c"]
    assert len(merged["hits"]) == 2


if __name__ == "__main__":
    n = 0
    for fn in [
        test_toposort_orders_dependencies,
        test_cycle_rejected,
        test_dag_runs_and_passes_data_downstream,
    ]:
        fn()
        n += 1
        print(f"PASS  {fn.__name__}")
    print(f"\n{n}/{n} passed")
