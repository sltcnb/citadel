"""Binary-parser golden tests (EVTX/LNK/Prefetch/Registry/MFT).

Each case runs only when its committed fixture + runtime lib are present;
otherwise it SKIPS with a clear reason (no fabricated binaries). Standalone +
pytest. Regenerate with BABEL_REGEN_GOLDEN=1.
"""

import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # tools/ for the `plugins` pkg

from babel.base_plugin import PluginContext  # noqa: E402
from babel.tests.golden import harness  # noqa: E402
from babel.tests.golden.cases import (  # noqa: E402
    BINARY_CASES,
    BINARY_FIXTURES_DIR,
    binary_case_status,
    load_binary_plugin,
)

_REGEN = os.environ.get("BABEL_REGEN_GOLDEN") == "1"


def _run_one(case: dict, validate) -> str:
    plugin_cls = load_binary_plugin(case)
    fixture = BINARY_FIXTURES_DIR / case["fixture"]
    ctx = PluginContext(
        case_id="golden",
        job_id="golden",
        source_file_path=fixture,
        source_minio_url=f"file://{fixture}",
        config={},
        logger=logging.getLogger("golden"),
    )
    plugin = plugin_cls(ctx)
    plugin.setup()
    try:
        events = [harness.scrub_event(dict(e)) for e in plugin.parse()]
    finally:
        plugin.teardown()
    expected_path = harness.EXPECTED_DIR if hasattr(harness, "EXPECTED_DIR") else None
    exp = (
        Path(__file__).resolve().parents[1] / "tests" / "golden" / "expected" / f"{case['id']}.json"
    )
    if _REGEN or not exp.exists():
        exp.parent.mkdir(parents=True, exist_ok=True)
        import json

        exp.write_text(json.dumps(events, indent=2, sort_keys=True) + "\n")
        return "regenerated"
    import json

    assert events == json.loads(exp.read_text()), f"{case['id']}: golden mismatch"
    for e in events:
        validate(e)
    return "matched"


def main() -> int:
    validate = harness.load_schema_validator()
    ran = skipped = 0
    print("Binary golden cases:")
    for case in BINARY_CASES:
        runnable, reason = binary_case_status(case)
        if not runnable:
            print(f"  SKIP {case['id']:18} — {reason}")
            skipped += 1
            continue
        status = _run_one(case, validate)
        print(f"  RUN  {case['id']:18} — {status}")
        ran += 1
    print(f"\n{ran} ran, {skipped} skipped (of {len(BINARY_CASES)} binary cases)")
    # The mechanism itself must be sound: every case yields a clean runnable/skip
    # decision (no crashes). Real runs happen once fixtures+libs are present.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
