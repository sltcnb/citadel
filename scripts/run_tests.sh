#!/usr/bin/env bash
# Citadel test gate -- runs every standalone test suite across the tool suite.
# Each suite is runnable without pytest (stdlib __main__ runners) and exits
# non-zero on failure, so this is a real, dependency-light CI gate.
#
#   scripts/run_tests.sh
#
# Exit 0 only if ALL suites pass.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

SUITES=(
  "tools/citadel_contracts/test_validator.py"
  "api/test_agg_rules.py"
  "tools/sigil/test_sigil_tools.py"
  "tools/babel/tests/test_routing_fixes.py"
  "tools/babel/tests/test_sdk_template.py"
  "tools/babel/tests/test_golden_binary.py"
  "tools/anvil/test_pipeline.py"
  "tools/anvil/test_artifacts.py"
  "tools/rosetta/tests/test_daemon.py"
  "tools/augur/tests/test_phase2_close.py"
  "tools/talon/tests/test_secure_upload.py"
  "tools/talon/tests/test_chunker.py"
  "tools/sluice/worker/tests/test_routing_coverage.py"
  "tools/sluice/worker/tests/test_observability.py"
  "tools/sluice/worker/tests/test_parse_metrics.py"
  "tests/integration/test_pipeline_e2e.py"
)

pass=0; fail=0; failed=()
for s in "${SUITES[@]}"; do
  if python3 "$ROOT/$s" >/tmp/citadel_test.out 2>&1; then
    printf '  \033[32mPASS\033[0m %-52s %s\n' "$s" "$(tail -1 /tmp/citadel_test.out)"
    pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m %s\n' "$s"; tail -6 /tmp/citadel_test.out
    fail=$((fail+1)); failed+=("$s")
  fi
done

# Babel golden text cases (run inline; needs the plugins package on path).
if ( cd "$ROOT/tools" && python3 - <<'PY' >/tmp/citadel_test.out 2>&1
import sys; sys.path.insert(0, ".")
from babel.tests.golden import harness
from babel.tests.golden.cases import CASES
v = harness.load_schema_validator()
for c in CASES:
    assert harness.run_case(c) == harness.load_golden(c), f"{c.id} golden mismatch"
    [v(e) for e in harness.run_case(c)]
print(f"{len(CASES)}/{len(CASES)} golden cases match + contract-valid")
PY
); then
  printf '  \033[32mPASS\033[0m %-52s %s\n' "babel golden text" "$(tail -1 /tmp/citadel_test.out)"
  pass=$((pass+1))
else
  printf '  \033[31mFAIL\033[0m %s\n' "babel golden text"; tail -6 /tmp/citadel_test.out
  fail=$((fail+1)); failed+=("babel golden text")
fi

echo "---------------------------------------------"
echo "SUITES: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || { echo "FAILED: ${failed[*]}"; exit 1; }
echo "ALL GREEN"
