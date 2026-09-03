import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# See capa_module for why this dir is forced onto sys.path before importing base.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import BaseModule, Result, RunContext, iter_local_files  # noqa: E402

MODULE_NAME = "Grep / Pattern Search"
MODULE_DESCRIPTION = "Search files for regex patterns — URLs, IPs, hashes, encoded payloads, suspicious command references. Accepts custom patterns via params."
INPUT_EXTENSIONS = []
INPUT_FILENAMES = []
ARTIFACT_TYPE = "grep_search"

_DEFAULT_PATTERNS = [
    r'https?://[^\s<>"]+',
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"[a-fA-F0-9]{32}",  # MD5
    r"[a-fA-F0-9]{40}",  # SHA1
    r"[a-fA-F0-9]{64}",  # SHA256
    r"(?:powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin)",
]


def _normalize(pat: str) -> str:
    try:
        re.compile(pat)
        return pat
    except re.error:
        return re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".")


# ── Pattern cost bounds ───────────────────────────────────────────────────────
#
# Patterns arrive in ctx.params, so whoever can queue a module run chooses
# them. `grep -oP` runs PCRE, and a nested quantifier like (a+)+$ backtracks
# exponentially on crafted input: one pattern could pin a worker core for the
# whole subprocess timeout, per pattern, per file. Bounding the pattern set and
# the per-invocation wall clock keeps a bad pattern from becoming a worker DoS.
_MAX_PATTERNS = 64
_MAX_PATTERN_LEN = 512
# Seconds per grep invocation. Was 60; a pathological pattern used the full
# budget on every file, and legitimate patterns finish in well under this.
_GREP_TIMEOUT = int(os.getenv("GREP_SEARCH_TIMEOUT", "15"))

# Nested quantifier applied to an already-quantified group — the classic
# catastrophic-backtracking shape: (a+)+, (x*)*, ([a-z]+)*, (\d{2,})+.
#
# This is a cheap screen, not a decision procedure. Other shapes backtrack too
# (overlapping alternation such as (a|aa)+ is not matched here), and detecting
# them reliably would reject legitimate patterns like (foo|bar)+. The bounded
# _GREP_TIMEOUT below is what covers the rest: this rule removes the pattern
# class that is both obviously pathological and unambiguous to spot.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*}][)]?\)\s*[+*{]")


def _pattern_rejection(pat: str) -> str | None:
    """Return a reason to refuse this pattern, or None if it is acceptable."""
    if len(pat) > _MAX_PATTERN_LEN:
        return f"pattern is {len(pat)} characters (limit {_MAX_PATTERN_LEN})"
    if _NESTED_QUANTIFIER.search(pat):
        return (
            "pattern nests a quantifier inside a quantified group "
            "(catastrophic backtracking); rewrite it without the nesting"
        )
    return None


class GrepSearchModule(BaseModule):
    name = MODULE_NAME
    description = MODULE_DESCRIPTION
    input_extensions = INPUT_EXTENSIONS
    input_filenames = INPUT_FILENAMES
    estimated_runtime = 120

    def validate(self, ctx: RunContext) -> Result | None:
        pre = super().validate(ctx)
        if pre is not None:
            return pre
        if not shutil.which("grep"):
            # Run-status/config condition, not a timeline finding.
            return Result(
                module=self.name,
                status="error",
                error="grep not installed — install coreutils on the worker.",
            )
        return None

    def analyze(self, ctx: RunContext) -> Result:
        grep_bin = shutil.which("grep")
        patterns = ctx.params.get("patterns") or list(_DEFAULT_PATTERNS)
        bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
        result = Result(module=self.name)
        matches_total = 0

        if len(patterns) > _MAX_PATTERNS:
            print(
                f"[grep_search] {len(patterns)} patterns supplied; using the "
                f"first {_MAX_PATTERNS} (limit)",
                file=sys.stderr,
            )
            result.add_finding(
                "low",
                "Pattern list truncated",
                f"{len(patterns)} patterns supplied; only the first "
                f"{_MAX_PATTERNS} were run.",
            )
            patterns = patterns[:_MAX_PATTERNS]

        # Screen the pattern set once, before touching any file.
        usable: list[str] = []
        for raw in patterns:
            pat = _normalize(raw)
            reason = _pattern_rejection(pat)
            if reason:
                print(f"[grep_search] refusing pattern {pat[:60]!r}: {reason}", file=sys.stderr)
                result.add_finding(
                    "low",
                    f"Pattern refused — {pat[:60]}",
                    f"This pattern was not run: {reason}.",
                    pattern=pat,
                )
                continue
            usable.append(pat)
        patterns = usable

        for filename, local_path, _sf in iter_local_files(ctx, bucket=bucket):
            print(
                f"[grep_search] scanning {filename} with {len(patterns)} patterns …",
                file=sys.stderr,
            )

            for pat in patterns:
                try:
                    proc_count = subprocess.run(
                        [grep_bin, "-oPc", "--", pat, str(local_path)],
                        capture_output=True,
                        text=True,
                        timeout=_GREP_TIMEOUT,
                    )
                    count = (
                        int(proc_count.stdout.strip()) if proc_count.stdout.strip().isdigit() else 0
                    )
                except subprocess.TimeoutExpired:
                    # Record it. Reporting 0 here would show the analyst "no
                    # matches" for a search that never actually completed.
                    print(
                        f"[grep_search]   [{pat[:40]}] timed out after "
                        f"{_GREP_TIMEOUT}s on {filename}",
                        file=sys.stderr,
                    )
                    result.add_finding(
                        "medium",
                        f"Pattern timed out — {pat[:60]}",
                        f"grep did not finish within {_GREP_TIMEOUT}s on this "
                        f"file, so its result is UNKNOWN — not zero matches. "
                        f"Simplify the pattern or narrow the input.",
                        file=filename,
                        filename=filename,
                        pattern=pat,
                    )
                    continue
                except ValueError:
                    count = 0

                if count > 0:
                    try:
                        proc_m = subprocess.run(
                            [grep_bin, "-oP", "--", pat, str(local_path)],
                            capture_output=True,
                            text=True,
                            timeout=_GREP_TIMEOUT,
                        )
                        samples = list(set(proc_m.stdout.strip().split("\n")))[:50]
                    except subprocess.TimeoutExpired:
                        samples = []

                    level = "high" if count > 10 else ("medium" if count > 2 else "low")
                    matches_total += count
                    result.add_finding(
                        level,
                        f"Pattern Match — {pat[:60]}",
                        json.dumps({"count": count, "samples": samples}),
                        file=filename,
                        computer=filename,
                        details_raw=json.dumps({"count": count, "samples": samples}),
                        filename=filename,
                        pattern=pat,
                        match_count=count,
                    )
                    print(f"[grep_search]   [{pat[:40]}…] → {count} match(es)", file=sys.stderr)

        result.metrics["patterns"] = len(patterns)
        result.metrics["matches"] = matches_total
        return result


run = GrepSearchModule.as_run()
