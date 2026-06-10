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
            return Result(module=self.name, status="skipped").add_finding(
                "informational", "grep not installed", "Install coreutils"
            )
        return None

    def analyze(self, ctx: RunContext) -> Result:
        grep_bin = shutil.which("grep")
        patterns = ctx.params.get("patterns") or list(_DEFAULT_PATTERNS)
        bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
        result = Result(module=self.name)
        matches_total = 0

        for filename, local_path, _sf in iter_local_files(ctx, bucket=bucket):
            print(
                f"[grep_search] scanning {filename} with {len(patterns)} patterns …",
                file=sys.stderr,
            )

            for pat in patterns:
                pat = _normalize(pat)
                try:
                    proc_count = subprocess.run(
                        [grep_bin, "-oPc", pat, str(local_path)],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    count = (
                        int(proc_count.stdout.strip()) if proc_count.stdout.strip().isdigit() else 0
                    )
                except (subprocess.TimeoutExpired, ValueError):
                    count = 0

                if count > 0:
                    try:
                        proc_m = subprocess.run(
                            [grep_bin, "-oP", pat, str(local_path)],
                            capture_output=True,
                            text=True,
                            timeout=60,
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
