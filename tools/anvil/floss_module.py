import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# See capa_module for why this dir is forced onto sys.path before importing base.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import BaseModule, Result, RunContext, iter_local_files  # noqa: E402

MODULE_NAME = "FLOSS"
MODULE_DESCRIPTION = "FireEye Labs Obfuscated String Solver. Extracts static, stack, and decoded strings from PE malware samples — finds strings that regular tools miss by emulating deobfuscation routines. Ideal for malware triage."
INPUT_EXTENSIONS = [".exe", ".dll", ".sys", ".bin", ".scr"]
INPUT_FILENAMES = []


class FlossModule(BaseModule):
    name = MODULE_NAME
    description = MODULE_DESCRIPTION
    input_extensions = INPUT_EXTENSIONS
    input_filenames = INPUT_FILENAMES
    estimated_runtime = 300

    def validate(self, ctx: RunContext) -> Result | None:
        pre = super().validate(ctx)
        if pre is not None:
            return pre
        if not shutil.which("floss"):
            # Missing binary is a run-status/config condition — surface it on the
            # run card as an error, not as an informational timeline finding.
            return Result(
                module=self.name,
                status="error",
                error="FLOSS not installed — install from https://github.com/mandiant/flare-floss/releases and add it to PATH.",
            )
        return None

    def analyze(self, ctx: RunContext) -> Result:
        floss_bin = shutil.which("floss")
        bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
        result = Result(module=self.name)
        decoded_total = 0
        static_total = 0

        for filename, local_path, _sf in iter_local_files(ctx, bucket=bucket):
            print(f"[floss] analysing {filename} …", file=sys.stderr)
            try:
                proc = subprocess.run(
                    [floss_bin, "--json", "--minimum-length", "4", str(local_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.estimated_runtime,
                )
            except subprocess.TimeoutExpired:
                print(f"[floss] timeout for {filename}", file=sys.stderr)
                continue

            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                print(f"[floss] invalid JSON for {filename}: {proc.stderr[:300]}", file=sys.stderr)
                continue

            strings_section = data.get("strings", {})

            # Report decoded + stack strings (interesting, non-trivial)
            for key, label in (("decoded_strings", "decoded"), ("stack_strings", "stack")):
                for entry in strings_section.get(key, []):
                    s = entry.get("string", "") if isinstance(entry, dict) else str(entry)
                    offset = entry.get("offset", "") if isinstance(entry, dict) else ""
                    encoding = entry.get("encoding", "") if isinstance(entry, dict) else ""
                    if len(s) < 4:
                        continue
                    decoded_total += 1
                    result.add_finding(
                        "informational",
                        f"FLOSS {label} string",
                        s,
                        file=filename,
                        offset=str(offset),
                        encoding=encoding,
                    )

            # Summary hit for static strings (too many to enumerate individually)
            static = strings_section.get("static_strings", [])
            if static:
                static_total += len(static)
                result.add_finding(
                    "informational",
                    "FLOSS static strings",
                    f"{len(static)} static strings extracted",
                    file=filename,
                    count=len(static),
                )

        result.metrics["decoded_strings"] = decoded_total
        result.metrics["static_strings"] = static_total
        return result


run = FlossModule.as_run()
