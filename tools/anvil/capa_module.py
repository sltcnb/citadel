import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Ensure sibling `base` is importable whether this file is imported as part of a
# package, run directly, or loaded by the processor sandbox via
# spec_from_file_location (which does not put this dir on sys.path).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import BaseModule, Result, RunContext, iter_local_files  # noqa: E402

MODULE_NAME = "CAPA"
MODULE_DESCRIPTION = "Mandiant CAPA — detects capabilities in executable files and shellcode. Identifies malware behaviors (process injection, C2, persistence) mapped to MITRE ATT&CK, Malware Behavior Catalog (MBC), and CAPE signatures."
INPUT_EXTENSIONS = [".exe", ".dll", ".sys", ".bin", ".so"]
INPUT_FILENAMES = []

_HIGH_NAMESPACES = {
    "inject",
    "c2",
    "backdoor",
    "credential",
    "escalat",
    "persist",
    "exfil",
    "ransomware",
    "rootkit",
}
_MEDIUM_NAMESPACES = {
    "anti-analysis",
    "obfuscat",
    "encrypt",
    "defense",
    "evad",
    "pack",
}


def _severity(namespace: str) -> str:
    ns = namespace.lower()
    if any(k in ns for k in _HIGH_NAMESPACES):
        return "high"
    if any(k in ns for k in _MEDIUM_NAMESPACES):
        return "medium"
    return "informational"


class CapaModule(BaseModule):
    name = MODULE_NAME
    description = MODULE_DESCRIPTION
    input_extensions = INPUT_EXTENSIONS
    input_filenames = INPUT_FILENAMES
    estimated_runtime = 600  # capa can take minutes on large binaries

    def validate(self, ctx: RunContext) -> Result | None:
        pre = super().validate(ctx)
        if pre is not None:
            return pre
        if not shutil.which("capa"):
            return Result(module=self.name, status="skipped").add_finding(
                "informational",
                "CAPA not installed",
                "Install CAPA: https://github.com/mandiant/capa/releases — add to PATH.",
            )
        return None

    def analyze(self, ctx: RunContext) -> Result:
        capa_bin = shutil.which("capa")
        bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
        result = Result(module=self.name)
        files_scanned = 0

        for filename, local_path, _sf in iter_local_files(ctx, bucket=bucket):
            print(f"[capa] analysing {filename} …", file=sys.stderr)
            try:
                proc = subprocess.run(
                    [capa_bin, "--json", str(local_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.estimated_runtime,
                )
            except subprocess.TimeoutExpired:
                print(f"[capa] timeout for {filename}", file=sys.stderr)
                continue

            # capa exits 0 (capabilities found), 1 (no capabilities / error)
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                print(f"[capa] invalid JSON for {filename}: {proc.stderr[:400]}", file=sys.stderr)
                continue
            files_scanned += 1

            for cap_name, cap_data in data.get("rules", {}).items():
                meta = cap_data.get("meta", {})
                namespace = meta.get("namespace", "")

                attack_ids = [t["id"] for t in meta.get("attack", []) if t.get("id")]
                mbc_ids = [
                    m["id"] for m in meta.get("mbc", []) if isinstance(m, dict) and m.get("id")
                ]

                parts = [meta.get("description", "")]
                if attack_ids:
                    parts.append(f"ATT&CK: {', '.join(attack_ids)}")
                if mbc_ids:
                    parts.append(f"MBC: {', '.join(mbc_ids)}")

                result.add_finding(
                    _severity(namespace),
                    cap_name,
                    " | ".join(p for p in parts if p),
                    file=filename,
                    techniques=attack_ids,
                    namespace=namespace,
                )

        result.metrics["files_scanned"] = files_scanned
        result.metrics["findings"] = len(result.findings)
        return result


run = CapaModule.as_run()
