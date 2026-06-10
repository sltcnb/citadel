import json
import os
import re
import shutil
import subprocess
import sys
import uuid

MODULE_NAME = "Strings Analysis"
MODULE_DESCRIPTION = "Extract ASCII + Unicode strings then categorise IOC patterns: URLs, IPs, email addresses, registry keys, filesystem paths."
INPUT_EXTENSIONS = []
INPUT_FILENAMES = []
ARTIFACT_TYPE = "strings_analysis"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

_IOC_PATTERNS = {
    "urls": re.compile(r"https?://"),
    "ips": re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    "emails": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "paths": re.compile(r"[A-Z]:\\|/usr/|/etc/|/var/"),
    "registry": re.compile(r"HKEY_|HKLM\\|HKCU\\"),
}


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return [
            {
                "level": "informational",
                "rule_title": "strings not installed",
                "description": "apt-get install binutils",
            }
        ]

    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []

    for sf in source_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[strings_analysis] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[strings_analysis] extracting from {filename} …", file=sys.stderr)

        def _extract(extra_flags):
            try:
                p = subprocess.run(
                    [strings_bin, "-a", "-n", "6"] + extra_flags + [str(local_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                return p.stdout.strip().split("\n") if p.stdout.strip() else []
            except subprocess.TimeoutExpired:
                return []

        all_strings = list(set(_extract([]) + _extract(["-el"])))

        iocs: dict[str, list[str]] = {cat: [] for cat in _IOC_PATTERNS}
        for s in all_strings:
            for cat, pat in _IOC_PATTERNS.items():
                if pat.search(s):
                    iocs[cat].append(s)

        ioc_count = sum(len(v) for v in iocs.values())
        level = "high" if ioc_count > 20 else ("medium" if ioc_count > 5 else "informational")

        hits.append(
            {
                "id": str(uuid.uuid4()),
                "level": level,
                "level_int": _LEVEL_INT.get(level, 1),
                "rule_title": f"Strings Analysis — {filename}",
                "computer": filename,
                "details_raw": json.dumps(
                    {
                        "total_strings": len(all_strings),
                        "interesting_strings": {k: v[:50] for k, v in iocs.items()},
                        "sample_strings": all_strings[:200],
                    }
                ),
                "filename": filename,
                "total_strings": len(all_strings),
            }
        )

        for cat, matches in iocs.items():
            for m in matches[:50]:
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": "medium",
                        "level_int": _LEVEL_INT["medium"],
                        "rule_title": f"IOC String ({cat})",
                        "computer": filename,
                        "details_raw": m,
                        "filename": filename,
                        "ioc_type": cat,
                    }
                )

        print(
            f"[strings_analysis]   {len(all_strings)} strings, {ioc_count} IOCs "
            f"(urls={len(iocs['urls'])}, ips={len(iocs['ips'])}, emails={len(iocs['emails'])})",
            file=sys.stderr,
        )

    return hits


# ── Typed BaseModule interface (Anvil) ───────────────────────────────────────
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from base import wrap_legacy as _wrap_legacy  # noqa: E402

_TypedModule = _wrap_legacy(
    MODULE_NAME,
    _legacy_run,
    description=MODULE_DESCRIPTION,
    input_extensions=globals().get("INPUT_EXTENSIONS", []),
    input_filenames=globals().get("INPUT_FILENAMES", []),
)
run = _TypedModule.as_run()
