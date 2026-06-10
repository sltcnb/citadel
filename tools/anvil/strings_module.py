import os
import shutil
import subprocess
import sys
import uuid

MODULE_NAME = "Strings"
MODULE_DESCRIPTION = (
    "Extract printable ASCII and Unicode strings from binary files using the GNU strings utility."
)
INPUT_EXTENSIONS = []
INPUT_FILENAMES = []
INDEX_SKIP = True  # too noisy to index individually into Timeline

MAX_HITS = 10_000


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return [
            {
                "level": "informational",
                "rule_title": "strings not installed",
                "description": "Install binutils: apt-get install binutils",
            }
        ]

    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []
    total = 0

    for sf in source_files:
        if total >= MAX_HITS:
            break
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[strings] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[strings] extracting from {filename} …", file=sys.stderr)
        try:
            proc = subprocess.run(
                [strings_bin, "-n", "8", str(local_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            print(f"[strings] timeout for {filename}", file=sys.stderr)
            continue

        for line in proc.stdout.splitlines():
            s = line.strip()
            if not s or total >= MAX_HITS:
                break
            hits.append(
                {
                    "id": str(uuid.uuid4()),
                    "level": "informational",
                    "rule_title": filename,
                    "details_raw": s,
                    "filename": filename,
                    "string_value": s,
                }
            )
            total += 1

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
