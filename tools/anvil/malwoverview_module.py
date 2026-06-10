import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

MODULE_NAME = "Malwoverview — VirusTotal Lookup"
MODULE_DESCRIPTION = "Hash files and query VirusTotal v3. Requires a VT API key configured in Settings → Integrations → malwoverview."
INPUT_EXTENSIONS = []
INPUT_FILENAMES = []
ARTIFACT_TYPE = "malwoverview"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}
_CONFIG_KEY = "fo:config:malwoverview"
_ANSI_RE_IMPORT = None  # lazy

try:
    import re as _re

    _ANSI_RE_IMPORT = _re.compile(r"\x1b\[[0-9;]*m")
except Exception:
    pass


def _strip_ansi(text: str) -> str:
    return _ANSI_RE_IMPORT.sub("", text) if _ANSI_RE_IMPORT else text


def _vt_lookup(sha256: str, api_key: str, filename: str) -> list[dict]:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"[malwoverview] {sha256[:16]}… not found in VT", file=sys.stderr)
            return [
                {
                    "id": str(uuid.uuid4()),
                    "level": "info",
                    "level_int": 1,
                    "rule_title": "Not in VirusTotal",
                    "computer": filename,
                    "details_raw": json.dumps({"sha256": sha256, "status": "not_found"}),
                    "message": f"{filename} — hash not found in VirusTotal",
                }
            ]
        raise

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(stats.values())

    if malicious >= 10:
        level = "critical"
    elif malicious >= 5:
        level = "high"
    elif malicious >= 2 or suspicious >= 5:
        level = "medium"
    elif malicious >= 1 or suspicious >= 1:
        level = "low"
    else:
        level = "info"

    engine_verdicts = {
        engine: result.get("result") or result.get("category", "")
        for engine, result in (attrs.get("last_analysis_results") or {}).items()
        if result.get("category") in ("malicious", "suspicious")
    }
    names = attrs.get("names", [])
    tags = attrs.get("tags", [])

    print(f"[malwoverview]   VT: {malicious}/{total} engines flagged {filename}", file=sys.stderr)
    return [
        {
            "id": str(uuid.uuid4()),
            "level": level,
            "level_int": _LEVEL_INT.get(level, 1),
            "rule_title": f"VirusTotal: {malicious}/{total} detections",
            "computer": filename,
            "details_raw": json.dumps(
                {
                    "sha256": sha256,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "names": names[:10],
                    "tags": tags,
                    "engine_verdicts": dict(list(engine_verdicts.items())[:20]),
                }
            ),
            "message": (
                f"{filename} — {malicious}/{total} AV engines detected malware"
                + (f" | {', '.join(names[:2])}" if names else "")
                + (f" [{', '.join(tags[:3])}]" if tags else "")
            ),
        }
    ]


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    # Load VT API key from Redis config or env fallback
    vt_api_key = ""
    if redis_client:
        try:
            cfg = redis_client.hgetall(_CONFIG_KEY) or {}
            vt_api_key = (cfg.get("vt_api_key") or "").strip()
        except Exception:
            pass
    if not vt_api_key:
        vt_api_key = os.getenv("VT_API_KEY", "").strip()
    if not vt_api_key:
        return [
            {
                "level": "informational",
                "rule_title": "malwoverview not configured",
                "description": "Set VirusTotal API key in Settings → Integrations → malwoverview.",
            }
        ]

    mwo_bin = shutil.which("malwoverview") or shutil.which("malwoverview.py")
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
            print(f"[malwoverview] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        # Hash
        sha256_h, md5_h, sha1_h = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        with open(local_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256_h.update(chunk)
                md5_h.update(chunk)
                sha1_h.update(chunk)
        sha256 = sha256_h.hexdigest()
        print(
            f"[malwoverview] {filename}  sha256={sha256}  md5={md5_h.hexdigest()}", file=sys.stderr
        )

        try:
            hits.extend(_vt_lookup(sha256, vt_api_key, filename))
        except urllib.error.URLError as exc:
            print(f"[malwoverview] VT network error: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[malwoverview] error for {filename}: {exc}", file=sys.stderr)

        # Optional malwoverview CLI enrichment
        if mwo_bin:
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/usr/local/bin"),
                "HOME": str(tmp_dir),
                "LANG": "en_US.UTF-8",
            }
            cfg_dir = tmp_dir / ".malwoverview"
            cfg_dir.mkdir(exist_ok=True)
            (cfg_dir / ".malwoverview").write_text(f"[VIRUSTOTAL]\nvtapi = {vt_api_key}\n")
            try:
                proc = subprocess.run(
                    [mwo_bin, "-x", sha256, "-V", "3"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=env,
                )
                if proc.stdout:
                    print("[malwoverview CLI]\n" + _strip_ansi(proc.stdout), file=sys.stderr)
            except Exception as exc:
                print(f"[malwoverview] CLI skipped: {exc}", file=sys.stderr)

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
