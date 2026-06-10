import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

MODULE_NAME = "de4dot — .NET Deobfuscator"
MODULE_DESCRIPTION = "Deobfuscate .NET assemblies using de4dot. Detects and removes known obfuscation patterns from .NET executables and DLLs."
INPUT_EXTENSIONS = [".exe", ".dll"]
INPUT_FILENAMES = []
ARTIFACT_TYPE = "de4dot"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SAFE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/tmp",
    "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    "TMPDIR": "/tmp",
}


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    de4dot_bin = shutil.which("de4dot")
    mono_bin = shutil.which("mono")
    de4dot_exe = shutil.which("de4dot.exe") or "/usr/local/bin/de4dot.exe"

    if de4dot_bin:
        cmd_prefix = [de4dot_bin]
    elif mono_bin and Path(de4dot_exe).exists():
        cmd_prefix = [mono_bin, de4dot_exe]
    else:
        return [
            {
                "level": "informational",
                "rule_title": "de4dot not installed",
                "description": (
                    "Place the Linux build of de4dot on PATH (/usr/local/bin/de4dot), "
                    "or install Mono and de4dot.exe at /usr/local/bin/de4dot.exe."
                ),
            }
        ]

    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []

    for sf in source_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key or Path(filename).suffix.lower() not in {".exe", ".dll"}:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[de4dot] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        out_path = tmp_dir / f"{Path(filename).stem}_deob{Path(filename).suffix}"
        cmd = cmd_prefix + [str(local_path), "-o", str(out_path)]
        print(f"[de4dot] deobfuscating {filename} …", file=sys.stderr)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=_SAFE_ENV)
            stdout = _ANSI_RE.sub("", proc.stdout)
            stderr = _ANSI_RE.sub("", proc.stderr)
            print(stdout, file=sys.stderr)
            if stderr:
                print(stderr, file=sys.stderr)

            obf_match = re.search(r"Detected:\s*(.+)", stdout, re.IGNORECASE)
            obfuscator = obf_match.group(1).strip() if obf_match else "Unknown"
            success = out_path.exists()
            level = "high" if obfuscator != "Unknown" else "medium"

            hits.append(
                {
                    "id": str(uuid.uuid4()),
                    "level": level,
                    "level_int": _LEVEL_INT.get(level, 2),
                    "rule_title": f"Obfuscated .NET Assembly — {obfuscator}",
                    "computer": filename,
                    "details_raw": json.dumps(
                        {
                            "file": filename,
                            "obfuscator": obfuscator,
                            "deobfuscated": out_path.name if success else None,
                            "exit_code": proc.returncode,
                        }
                    ),
                    "message": (
                        f"{filename} — obfuscated with {obfuscator}; "
                        f"{'deobfuscated OK' if success else 'deobfuscation failed'}"
                    ),
                }
            )

        except subprocess.TimeoutExpired:
            print(f"[de4dot] timeout for {filename}", file=sys.stderr)
        except Exception as exc:
            print(f"[de4dot] error for {filename}: {exc}", file=sys.stderr)

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
