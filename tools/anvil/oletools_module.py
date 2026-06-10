import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

MODULE_NAME = "Oletools — VBA / Macro Analysis"
MODULE_DESCRIPTION = "Analyse Office documents (doc, xls, ppt, rtf) for VBA macros using oletools. Detects suspicious keywords: shell execution, network downloads, registry writes."
INPUT_EXTENSIONS = [
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xla",
    ".xlam",
    ".ppt",
    ".pptx",
    ".pptm",
    ".rtf",
    ".mht",
]
INPUT_FILENAMES = []
ARTIFACT_TYPE = "oletools"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
_SUSPICIOUS_VBA = {
    "shell",
    "createobject",
    "wscript",
    "powershell",
    "cmd.exe",
    "regwrite",
    "environ",
    "shlobj",
    "dde",
    "autoopen",
    "autoclose",
    "document_open",
    "workbook_open",
    "auto_open",
    "auto_close",
    "download",
    "urldownloadtofile",
    "winexec",
    "shellexecute",
}
_OFFICE_EXTS = frozenset(
    {
        ".doc",
        ".docx",
        ".docm",
        ".dot",
        ".dotm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".xla",
        ".xlam",
        ".ppt",
        ".pptx",
        ".pptm",
        ".rtf",
        ".mht",
    }
)


def _run_cli(olevba_bin, local_path, filename):
    hits = []
    try:
        proc = subprocess.run(
            [olevba_bin, "--json", str(local_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                for item in data if isinstance(data, list) else [data]:
                    for macro in item.get("macros", []):
                        kw = macro.get("keyword", "")
                        level = "high" if kw.lower() in _SUSPICIOUS_VBA else "medium"
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "level": level,
                                "level_int": _LEVEL_INT.get(level, 1),
                                "rule_title": f"VBA Macro — {macro.get('type', 'unknown')}: {kw}",
                                "computer": filename,
                                "details_raw": macro.get("description", "")[:1000],
                                "filename": filename,
                                "vba_keyword": kw,
                            }
                        )
            except json.JSONDecodeError:
                if "VBA" in proc.stdout or "macro" in proc.stdout.lower():
                    hits.append(
                        {
                            "id": str(uuid.uuid4()),
                            "level": "medium",
                            "level_int": 3,
                            "rule_title": "VBA Macros Detected",
                            "computer": filename,
                            "details_raw": proc.stdout[:2000],
                            "filename": filename,
                        }
                    )
    except subprocess.TimeoutExpired:
        pass
    return hits


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    try:
        import oletools.olevba as _olevba

        _OT = True
    except ImportError:
        _OT = False

    if not _OT:
        olevba_bin = shutil.which("olevba") or shutil.which("olevba3")
        if not olevba_bin:
            return [
                {
                    "level": "informational",
                    "rule_title": "oletools not installed",
                    "description": "pip install oletools",
                }
            ]

    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []

    for sf in source_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key or Path(filename).suffix.lower() not in _OFFICE_EXTS:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[oletools] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[oletools] scanning {filename} …", file=sys.stderr)

        if not _OT:
            hits.extend(_run_cli(olevba_bin, local_path, filename))
            continue

        try:
            vba = _olevba.VBA_Parser(str(local_path))
            if vba.detect_vba_macros():
                for _, stream_path, vba_filename, vba_code in vba.extract_macros():
                    if not vba_code:
                        continue
                    for kw_type, keyword, description in vba.analyze_macros():
                        level = "high" if keyword.lower() in _SUSPICIOUS_VBA else "medium"
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "level": level,
                                "level_int": _LEVEL_INT.get(level, 1),
                                "rule_title": f"VBA Macro — {kw_type}: {keyword}",
                                "computer": filename,
                                "details_raw": description[:1000],
                                "filename": filename,
                                "vba_keyword": keyword,
                                "vba_type": kw_type,
                            }
                        )
                    hits.append(
                        {
                            "id": str(uuid.uuid4()),
                            "level": "medium",
                            "level_int": 3,
                            "rule_title": f"VBA Module: {vba_filename or stream_path}",
                            "computer": filename,
                            "details_raw": vba_code[:2000],
                            "filename": filename,
                            "stream_path": stream_path,
                        }
                    )
                print(f"[oletools]   VBA macros detected in {filename}", file=sys.stderr)
            else:
                print(f"[oletools]   no macros in {filename}", file=sys.stderr)
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": "informational",
                        "level_int": 1,
                        "rule_title": "No Macros Detected",
                        "computer": filename,
                        "details_raw": f"No VBA macros found in {filename}",
                        "filename": filename,
                    }
                )
        except Exception as exc:
            hits.append(
                {
                    "id": str(uuid.uuid4()),
                    "level": "medium",
                    "level_int": 3,
                    "rule_title": "Oletools Parse Error",
                    "computer": filename,
                    "details_raw": str(exc)[:500],
                    "filename": filename,
                }
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
