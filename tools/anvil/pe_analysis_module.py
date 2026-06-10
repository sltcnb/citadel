import math
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

MODULE_NAME = "PE Analysis"
MODULE_DESCRIPTION = "Analyse PE executables with pefile — header info, compile timestamp, section entropy (packed/encrypted detection), suspicious imports."
INPUT_EXTENSIONS = [".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".cpl", ".com"]
INPUT_FILENAMES = []
ARTIFACT_TYPE = "pe_analysis"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
_ENTROPY_HIGH = 7.0
_ENTROPY_MED = 6.0
_SUSPICIOUS = {
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "openprocess",
    "ntunmapviewofsection",
    "rtldecompressbuffer",
    "rtlmovememory",
    "loadlibrarya",
    "loadlibraryexw",
    "getprocaddress",
    "createprocessw",
    "createprocessa",
    "shellexecutea",
    "shellexecutew",
    "winexec",
    "system",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "gettickcount",
    "sleep",
    "regsetvalueexa",
    "regcreatekeyexa",
    "internetopena",
    "internetconnecta",
    "httpopenrequesta",
    "wsastartup",
    "socket",
    "connect",
    "send",
    "recv",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    try:
        import pefile as _pefile
    except ImportError:
        return [
            {
                "level": "informational",
                "rule_title": "pefile not installed",
                "description": "pip install pefile",
            }
        ]

    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []

    for sf in source_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key or Path(filename).suffix.lower() not in {
            ".exe",
            ".dll",
            ".sys",
            ".ocx",
            ".scr",
            ".drv",
            ".cpl",
            ".com",
        }:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[pe_analysis] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[pe_analysis] analysing {filename} …", file=sys.stderr)
        try:
            pe = _pefile.PE(str(local_path), fast_load=False)
        except Exception as exc:
            hits.append(
                {
                    "id": str(uuid.uuid4()),
                    "level": "medium",
                    "level_int": 3,
                    "rule_title": "PE Parse Error",
                    "computer": filename,
                    "details_raw": str(exc)[:500],
                    "filename": filename,
                }
            )
            continue

        # Header
        try:
            machine = pe.FILE_HEADER.Machine
            num_sects = pe.FILE_HEADER.NumberOfSections
            ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
            compile_ts = datetime.fromtimestamp(ts, tz=UTC).isoformat() if ts else ""
            entry_pt = hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
            arch = "x86" if machine == 0x014C else ("x64" if machine == 0x8664 else hex(machine))
        except Exception:
            arch, num_sects, compile_ts, entry_pt = "unknown", 0, "", ""

        hits.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": compile_ts,
                "level": "informational",
                "level_int": 1,
                "rule_title": f"PE Header — {filename}",
                "computer": filename,
                "details_raw": (
                    f"Architecture: {arch}  |  Sections: {num_sects}  |  "
                    f"Compile time: {compile_ts or 'unknown'}  |  EP: {entry_pt}"
                ),
                "filename": filename,
                "pe_arch": arch,
            }
        )

        # Section entropy
        try:
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                data = section.get_data()
                ent = _entropy(data)
                level = (
                    "high"
                    if ent >= _ENTROPY_HIGH
                    else ("medium" if ent >= _ENTROPY_MED else "informational")
                )
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": level,
                        "level_int": _LEVEL_INT.get(level, 1),
                        "rule_title": f"Section Entropy — {name.strip() or '(unnamed)'}",
                        "computer": filename,
                        "details_raw": f"Entropy: {ent:.2f}  |  Size: {len(data):,} bytes",
                        "filename": filename,
                        "entropy": round(ent, 3),
                    }
                )
                if ent >= _ENTROPY_HIGH:
                    print(
                        f"[pe_analysis]   HIGH ENTROPY section {name}: {ent:.2f}", file=sys.stderr
                    )
        except Exception:
            pass

        # Suspicious imports
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                    for imp in entry.imports:
                        fn = (imp.name or b"").decode("utf-8", errors="replace")
                        if fn.lower() in _SUSPICIOUS:
                            hits.append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "level": "medium",
                                    "level_int": 3,
                                    "rule_title": f"Suspicious Import — {fn}",
                                    "computer": filename,
                                    "details_raw": f"{dll}::{fn}",
                                    "filename": filename,
                                    "import_dll": dll,
                                    "import_fn": fn,
                                }
                            )
        except Exception:
            pass

        pe.close()

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
