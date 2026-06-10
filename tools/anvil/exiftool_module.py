import json
import os
import shutil
import subprocess
import sys
import uuid

MODULE_NAME = "ExifTool"
MODULE_DESCRIPTION = "Extract metadata from files using ExifTool — timestamps, author, GPS, software, embedded macro indicators."
INPUT_EXTENSIONS = []
INPUT_FILENAMES = []
ARTIFACT_TYPE = "exiftool"

_INTERESTING_FIELDS = [
    "EXIF:Make",
    "EXIF:Model",
    "EXIF:GPSLatitude",
    "EXIF:GPSLongitude",
    "XMP:Subject",
    "XMP:Description",
    "PDF:Title",
    "PDF:Subject",
    "Office:LastModifiedBy",
    "Office:AppVersion",
    "File:MIMEType",
    "File:FileSize",
    "Composite:GPSPosition",
]

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    exiftool_bin = shutil.which("exiftool")
    if not exiftool_bin:
        return [
            {
                "level": "informational",
                "rule_title": "exiftool not installed",
                "description": "Install: apt-get install libimage-exiftool-perl",
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
            print(f"[exiftool] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[exiftool] scanning {filename} …", file=sys.stderr)
        try:
            proc = subprocess.run(
                [exiftool_bin, "-json", "-l", "-a", "-G1", str(local_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            print(f"[exiftool] timeout for {filename}", file=sys.stderr)
            continue

        if not proc.stdout.strip():
            continue
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        if not data or not isinstance(data, list):
            continue

        meta = data[0]

        ts = (
            meta.get("EXIF:DateTimeOriginal", {}).get("val")
            or meta.get("XMP:CreateDate", {}).get("val")
            or meta.get("QuickTime:CreateDate", {}).get("val")
            or meta.get("PDF:CreateDate", {}).get("val")
            or meta.get("File:FileModifyDate", {}).get("val")
            or ""
        )
        author = (
            meta.get("EXIF:Artist", {}).get("val")
            or meta.get("XMP:Creator", {}).get("val")
            or meta.get("PDF:Author", {}).get("val")
            or meta.get("Office:Author", {}).get("val")
            or ""
        )
        software = (
            meta.get("EXIF:Software", {}).get("val")
            or meta.get("XMP:CreatorTool", {}).get("val")
            or meta.get("PDF:Producer", {}).get("val")
            or ""
        )
        gps_lat = meta.get("EXIF:GPSLatitude", {}).get("val", "")
        gps_lon = meta.get("EXIF:GPSLongitude", {}).get("val", "")

        interesting = []
        for field in _INTERESTING_FIELDS:
            val_obj = meta.get(field, {})
            val = val_obj.get("val") if isinstance(val_obj, dict) else val_obj
            if val:
                interesting.append(f"{field.split(':')[1]}: {val}")

        details = " | ".join(interesting[:10]) if interesting else f"File: {filename}"
        has_macros = any("macro" in k.lower() or "vba" in k.lower() for k in meta)
        level = "medium" if has_macros else "informational"

        hits.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": ts,
                "level": level,
                "level_int": _LEVEL_INT[level],
                "rule_title": f"ExifTool: {filename}",
                "computer": author or "",
                "details_raw": details,
                "exiftool": {
                    "author": author,
                    "software": software,
                    "gps": f"{gps_lat}, {gps_lon}" if gps_lat and gps_lon else "",
                    "has_macros": has_macros,
                },
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
