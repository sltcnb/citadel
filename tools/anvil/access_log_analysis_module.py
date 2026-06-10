import json
import os
import re
import sys
import uuid
from datetime import datetime

MODULE_NAME = "Access Log Analysis"
MODULE_DESCRIPTION = "Parse Apache/Nginx access logs for path traversal, scanner user-agents, brute force, admin probing, command injection, and high error rates."
INPUT_EXTENSIONS = [".log", ".txt", ".gz"]
INPUT_FILENAMES = ["access.log", "access_log", "error.log"]
ARTIFACT_TYPE = "access_log"

_LEVEL_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

# Standard combined log: IP - - [ts] "METHOD path PROTO" status size "ref" "ua"
# Also handles optional vhost prefix: VHOST IP - - [ts] ...
_ACCESS_LOG_RE = re.compile(
    r"(?:\S+\s+)?"  # optional vhost/port prefix
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # IPv4
    r"|[0-9a-fA-F:]{3,39})"  # or IPv6
    r"\s+\S+\s+\S+\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z-]+)\s+(?P<path>\S+)[^"]*"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_SCANNER_UAS = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|wfuzz|gobuster|burpsuite|nessus|openvas"
    r"|acunetix|w3af|nuclei|metasploit|zgrab|shodan|censys|internetmeasurement"
    r"|hydra|medusa|curl/|python-requests|go-http-client|libwww-perl|wget/"
    r"|whatweb|arachni|skipfish|zap|owasp|dirb|feroxbuster|ffuf|rustscan"
    r"|naabu|httpx|nuclei|caido|katana|gau|subfinder",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|%2e%2e|%252e|\.\.\\|%2f\.\.|/etc/passwd|/etc/shadow"
    r"|/proc/self|/windows/system32|/boot\.ini|/winnt/system32)",
    re.IGNORECASE,
)
_ADMIN_PATHS_RE = re.compile(
    r"(?:/wp-admin|/wp-login|/wp-config|/admin|/administrator|/phpmyadmin"
    r"|/\.env|/\.git/|/config\.php|/shell\.php|/cmd\.php|/webshell"
    r"|/manager/html|/jmx-console|/solr/admin|/actuator|/console"
    r"|/cgi-bin/|/xmlrpc\.php|/setup\.php|/install\.php)",
    re.IGNORECASE,
)
_CMD_INJECT_RE = re.compile(
    r"(?:;ls|;id|;cat\s|;wget|;curl|%7cid|%3bls|\$\(|\`cmd|union\s+select"
    r"|%7c|exec\(|system\(|passthru\(|eval\(|base64_decode)",
    re.IGNORECASE,
)
_WEBSHELL_RE = re.compile(
    r"(?:\.php\?[^=]+=|cmd=|exec=|shell=|payload=|c=|eval=|code=)",
    re.IGNORECASE,
)


def _parse_ts(ts_raw: str) -> str:
    for fmt in ("%d/%b/%Y:%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return datetime.strptime(ts_raw[:26].strip(), fmt).isoformat() + "Z"
        except ValueError:
            pass
    return ts_raw


def _legacy_run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir):
    bucket = os.getenv("MINIO_BUCKET", "forensics-cases")
    hits = []

    # Deduplicate by minio_key — same file may appear multiple times in source_files
    seen_keys: set[str] = set()
    unique_files = []
    for sf in source_files:
        key = sf.get("minio_key", "")
        if key and key not in seen_keys:
            seen_keys.add(key)
            unique_files.append(sf)

    for sf in unique_files:
        filename = sf.get("filename") or sf.get("minio_key", "file").split("/")[-1]
        minio_key = sf.get("minio_key", "")
        if not minio_key:
            continue

        local_path = tmp_dir / filename
        try:
            minio_client.fget_object(bucket, minio_key, str(local_path))
        except Exception as exc:
            print(f"[access_log_analysis] download failed for {filename}: {exc}", file=sys.stderr)
            continue

        print(f"[access_log_analysis] scanning {filename} …", file=sys.stderr)

        ip_stats: dict[str, dict] = {}  # ip → {4xx, 5xx, req, 404}
        auth_failures: dict[str, int] = {}  # ip → total 401 count across all paths
        parsed_lines = 0
        failed_lines = 0

        try:
            open_fn = __import__("gzip").open if filename.endswith(".gz") else open
            with open_fn(local_path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = _ACCESS_LOG_RE.search(line)
                    if not m:
                        failed_lines += 1
                        continue
                    parsed_lines += 1

                    ip = m.group("ip")
                    ts_raw = m.group("ts")
                    method = m.group("method")
                    path = m.group("path")
                    status = int(m.group("status"))
                    ua = m.group("ua") or ""
                    size = m.group("size") or "-"

                    try:
                        ts = _parse_ts(ts_raw)
                    except ValueError:
                        ts = ""

                    stat = ip_stats.setdefault(ip, {"4xx": 0, "5xx": 0, "req": 0, "404": 0})
                    stat["req"] += 1
                    if status == 404:
                        stat["404"] += 1
                    if 400 <= status < 500:
                        stat["4xx"] += 1
                    elif 500 <= status < 600:
                        stat["5xx"] += 1
                    if status == 401:
                        auth_failures[ip] = auth_failures.get(ip, 0) + 1

                    extra = {
                        "ip": ip,
                        "method": method,
                        "path": path[:256],
                        "status": status,
                        "ua": ua[:200],
                    }

                    if _PATH_TRAVERSAL_RE.search(path):
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "timestamp": ts,
                                "level": "high",
                                "level_int": 4,
                                "rule_title": "Path Traversal Attempt",
                                "computer": filename,
                                "details_raw": json.dumps(extra),
                                "message": f"{ip} → {method} {path[:200]} ({status})",
                            }
                        )

                    if _SCANNER_UAS.search(ua):
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "timestamp": ts,
                                "level": "high",
                                "level_int": 4,
                                "rule_title": "Known Scanner User-Agent",
                                "computer": filename,
                                "details_raw": json.dumps(extra),
                                "message": f"{ip} → Scanner: {ua[:100]}",
                            }
                        )

                    if _ADMIN_PATHS_RE.search(path):
                        level = "high" if status not in (200, 301, 302) else "low"
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "timestamp": ts,
                                "level": level,
                                "level_int": _LEVEL_INT[level],
                                "rule_title": "Admin/Sensitive Path Access",
                                "computer": filename,
                                "details_raw": json.dumps(extra),
                                "message": f"{ip} → {method} {path[:200]} ({status})",
                            }
                        )

                    if _CMD_INJECT_RE.search(path):
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "timestamp": ts,
                                "level": "critical",
                                "level_int": 5,
                                "rule_title": "Command Injection in URL",
                                "computer": filename,
                                "details_raw": json.dumps(extra),
                                "message": f"{ip} → Injection payload in {path[:200]}",
                            }
                        )

                    if method == "POST" and _WEBSHELL_RE.search(path):
                        hits.append(
                            {
                                "id": str(uuid.uuid4()),
                                "timestamp": ts,
                                "level": "critical",
                                "level_int": 5,
                                "rule_title": "Possible Web Shell Interaction",
                                "computer": filename,
                                "details_raw": json.dumps(extra),
                                "message": f"{ip} → POST to {path[:200]} ({status})",
                            }
                        )

        except Exception as exc:
            print(f"[access_log_analysis] error reading {filename}: {exc}", file=sys.stderr)
            continue

        if failed_lines > 0 and parsed_lines == 0:
            print(
                f"[access_log_analysis] WARNING: 0/{failed_lines} lines matched regex in {filename} — unexpected format?",
                file=sys.stderr,
            )
        elif failed_lines > 0:
            print(
                f"[access_log_analysis] {parsed_lines} lines parsed, {failed_lines} skipped in {filename}",
                file=sys.stderr,
            )

        # Per-IP aggregate detections
        for ip, count in auth_failures.items():
            if count >= 5:
                level = "critical" if count >= 50 else ("high" if count >= 20 else "medium")
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": level,
                        "level_int": _LEVEL_INT[level],
                        "rule_title": "Authentication Brute Force",
                        "computer": filename,
                        "details_raw": json.dumps({"ip": ip, "total_401_count": count}),
                        "message": f"{ip} → {count} total failed auth attempts",
                    }
                )

        for ip, stat in ip_stats.items():
            errors = stat["4xx"] + stat["5xx"]
            total = stat["req"]
            notfound = stat["404"]

            if total >= 30 and errors / total >= 0.5:
                level = "high" if errors >= 100 else "medium"
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": level,
                        "level_int": _LEVEL_INT[level],
                        "rule_title": "High Error Rate from Single IP",
                        "computer": filename,
                        "details_raw": json.dumps({"ip": ip, "requests": total, "errors": errors}),
                        "message": f"{ip} → {errors}/{total} error responses ({int(100 * errors / total)}%)",
                    }
                )

            if notfound >= 50:
                level = "high" if notfound >= 200 else "medium"
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": level,
                        "level_int": _LEVEL_INT[level],
                        "rule_title": "Directory Enumeration (404 Flood)",
                        "computer": filename,
                        "details_raw": json.dumps(
                            {"ip": ip, "total_requests": total, "not_found_404": notfound}
                        ),
                        "message": f"{ip} → {notfound} 404 responses ({total} total requests)",
                    }
                )

            if total >= 500:
                level = "medium" if total < 2000 else "high"
                hits.append(
                    {
                        "id": str(uuid.uuid4()),
                        "level": level,
                        "level_int": _LEVEL_INT[level],
                        "rule_title": "High Request Volume from Single IP",
                        "computer": filename,
                        "details_raw": json.dumps({"ip": ip, "requests": total}),
                        "message": f"{ip} → {total} requests (potential scanner/bot)",
                    }
                )

    print(f"[access_log_analysis] {len(hits)} findings", file=sys.stderr)
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
