"""Sigil — ATT&CK coverage matrix.

Scans the rule corpus and emits a coverage matrix to ``coverage_matrix.md`` (and
``coverage_matrix.json``). Coverage is reported at **tactic** granularity, keyed
off each rule pack's ATT&CK tactic (native packs declare ``category``; sigma_hq
packs are named by tactic). Any explicit ATT&CK technique ids found in rule
bodies (``attack.tNNNN`` / ``Tnnnn``) are tallied as a technique sub-breakdown.

    python3 tools/sigil/sigil_coverage.py        # regenerate the matrix
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent
NON_RULE_FILES = {"sample_events"}

# ATT&CK enterprise tactics (id -> name), the canonical column order.
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
# Map the corpus's pack categories / filenames onto a tactic name.
_NAME_TO_TACTIC = {
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "privilege escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "defense evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "command_control": "Command and Control",
    "command_and_control": "Command and Control",
    "command and control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "initial_access": "Initial Access",
    "reconnaissance": "Reconnaissance",
    "authentication": "Credential Access",
    "anti_forensics": "Defense Evasion",
    # Themed native packs — mapped to their dominant tactic (matched by filename
    # stem when the human-readable category text doesn't normalise to a key).
    "ransomware": "Impact",
    "windows_lolbins": "Execution",
    "active_directory": "Credential Access",
    "linux_endpoint": "Persistence",
    "cloud_identity": "Credential Access",
    "edr_av_tampering": "Defense Evasion",
    "powershell_specific": "Execution",
    "enhanced_authentication": "Credential Access",
    "web_server": "Initial Access",
    "registry_forensics": "Persistence",
    "prefetch_analysis": "Execution",
    "lnk_analysis": "Execution",
    "zeek_analysis": "Command and Control",
    "sysmon_specific": "Execution",
}


def _tactic_for(category: str | None, filename: str) -> str:
    if category:
        key = category.strip().lower().replace("-", "_")
        if key in _NAME_TO_TACTIC:
            return _NAME_TO_TACTIC[key]
    stem = re.sub(r"^\d+_", "", Path(filename).stem).lower()
    return _NAME_TO_TACTIC.get(stem, "Uncategorized")


def build() -> dict:
    files = [p for p in sorted(RULES_DIR.glob("*.yaml")) if p.stem not in NON_RULE_FILES]
    files += sorted((RULES_DIR / "sigma_hq").glob("*.yaml"))
    by_tactic_native: Counter = Counter()
    by_tactic_sigma: Counter = Counter()
    techniques: Counter = Counter()
    tech_by_tactic: dict[str, set] = defaultdict(set)

    for f in files:
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        category = d.get("category") if isinstance(d, dict) else None
        rules = d.get("rules") if isinstance(d, dict) else d
        tactic = _tactic_for(category, f.name)
        for r in rules or []:
            if not isinstance(r, dict):
                continue
            if r.get("query"):
                by_tactic_native[tactic] += 1
            else:
                by_tactic_sigma[tactic] += 1
            for tid in re.findall(r"(?:attack\.)?[Tt](\d{4}(?:\.\d{3})?)", str(r)):
                techniques[f"T{tid}"] += 1
                tech_by_tactic[tactic].add(f"T{tid}")

    matrix = []
    for _tid, name in TACTICS:
        nat = by_tactic_native.get(name, 0)
        sig = by_tactic_sigma.get(name, 0)
        matrix.append(
            {
                "tactic": name,
                "native": nat,
                "sigma": sig,
                "total": nat + sig,
                "techniques": sorted(tech_by_tactic.get(name, [])),
            }
        )
    # any tactic buckets we didn't enumerate (e.g. Uncategorized)
    seen = {m["tactic"] for m in matrix}
    for name in set(by_tactic_native) | set(by_tactic_sigma):
        if name not in seen:
            matrix.append(
                {
                    "tactic": name,
                    "native": by_tactic_native.get(name, 0),
                    "sigma": by_tactic_sigma.get(name, 0),
                    "total": by_tactic_native.get(name, 0) + by_tactic_sigma.get(name, 0),
                    "techniques": sorted(tech_by_tactic.get(name, [])),
                }
            )
    return {
        "matrix": matrix,
        "totals": {
            "tactics_covered": sum(1 for m in matrix if m["total"] > 0),
            "tactics_total": len(TACTICS),
            "rules": sum(m["total"] for m in matrix),
            "techniques_tagged": len(techniques),
        },
    }


def render_md(data: dict) -> str:
    t = data["totals"]
    lines = [
        "# Sigil — ATT&CK Coverage Matrix",
        "",
        "_Auto-generated by `sigil_coverage.py`. Tactic-granular; technique counts",
        "reflect explicit ATT&CK ids present in rule bodies._",
        "",
        f"**Coverage:** {t['tactics_covered']}/{t['tactics_total']} ATT&CK tactics · "
        f"{t['rules']} rules · {t['techniques_tagged']} distinct techniques tagged.",
        "",
        "| Tactic | Native | Sigma | Total | Techniques tagged |",
        "|--------|-------:|------:|------:|-------------------|",
    ]
    for m in data["matrix"]:
        techs = ", ".join(m["techniques"]) if m["techniques"] else "—"
        lines.append(f"| {m['tactic']} | {m['native']} | {m['sigma']} | {m['total']} | {techs} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    data = build()
    (RULES_DIR / "coverage_matrix.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (RULES_DIR / "coverage_matrix.md").write_text(render_md(data), encoding="utf-8")
    t = data["totals"]
    print(
        f"Sigil coverage: {t['tactics_covered']}/{t['tactics_total']} tactics, "
        f"{t['rules']} rules -> coverage_matrix.md"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
