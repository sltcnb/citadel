"""Pilot investigation playbooks — targeted procedures injected into the agent
prompt when the analyst's scenario matches a known investigation type.

A playbook is not a script; it is the checklist a senior DFIR analyst would
run, expressed in the agent's own tools. It keeps runs from wandering into
open-ended searching on million-event cases and from concluding "no evidence"
after a handful of generic queries.

Each entry: trigger keywords (matched case-insensitively against the
circumstance) + the procedure text. `_select_playbook` returns the best
match or None (no injection then — the generic flow applies).
"""

from __future__ import annotations

PLAYBOOKS: list[dict] = [
    {
        "name": "lateral-movement / pass-the-hash / overpass-the-hash",
        "keywords": [
            "overpass", "overpass-the-hash", "pass-the-hash", "pth", "t1550",
            "lateral movement", "lateral", "kerberoast", "as-rep", "golden ticket",
        ],
        "procedure": """\
Playbook — suspected credential-based lateral movement:
1. Anchor the alert: inspect the detection's source event (channel+record_id
   via the Source Event flow). Note the exact timestamp, host, account.
2. `time_window` ±15 min around it on the host: look for 4624 type 3/9/10
   logons, 4672 special privileges, 4768/4769/4770/4771/4776 Kerberos/NTLM
   events. A PTH shows as a logon with NO corresponding 4625 password
   failures and often a fresh ticket without a prior 4768 from that account.
3. `entity_graph` focus=<host> — which OTHER hosts did the account touch?
   Lateral movement = the same account authenticating to hosts it never
   used before. Aggregate logons per (user, host) pair across the case.
4. `stack_rare` on process.name / service names for the host — what ran
   right after the suspect logon.
5. Cross-case: `cti_seen_before` on any new IP/host surfaced.
6. Conclude with the exact movement path (or its absence) — host A → host B
   with account X at time T, or state that no second host shows the account.""",
    },
    {
        "name": "infostealer / malware triage",
        "keywords": [
            "infostealer", "stealer", "lumma", "remus", "vidar", "redline",
            "exfil", "credential theft", "browser", "cookie", "malware",
        ],
        "procedure": """\
Playbook — suspected infostealer on a workstation:
1. Establish the execution chain: parent → child processes around the
   reported time (`search` on process.executable_name, process.command_line;
   `stack_rare` process.name on the host).
2. Persistence: registry run keys, services, scheduled tasks
   (`mitre_hits` T1547/T1053, `stack_rare` on registry.key_path).
3. Theft staging: archive creation in user dirs, reads of browser profile
   paths (Login Data, Cookies, *.sqlite under AppData), clipboard/screen
   capture (`mitre_hits` T1113/T1115/T1555).
4. Egress: network connections from the loader process to rare external IPs
   (aggregate network.dst_ip, check `cti_seen_before` on each).
5. If browser artifacts are ingested, run/refresh the browser_report module.
6. Conclude with the chain: delivery → execution → persistence → theft → C2,
   with fo_ids for each link; mark links not present in the data as MISSING.""",
    },
    {
        "name": "brute force / password spray",
        "keywords": [
            "brute force", "password spray", "spray", "failed logon", "4625",
            "credential stuffing",
        ],
        "procedure": """\
Playbook — authentication attack (brute force vs spray):
1. `aggregate` user.name and network.src_ip on 4625 events: one source → many
   accounts = spray; many sources → one account = stuffing; one-to-one = brute.
2. Timing: `time_window` the burst start/end; spray cadence is slow-and-wide.
3. Success check: any 4624/4627/4672 from a sprayed account AFTER the burst —
   that is the compromise, not the noise.
4. Whitelist first: own infra / helpdesk sources belong in the case whitelist
   (check `watchlist`/whitelist context before calling it an attack).
5. Conclude with source(s), targeted accounts, outcome (breached or not).""",
    },
    {
        "name": "data exfiltration",
        "keywords": ["exfiltration", "exfil", "data theft", "upload", "leak"],
        "procedure": """\
Playbook — suspected exfiltration:
1. Volume: `aggregate` network.bytes per dst_ip/host; an exfil host stands out.
2. Destination: rare external IPs/domains (`stack_rare` network.dst_ip) and
   `cti_seen_before` on each.
3. Staging: archive tools (rar/7z/tar/zip) in process.command_line, mass file
   reads in short windows.
4. Channels: DNS length spikes, uncommon ports, cloud storage domains.
5. Conclude with volume + destination + window, or a defensible 'no egress
   anomaly in the ingested data'.""",
    },
]


def _select_playbook(circumstance: str) -> dict | None:
    """Best-matching playbook for the analyst's scenario, or None."""
    text = (circumstance or "").lower()
    best = None
    best_hits = 0
    for pb in PLAYBOOKS:
        hits = sum(1 for kw in pb["keywords"] if kw in text)
        if hits > best_hits:
            best = pb
            best_hits = hits
    return best
