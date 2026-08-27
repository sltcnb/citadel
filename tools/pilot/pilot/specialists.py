"""Specialist lenses for the Pilot agent.

One agent carrying every tool, every field hint and every playbook has a
predictable failure mode, and a real run showed it: on a case holding 45 syslog
events and nothing else, the agent spent 40 steps searching for browser history,
network connections and process execution that were never collected, then
concluded "inconclusive — no determinative evidence" at 40% confidence. The
honest answer was available at step 1 and is a different sentence entirely:
*the artifact types needed to answer this question are not in the case.*

That is what this module exists to make structural rather than hoped-for.

A :class:`Specialist` is a lens: a mandate, the artifact types it needs to do
its job, the tools it is allowed to use, and the domain knowledge that makes it
good at one thing. Before any of them runs, :func:`plan` compares what each
needs against what the case actually holds and splits them into:

  viable   — its evidence is present; run it
  blocked  — its evidence is absent; do NOT run it, and say what is missing

A blocked specialist is not a gap in the investigation. It is a finding: it
names the collection that has to happen before the question can be answered at
all, which is the recommendation an analyst actually needs.

Nothing here talks to Elasticsearch or the LLM. It is pure data plus selection
logic, so it is cheap to test and cannot break a run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Tools every specialist may use: reading what is already known, orienting in
# the data, and recording a conclusion. Withholding these would just make each
# specialist rediscover the case from scratch.
_COMMON_TOOLS: frozenset[str] = frozenset(
    {
        "search",
        "aggregate",
        "inspect",
        "findings",
        "save_finding",
        "time_window",
    }
)


@dataclass(frozen=True)
class Specialist:
    """One domain lens over a case.

    ``needs`` is the honest precondition: artifact types without which this
    specialist cannot produce evidence. It is deliberately a *set of
    alternatives* — persistence looks different on Windows (registry, services)
    and macOS (launchd plists), and either is enough to work.
    """

    id: str
    name: str
    mandate: str
    needs: frozenset[str]
    tools: frozenset[str]
    lens: str
    mitre: tuple[str, ...] = field(default=())

    def is_viable(self, present: frozenset[str]) -> bool:
        return bool(self.needs & present)

    def missing(self, present: frozenset[str]) -> list[str]:
        """Artifact types that would unblock this specialist, in a stable order."""
        return sorted(self.needs - present)


SPECIALISTS: tuple[Specialist, ...] = (
    Specialist(
        id="execution",
        name="Execution & process ancestry",
        mandate=(
            "Establish what ran, from what parent, with what command line, and "
            "in what order. Produce the process chain or state that it is absent."
        ),
        needs=frozenset(
            {
                "process",
                "evtx",
                "prefetch",
                "hayabusa",
                "shell_history",
                "macos_triage",
                "linux_triage",
                "auditd",
                "win_log",
            }
        ),
        tools=_COMMON_TOOLS
        | {"correlate", "stack_rare", "mitre_hits", "entity_graph"},
        lens=(
            "Anchor on the earliest suspicious execution, then walk BOTH ways: "
            "parent (how did it get here) and children (what did it do).\n"
            "Windows: evtx.event_data.Image, .CommandLine, .ParentImage, "
            ".ParentCommandLine, .ProcessGuid; Sysmon 1/3/7/11, Security 4688; "
            "prefetch for first/last run of a binary now deleted.\n"
            "Linux/macOS: process.command_line, process.path, shell_history for "
            "hands-on-keyboard, auditd EXECVE.\n"
            "stack_rare on process.name for the host is the fastest way to the "
            "one-off binary. A living-off-the-land chain (powershell, wscript, "
            "rundll32, curl, osascript) matters more than an unknown filename."
        ),
        mitre=("T1059", "T1204", "T1218", "T1106"),
    ),
    Specialist(
        id="persistence",
        name="Persistence & autostart",
        mandate=(
            "Determine whether the activity survives reboot, and by what "
            "mechanism. Name the mechanism and its payload, or state that no "
            "persistence is present in the data."
        ),
        needs=frozenset(
            {
                "persistence",
                "registry",
                "scheduled_task",
                "service",
                "plist",
                "cron_job",
                "startup_item",
                "macos_triage",
                "linux_triage",
                "evtx",
            }
        ),
        tools=_COMMON_TOOLS | {"stack_rare", "mitre_hits", "correlate"},
        lens=(
            "Persistence is a small, enumerable set — check it exhaustively "
            "rather than searching freely.\n"
            "Windows: Run/RunOnce keys, services (registry.key_path, 7045), "
            "scheduled tasks, WMI event subscriptions, startup folder.\n"
            "macOS: launchd jobs (artifact_type:persistence, kind=launchd) — the "
            "executable and its trigger; login items; the user_writable_path flag "
            "is the strongest single signal.\n"
            "Linux: systemd units and timers, cron, profile.d, XDG autostart.\n"
            "For each mechanism found, resolve the PAYLOAD path and cross-check it "
            "against what the execution lens saw run."
        ),
        mitre=("T1547", "T1053", "T1543", "T1546"),
    ),
    Specialist(
        id="network",
        name="Network, C2 & egress",
        mandate=(
            "Establish outbound contact: what talked to what, when, and whether "
            "any of it is known-bad. Produce the egress picture or state that no "
            "network evidence exists."
        ),
        needs=frozenset(
            {
                "network_conn",
                "pcap",
                "zeek",
                "suricata",
                "access_log",
                "firewall_log",
                "dns",
                "macos_uls",
                "netstat",
                "iptables",
                "browser",
            }
        ),
        tools=_COMMON_TOOLS
        | {"correlate", "stack_rare", "cti_seen_before", "watchlist", "entity_graph"},
        lens=(
            "Rare beats voluminous: aggregate destination IPs and domains, then "
            "work the tail, not the head. A single connection to one address is "
            "worth more than a thousand to a CDN.\n"
            "Tie every connection to its owning process where the data allows "
            "(macos_triage network_conn carries pid; Sysmon 3 carries Image).\n"
            "DNS resolution of a suspect domain is evidence of contact even when "
            "no connection followed. Run cti_seen_before on every external "
            "address surfaced — a prior case is the cheapest confirmation there is."
        ),
        mitre=("T1071", "T1041", "T1090", "T1568"),
    ),
    Specialist(
        id="identity",
        name="Identity, authentication & lateral movement",
        mandate=(
            "Establish which accounts were used where, whether any authentication "
            "is anomalous, and whether the activity spread. Produce the movement "
            "path or state that only one host is involved."
        ),
        needs=frozenset(
            {
                "evtx",
                "auth_log",
                "login_event",
                "logged_user",
                "utmp",
                "lastlog",
                "user_account",
                "macos_triage",
                "linux_triage",
                "okta_system_log",
                "azure_signin",
            }
        ),
        tools=_COMMON_TOOLS | {"entity_graph", "correlate", "mitre_hits", "stack_rare"},
        lens=(
            "entity_graph first — it answers 'did this spread' in one call, and "
            "the flat searches that substitute for it usually miss the second host.\n"
            "Windows: 4624 with logon type (3 network, 9 newcreds, 10 RDP), 4672 "
            "special privileges, 4768/4769 Kerberos, 4776 NTLM. A logon with no "
            "preceding 4625 failures and no 4768 for that account is the "
            "pass-the-hash shape.\n"
            "Unix/macOS: auth_log, login_event, logged_user — note remote source "
            "IPs.\n"
            "The finding is an account touching a host it has no history with."
        ),
        mitre=("T1078", "T1550", "T1021", "T1110"),
    ),
    Specialist(
        id="malware",
        name="Malware, IOCs & threat intel",
        mandate=(
            "Determine whether any artifact matches known-bad, and what the "
            "sample is. Produce identifications with their source, or state that "
            "nothing matched."
        ),
        needs=frozenset(
            {
                "yara",
                "antivirus",
                "module_finding",
                "cti_match",
                "hayabusa",
                "file",
                "binary_files",
                "wer",
                "browser",
                "installed_software",
            }
        ),
        tools=_COMMON_TOOLS
        | {
            "cti_seen_before",
            "watchlist",
            "module_runs",
            "list_modules",
            "launch_module",
            "read_module_result",
            "mitre_hits",
        },
        lens=(
            "Check module_runs BEFORE launching anything — the answer is often "
            "already computed and re-running burns the per-case launch budget.\n"
            "A run that is PENDING or RUNNING has NOT returned a negative result; "
            "treat its empty hit list as unknown, not as clean.\n"
            "Prefer hashes and signatures over filenames. An unsigned binary from "
            "a user-writable path, or an app whose provenance reads 'Unknown', is "
            "worth more than a suspicious name."
        ),
        mitre=("T1027", "T1105", "T1140", "T1588"),
    ),
    Specialist(
        id="timeline",
        name="Timeline & sequencing",
        mandate=(
            "Order the confirmed events into a defensible sequence and identify "
            "the earliest evidence of compromise. Produce the chain, marking any "
            "link the data does not support."
        ),
        # Any case with events at all can be sequenced; this lens is never
        # blocked on artifact type, only on there being events.
        needs=frozenset({"*"}),
        tools=_COMMON_TOOLS | {"correlate", "time_window", "entity_graph"},
        lens=(
            "Work from anchors that carry a trustworthy timestamp, and prefer "
            "artifact-native times over ingest times.\n"
            "State the first evidence of compromise explicitly, and say whether "
            "anything precedes it that the collection would not have captured — "
            "an earliest-evidence claim on a 7-day log export is bounded by the "
            "export, not by the intrusion.\n"
            "Where two events are close in time but causally unrelated, say so; "
            "adjacency is not causation and a timeline that implies it is wrong."
        ),
        mitre=(),
    ),
)

SPECIALISTS_BY_ID: dict[str, Specialist] = {s.id: s for s in SPECIALISTS}


@dataclass
class Plan:
    """Which lenses can run on this case, and which cannot and why."""

    viable: list[Specialist]
    blocked: list[tuple[Specialist, list[str]]]
    present: frozenset[str]

    @property
    def is_answerable(self) -> bool:
        """False when only the always-on lens survives.

        That is the shape of the run this module exists to prevent: nothing
        domain-specific can be examined, so the only honest output is a
        collection gap, not an inconclusive investigation.
        """
        return any(s.id != "timeline" for s in self.viable)


def plan(artifact_types, wanted: list[str] | None = None) -> Plan:
    """Split the specialists into viable and blocked for this case.

    *artifact_types* is whatever the case context reports as present.
    *wanted* optionally restricts to specific specialist ids (an analyst asking
    for one lens), unknown ids being ignored rather than raising — a bad id in
    a request should not fail the run.
    """
    present = frozenset(t for t in (artifact_types or []) if t)
    pool = SPECIALISTS
    if wanted:
        keep = {w.strip().lower() for w in wanted if w and w.strip()}
        selected = tuple(s for s in SPECIALISTS if s.id in keep)
        # An unrecognised selection would otherwise silently produce an empty
        # plan and a run that does nothing.
        pool = selected or SPECIALISTS

    viable: list[Specialist] = []
    blocked: list[tuple[Specialist, list[str]]] = []
    for s in pool:
        if "*" in s.needs or s.is_viable(present):
            viable.append(s)
        else:
            blocked.append((s, s.missing(present)))
    return Plan(viable=viable, blocked=blocked, present=present)


def plan_block(p: Plan) -> str:
    """Render the plan for injection into the lead agent's prompt."""
    lines = ["\nSpecialist plan for this case:"]
    for s in p.viable:
        lines.append(f"  [runs]    {s.id:12s} {s.mandate.splitlines()[0]}")
    for s, missing in p.blocked:
        shown = ", ".join(missing[:6]) + ("…" if len(missing) > 6 else "")
        lines.append(f"  [BLOCKED] {s.id:12s} needs artifact types not in this case: {shown}")
    if p.blocked:
        lines.append(
            "\n  A BLOCKED lens is a COLLECTION GAP, not a negative result. Do not "
            "search for its evidence — it is not here. Report what must be "
            "collected to answer that part of the question."
        )
    if not p.is_answerable:
        lines.append(
            "\n  WARNING — no domain lens is viable on this case. The artifact "
            "types required to confirm or refute the scenario were never "
            "collected. Establish what IS present, then conclude with the "
            "collection gap as the finding. Do NOT spend the step budget "
            "searching for artifacts that are absent, and do NOT report their "
            "absence as evidence of absence."
        )
    return "\n".join(lines) + "\n"


def specialist_prompt(s: Specialist, p: Plan) -> str:
    """The system-prompt fragment that turns the generic agent into this lens."""
    parts = [
        f"You are the {s.name} specialist on this investigation.",
        "",
        f"Mandate: {s.mandate}",
        "",
        "Domain guidance:",
        s.lens,
    ]
    if s.mitre:
        parts += ["", f"Relevant MITRE techniques: {', '.join(s.mitre)}"]
    parts += [
        "",
        "Stay inside your mandate. Another specialist covers each of the other "
        "domains, and duplicating their work wastes the shared step budget. If "
        "you surface something outside your lens, record it with save_finding "
        "and move on rather than chasing it.",
        "",
        "Report what your lens establishes, including a clean negative — "
        '"the persistence mechanisms were checked and none is present" is a '
        "result, and a different one from silence.",
    ]
    return "\n".join(parts) + "\n"


def coverage_summary(p: Plan) -> dict:
    """Machine-readable plan, for the run record and the UI."""
    return {
        "viable": [s.id for s in p.viable],
        "blocked": {s.id: missing for s, missing in p.blocked},
        "answerable": p.is_answerable,
        "artifact_types_present": sorted(p.present),
    }
