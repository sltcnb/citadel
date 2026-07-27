"""Pilot query strategy — funnel search, progressive broadening, field coverage.

Pure functions, no FastAPI / Redis / Elasticsearch imports, so the agent's search
strategy can actually be unit tested. ``service.py`` supplies the I/O (the ES
coverage probe) and calls in here for every decision.

The problem this module exists to solve
---------------------------------------
An LLM investigating a case reaches for the most specific query it can imagine,
because that is what looks competent. In forensics that is precisely wrong, for
a reason that has nothing to do with the model's reasoning: **artifact types
populate different fields.**

``process.command_line`` is filled in by Sysmon EVTX and essentially nothing
else. ``registry.key_path`` comes only from hives. MFT records carry no user.
Syslog has no ``evtx.*`` at all. So this query:

    host.hostname:WIN01 AND process.command_line:*psexec*

does not search the case. It searches the subset of the case that populates
``process.command_line``, and silently discards every syslog, MFT, prefetch and
browser event. The agent gets a plausible hit count computed over a fraction of
the evidence, and cannot tell the difference between:

    "this did not happen"        (a real finding)
    "I asked a field that this artifact type never fills in"   (a mistake)

Those support opposite conclusions. Absence of evidence is only evidence of
absence where the field exists — so every search needs to know which case it is
in, and an over-narrow query needs a way back up the funnel.
"""

from __future__ import annotations

import re

# A Lucene field constraint: `field:` or `dotted.field:`.
_QUERY_FIELD_RE = re.compile(r'(?:^|[\s(])([a-zA-Z_][\w]*(?:\.[\w]+)+|[a-zA-Z_]\w*)\s*:')

# Lucene operators / URI schemes that look like fields but are not.
NOT_FIELDS = frozenset({"and", "or", "not", "to", "http", "https", "ftp", "minio", "file"})

# Pivot keys whose sparseness is intentional and not worth warning about.
COVERAGE_EXEMPT = frozenset({"artifact_type", "timestamp", "fo_id", "source_file", "os"})

# Below this share of a case's events, a field cannot support a negative
# conclusion. Deliberately generous — genuinely sparse fields sit far lower.
SPARSE_FRACTION = 0.25

# Upper bound on a broadened result that is still readable as evidence. Above
# it the sample is just the top of a wildcard scan and tells the agent nothing.
USABLE_HIT_CEILING = 5000


def query_fields(*queries: str) -> list[str]:
    """Field names a Lucene query constrains, in order of first appearance.

    Quoted regions are blanked first, so a value containing a colon
    (``message:"GET http://host/x"``) does not register ``http`` as a field.
    """
    out: list[str] = []
    for q in queries:
        if not q:
            continue
        stripped = re.sub(r'"[^"]*"', '""', str(q))
        for m in _QUERY_FIELD_RE.finditer(stripped):
            name = m.group(1)
            if name.lower() in NOT_FIELDS or name in out:
                continue
            out.append(name)
    return out


def auto_broaden(query: str) -> str | None:
    """One step broader, or None if *query* is already as broad as this can make it.

    Strategies, in order:
      1. Drop the last (most specific) top-level ``AND`` clause.
      2. Turn an exact ``field:"value"`` into ``field:*value*``.
    """
    if not query:
        return None
    q = query.strip()

    # Split on top-level " AND ", respecting quotes and parentheses.
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    in_quote = False
    for ch in q:
        if ch == '"' and (not buf or buf[-1] != "\\"):
            in_quote = not in_quote
        if not in_quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        buf.append(ch)
        if not in_quote and depth == 0 and "".join(buf).endswith(" AND "):
            parts.append("".join(buf)[:-5])
            buf = []
    parts.append("".join(buf))
    parts = [p.strip() for p in parts if p.strip()]
    if len(parts) >= 2:
        return " AND ".join(parts[:-1])

    broadened = re.sub(r'(\b[\w\.]+):"([^"]+)"', r"\1:*\2*", q)
    if broadened != q:
        return broadened
    return None


def broaden_ladder(query: str, max_rungs: int = 4) -> list[str]:
    """Successively broader rewrites of *query*, broadest last.

    A single broadening step is not enough: a query three clauses too narrow
    still comes back empty, and the agent burns a turn rediscovering that.
    Recovering from over-narrowing means walking back up the funnel:

        host:X AND user:Y AND process.command_line:"psexec.exe"   (0 hits)
        host:X AND user:Y
        host:X
        message:*psexec.exe*

    The final rung matters most. It abandons the field constraint and searches
    the distinctive literal in ``message``, which every event carries — so it is
    the only rung that can reach evidence living in artifact types that never
    populate the field the agent originally chose.
    """
    rungs: list[str] = []
    cur = (query or "").strip()
    seen = {cur}
    for _ in range(max_rungs):
        nxt = auto_broaden(cur)
        if not nxt or nxt in seen:
            break
        rungs.append(nxt)
        seen.add(nxt)
        cur = nxt

    literals = re.findall(r'"([^"]{4,80})"', query or "")
    if not literals:
        # No quoted phrase — fall back to the longest non-numeric bareword,
        # with field names stripped out so we don't search for "host.hostname".
        literals = [
            t
            for t in re.findall(r"[\w\.\-\\/]{6,80}", re.sub(r"\b[\w.]+\s*:", " ", query or ""))
            if not t.replace(".", "").isdigit()
        ]
    if literals:
        literal = max(literals, key=len).strip("*")
        free = f"message:*{literal}*"
        if free not in seen:
            rungs.append(free)
    return rungs


def coverage_warning(fields: list[str], coverage: dict, total_events: int) -> str | None:
    """Warning for a query whose fields cannot see the whole case.

    *coverage* is ``{field: {"docs", "fraction", "types", "missing_types"}}`` as
    produced by the ES probe in ``service.py``.

    Phrased around the distinction that changes a conclusion: those events are
    **excluded**, not **absent**. Emitted regardless of hit count — a query
    returning 40 events while structurally ignoring 95% of the corpus is more
    dangerous than one returning none, because it reads as an answer.
    """
    if not fields or not coverage or not total_events:
        return None

    all_types = ((coverage.get("__total__") or {}).get("types")) or []
    warnings: list[str] = []
    for fname in fields:
        info = coverage.get(fname)
        if not info:
            continue
        docs = info.get("docs", 0)
        if docs == 0:
            warnings.append(
                f"'{fname}' is populated by NO event in this case — any clause using it "
                f"matches nothing, so this query can only ever return 0 hits. "
                f"Artifact types present: {', '.join(all_types[:12]) or 'unknown'}."
            )
            continue
        fraction = info.get("fraction", 0.0)
        if fraction < SPARSE_FRACTION:
            types = info.get("types") or []
            missing = info.get("missing_types") or []
            warnings.append(
                f"'{fname}' exists in only {docs:,} of {total_events:,} events "
                f"({fraction * 100:.1f}%), populated by {', '.join(types[:6])}"
                + (f" (+{len(types) - 6} more)" if len(types) > 6 else "")
                + ". Constraining on it EXCLUDES "
                + (", ".join(missing[:6]) if missing else "nothing")
                + (f" (+{len(missing) - 6} more)" if len(missing) > 6 else "")
                + " by construction — those events are excluded, not absent. Do not read "
                "this result as evidence they contain nothing; re-check with a field they "
                "populate (or `message:`, which every event has) before concluding."
            )
    if not warnings:
        return None
    return "FIELD COVERAGE: " + " | ".join(warnings)
