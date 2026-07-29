"""Field-name help for the autopilot: what exists, and what the agent got wrong.

Two problems, both of which show up as the agent burning steps on queries that
cannot match.

1. The prompt hands over the case's field list under the heading
   "Full field list (use ONLY these — dotted, no aliases)" and truncates it with
   ``', '.join(fields)[:3500]``. That slices the JOINED STRING, not the list, so
   on a real case the list is both incomplete and corrupt: a full Windows triage
   indexes ~229 fields (~5,050 chars), which drops 90 of them and leaves the
   final entry cut mid-name. The ordering is alphabetical, so what gets dropped
   is whatever sorts late — ``registry.*``, ``user.*``, ``zeek.*`` disappear
   wholesale while ``browser.*`` and ``evtx.event_data.A…`` survive. The agent is
   then told to use ONLY that list. This module builds the list so that it is
   truncated at a field boundary, ordered by how populated each field actually
   is, and states how many were omitted — so "use ONLY these" stops being a lie.

2. When a query returns nothing, the agent cannot tell "no such events" from
   "no such field". The prompt asks it to infer this ("if a field:value query
   returns 0 twice, the FIELD is probably wrong"), which costs at least two
   steps and often more. The field set is known, so the tool can just say which
   token is not a field and what the near misses are.

Pure: stdlib only, no Elasticsearch, no LLM, so both behaviours are unit-testable.
"""

from __future__ import annotations

import re

# Lucene/KQL structural tokens that look like `name:` but are not fields.
_NOT_FIELDS = {"and", "or", "not", "to", "true", "false"}

# `field:` at a clause position. Excludes anything inside quotes by consuming
# quoted runs first (see _strip_quoted).
_FIELD_TOKEN = re.compile(r"(?:^|[\s(+\-!])([a-zA-Z_][a-zA-Z0-9_.]*)\s*:")

_QUOTED = re.compile(r'"[^"]*"')
# A Lucene regexp literal — /…/ — may contain colons that are not field separators.
_REGEXP = re.compile(r"/(?:[^/\\]|\\.)*/")


def _strip_quoted(query: str) -> str:
    """Blank out quoted strings and regexp literals so their contents are not
    mistaken for `field:value` pairs (``message:"a:b"`` has one field, not two)."""
    return _REGEXP.sub(" ", _QUOTED.sub(" ", query))


def query_fields(query: str) -> list[str]:
    """Distinct field names a Lucene query references, in first-seen order."""
    out: list[str] = []
    for name in _FIELD_TOKEN.findall(_strip_quoted(query or "")):
        if name.lower() in _NOT_FIELDS:
            continue
        if name not in out:
            out.append(name)
    return out


def _base(field: str) -> str:
    """Strip the subfield suffixes that are not part of the mapped name."""
    for suffix in (".keyword", ".ci"):
        if field.endswith(suffix):
            return field[: -len(suffix)]
    return field


def near_misses(field: str, known: set[str], limit: int = 4) -> list[str]:
    """Real fields most likely to be what *field* was meant to say.

    Ranked by cheap, explainable signals rather than a similarity library:
    an exact leaf-name match in another namespace first (``dest_port`` →
    ``network.dst_port``), then shared prefix, then substring, then leaf-name
    edit proximity. No fuzzy scoring the caller cannot reason about.
    """
    field = _base(field)
    if not field or not known:
        return []
    leaf = field.rsplit(".", 1)[-1].lower()
    head = field.split(".", 1)[0].lower()
    scored: list[tuple[int, int, str]] = []
    for cand in known:
        c_leaf = cand.rsplit(".", 1)[-1].lower()
        c_head = cand.split(".", 1)[0].lower()
        if cand == field:
            continue
        score = 0
        if c_leaf == leaf:
            score = 100                              # same leaf, wrong namespace
        elif c_head == head and _close(c_leaf, leaf):
            score = 80                               # right namespace, near leaf
        elif c_head == head:
            score = 40                               # right namespace
        elif leaf and (leaf in c_leaf or c_leaf in leaf):
            score = 30                               # leaf substring either way
        elif _close(c_leaf, leaf):
            score = 20
        if score:
            scored.append((-score, len(cand), cand))
    scored.sort()
    return [c for _, _, c in scored[:limit]]


def _close(a: str, b: str) -> bool:
    """True when two leaf names are within one edit — catches the common typo and
    the singular/plural or underscore slip (``last_run`` vs ``last_run_times``
    is NOT close, which is correct: those are different fields)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b, strict=True) if x != y) == 1
    short, long = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long)):
        if long[:i] + long[i + 1:] == short:
            return True
    return False


def unknown_fields(query: str, known: set[str]) -> list[tuple[str, list[str]]]:
    """Fields in *query* that the case does not have, each with near misses.

    ``.keyword`` / ``.ci`` subfields resolve to their parent: those are created by
    the mapping, not listed as separate fields, so flagging them would be a false
    alarm — the kind of wrong correction that is worse than none.
    """
    if not known:
        return []          # unknown field set: cannot judge, so do not accuse
    out: list[tuple[str, list[str]]] = []
    for field in query_fields(query):
        if _base(field) in known or field in known:
            continue
        out.append((field, near_misses(field, known)))
    return out


def unknown_field_hint(query: str, known: set[str]) -> str:
    """One line for the agent's step result, or "" when every field is real."""
    unknown = unknown_fields(query, known)
    if not unknown:
        return ""
    parts = []
    for field, suggestions in unknown:
        if suggestions:
            parts.append(f"{field!r} does not exist — did you mean {', '.join(suggestions)}?")
        else:
            parts.append(f"{field!r} does not exist in this case")
    return (
        "FIELD ERROR (this is why there are 0 hits, not an absence of evidence): "
        + "; ".join(parts)
    )


def prompt_field_list(
    searchable: list[str],
    density: list[dict] | None = None,
    budget: int = 3500,
) -> tuple[str, int, int]:
    """Return ``(text, shown, total)`` — the field list for the agent's prompt.

    * Ordered by population (``density``) first, so if anything is dropped it is
      the fields with no data rather than whatever sorts last alphabetically.
    * Truncated at a field boundary — never mid-name.
    * ``shown``/``total`` let the caller state the omission instead of implying
      the list is complete.
    """
    total = len(searchable)
    if not searchable:
        return "", 0, 0
    dense = [d["field"] for d in (density or []) if d.get("field") and d.get("count")]
    ordered = [f for f in dense if f in searchable]
    ordered += [f for f in searchable if f not in set(ordered)]

    kept: list[str] = []
    used = 0
    for field in ordered:
        cost = len(field) + (2 if kept else 0)   # ", " separator
        if used + cost > budget:
            break
        kept.append(field)
        used += cost
    return ", ".join(kept), len(kept), total
