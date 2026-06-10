#!/usr/bin/env python3
"""A tiny offline evaluator for Citadel-native rule queries.

In production a native rule's ``query`` is handed to Elasticsearch as a
``query_string`` and matched there. For CI we cannot stand up ES, so this
module re-implements the *subset* of Lucene syntax the native rule pack
actually uses — ``field:value``, ``field:*glob*``, ``AND`` / ``OR`` / ``NOT``,
and parentheses — so a rule can be matched against the sample_events corpus
in a unit test.

This is intentionally a small, dependency-free subset, used only to prove the
corpus exercises the rules; ES remains the source of truth at runtime.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lpar>\() |
        (?P<rpar>\)) |
        (?P<op>AND|OR|NOT)\b |
        (?P<term>(?:"[^"]*"|[^\s()]+))
    )""",
    re.VERBOSE,
)


def _get_field(event: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted ECS path (``host.name``) into nested dicts."""
    cur: Any = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_value(value: Any, pattern: str) -> bool:
    pattern = pattern.strip()
    if len(pattern) >= 2 and pattern[0] == '"' and pattern[-1] == '"':
        pattern = pattern[1:-1]
    if value is None:
        return False
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return re.search(regex, str(value), re.IGNORECASE) is not None
    return str(value).lower() == pattern.lower()


def _eval_term(event: dict[str, Any], term: str) -> bool:
    if ":" in term:
        field, _, val = term.partition(":")
        target = _get_field(event, field)
        # Fall back to scanning the whole message for bare globs on `message`.
        return _match_value(target, val)
    # bare term → substring match across the flattened message
    msg = str(event.get("message", ""))
    return term.strip('"').lower() in msg.lower()


def _tokenize(query: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(query):
        m = _TOKEN_RE.match(query, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.lastgroup == "lpar":
            tokens.append(("lpar", "("))
        elif m.lastgroup == "rpar":
            tokens.append(("rpar", ")"))
        elif m.lastgroup == "op":
            tokens.append(("op", m.group("op")))
        elif m.lastgroup == "term":
            tokens.append(("term", m.group("term")))
    return tokens


class _Parser:
    """Recursive-descent parser: OR > AND > NOT > primary."""

    def __init__(self, tokens: list[tuple[str, str]], event: dict[str, Any]):
        self.tokens = tokens
        self.i = 0
        self.event = event

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _advance(self) -> tuple[str, str]:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        val = self._and()
        while (t := self._peek()) and t == ("op", "OR"):
            self._advance()
            rhs = self._and()
            val = val or rhs
        return val

    def _and(self) -> bool:
        val = self._not()
        while (t := self._peek()) and (t == ("op", "AND") or t[0] in ("term", "lpar")):
            if t == ("op", "AND"):
                self._advance()
            rhs = self._not()
            val = val and rhs
        return val

    def _not(self) -> bool:
        if (t := self._peek()) and t == ("op", "NOT"):
            self._advance()
            return not self._not()
        return self._primary()

    def _primary(self) -> bool:
        t = self._peek()
        if t is None:
            return True
        if t[0] == "lpar":
            self._advance()
            val = self._or()
            if (n := self._peek()) and n[0] == "rpar":
                self._advance()
            return val
        if t[0] == "term":
            self._advance()
            return _eval_term(self.event, t[1])
        # stray operator/rpar — stop
        return False


def query_matches(query: str, event: dict[str, Any]) -> bool:
    """True if a Lucene-subset *query* matches an ECS *event* dict."""
    tokens = _tokenize(query)
    if not tokens:
        return False
    return _Parser(tokens, event).parse()


def rule_fires(rule: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, int]:
    """Evaluate a native rule against an event list.

    Returns ``(fired, match_count)`` where *fired* is ``count >= threshold``.
    """
    query = rule.get("query")
    if not isinstance(query, str):
        raise ValueError("rule_fires only supports native (query) rules")
    count = sum(1 for e in events if query_matches(query, e))
    return count >= int(rule.get("threshold", 1)), count
