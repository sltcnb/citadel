"""cti_match must not present the analyst's own estate as threat intel.

Mirrors api/routers/test_cti_internal.py for the worker-side classifier: both
call sites derive internal/non-routable status from the IOC value instead of
trusting the ``is_private`` flag written at ingest time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("celery")

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_TASKS_DIR = _WORKER_ROOT / "tasks"
_TOOLS_DIR = _WORKER_ROOT.parents[1]  # tools/sluice/worker -> tools/

for _p in (str(_WORKER_ROOT), str(_TASKS_DIR), str(_TOOLS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import module_task as mt
except ModuleNotFoundError:
    pytest.skip("module_task's hard dependency chain is unavailable", allow_module_level=True)


INTERNAL_IPS = [
    "10.0.0.9",
    "172.16.4.1",
    "192.168.1.1",
    "127.0.0.1",
    "169.254.169.254",
    "100.64.0.1",
    "224.0.0.1",
    "::1",
    "fe80::1",
]

EXTERNAL_IPS = ["8.8.8.8", "213.36.7.14", "172.32.0.1", "100.128.0.1", "2606:4700::1111"]


@pytest.mark.parametrize("value", INTERNAL_IPS)
def test_internal_ips_are_internal(value):
    assert mt._cti_ip_is_internal(value) is True
    assert mt._cti_is_internal("ip", value) is True


@pytest.mark.parametrize("value", EXTERNAL_IPS)
def test_routable_ips_are_not_internal(value):
    assert mt._cti_ip_is_internal(value) is False
    assert mt._cti_is_internal("ip", value) is False


@pytest.mark.parametrize("value", ["localhost", "dc01.corp", "printer.local", "svc.internal"])
def test_internal_hostnames(value):
    assert mt._cti_is_internal("domain", value) is True


@pytest.mark.parametrize("value", ["evil.com", "cdn.example.org"])
def test_public_domains(value):
    assert mt._cti_is_internal("domain", value) is False


@pytest.mark.parametrize("value", ["", "   ", "not-an-ip", None])
def test_malformed_values_do_not_raise(value):
    assert mt._cti_is_internal("ip", value) is False


def test_hash_and_url_types_are_untouched():
    assert mt._cti_is_internal("hash", "d41d8cd98f00b204e9800998ecf8427e") is False
    assert mt._cti_is_internal("url", "http://10.0.0.1/payload") is False
