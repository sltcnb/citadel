"""Regression tests: module-run staging must never write outside the work dir.

A caller-controlled filename like "../../../../app/anvil/capa_module.py" was an
arbitrary file write on the processor (and RCE once the overwritten module
ran). Guards now live at three layers: API validation, worker staging
(_safe_source_dest) and the contracts helpers (safe_source_filename /
iter_local_files / wrap_legacy).
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "tools" / "sluice" / "worker"))
sys.path.insert(0, str(_ROOT / "tools" / "citadel_contracts"))

from citadel_contracts.module import safe_source_filename  # noqa: E402


class TestSafeSourceFilename:
    def test_plain_name_passthrough(self):
        assert safe_source_filename("mem.raw") == "mem.raw"

    def test_relative_subpath_preserved(self):
        # Zip entries keep their relative structure — legitimate.
        assert safe_source_filename("evidence/disk1/Security.evtx") == "evidence/disk1/Security.evtx"

    @pytest.mark.parametrize(
        "bad",
        [
            "../../../../app/anvil/capa_module.py",
            "..\\..\\windows\\system32\\x.dll",
            "/etc/cron.d/pwn",
            "/abs/path.py",
            "..",
            "",
            "a/../../b.py",
            "ok/\x00evil.py",
        ],
    )
    def test_unsafe_collapses_to_fallback(self, bad):
        assert safe_source_filename(bad, "fallback.bin") == "fallback.bin"

    def test_fallback_default(self):
        assert safe_source_filename("../x.py") == "file"


class TestWorkerStagingGuard:
    def test_safe_source_dest_contained(self):
        from tasks.module_task import _safe_source_dest

        base = Path("/tmp/work/sources")
        # The guard resolves both sides (macOS /tmp → /private/tmp symlink).
        assert _safe_source_dest(base, "a/b.txt") == base.resolve() / "a" / "b.txt"

    @pytest.mark.parametrize("bad", ["../../../../app/x.py", "/etc/x", "..\\..\\x.py", "a/../../b.py", "\x00.py"])
    def test_safe_source_dest_rejects(self, bad):
        from tasks.module_task import _safe_source_dest

        with pytest.raises(ValueError):
            _safe_source_dest(Path("/tmp/work/sources"), bad)
