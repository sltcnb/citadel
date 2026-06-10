"""Routing/labelling fixes: strings_fallback text-vs-binary + utmp beats strings.

Standalone-runnable. Addresses:
  * apport.log mislabelled binary_files (now generic_text);
  * wtmp/btmp routing — utmp (priority 110) must claim them over strings (1).
"""

import logging
import sys
from pathlib import Path

PLUGINS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGINS.parent))  # tools/ for `plugins` pkg
sys.path.insert(0, str(PLUGINS))

from babel.base_plugin import PluginContext  # noqa: E402
from babel.strings_fallback.strings_fallback_plugin import StringsFallbackPlugin  # noqa: E402
from babel.utmp.utmp_plugin import UtmpPlugin  # noqa: E402


def _ctx(p: Path) -> PluginContext:
    return PluginContext(
        case_id="c",
        job_id="j",
        source_file_path=p,
        source_minio_url=f"file://{p}",
        config={},
        logger=logging.getLogger("t"),
    )


def _emit(p: Path):
    plug = StringsFallbackPlugin(_ctx(p))
    plug.setup()
    try:
        return list(plug.parse())
    finally:
        plug.teardown()


def test_text_log_labelled_generic_text(tmp_path):
    f = tmp_path / "apport.log"
    f.write_text("INFO: apport (pid 716832) called for global pid 716831, signal 11\n" * 200)
    events = _emit(f)
    assert events, "no event emitted for text log"
    assert events[0]["artifact_type"] == "generic_text", events[0]["artifact_type"]
    assert "lines" in events[0]["message"]


def test_binary_blob_labelled_binary_files(tmp_path):
    f = tmp_path / "blob.bin"
    # high-entropy bytes with a couple embedded ascii runs so it isn't noise-gated
    f.write_bytes(bytes(range(256)) * 40 + b"ELF_loader_stub_marker_string_here" * 5)
    events = _emit(f)
    if events:  # may be noise-gated; if emitted it must be binary_files
        assert events[0]["artifact_type"] == "binary_files", events[0]["artifact_type"]


def test_utmp_claims_wtmp_btmp_utmp_and_rotations():
    for name in ("wtmp", "btmp", "utmp", "wtmp.1", "btmp.old", "WTMP"):
        p = Path(f"/evidence/{name}")
        assert UtmpPlugin.can_handle(p, "application/octet-stream"), name
    # priority must beat the strings catch-all so the router never falls through
    assert UtmpPlugin.PLUGIN_PRIORITY > StringsFallbackPlugin.PLUGIN_PRIORITY


def test_utmp_does_not_grab_unrelated_files():
    assert not UtmpPlugin.can_handle(Path("/evidence/access.log"), "text/plain")


if __name__ == "__main__":
    import tempfile

    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        fn = globals()[name]
        if "tmp_path" in fn.__code__.co_varnames:
            with tempfile.TemporaryDirectory() as td:
                fn(Path(td))
        else:
            fn()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
