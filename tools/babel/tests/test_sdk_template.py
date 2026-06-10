"""SDK tests: every manifest has a semver, and the cookiecutter template
scaffolds a loadable, working parser. Offline; standalone-runnable.
"""

import json
import re
import sys
import tempfile
from pathlib import Path

PLUGINS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGINS))

_SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def _manifests():
    return sorted(PLUGINS.glob("*/manifest.yaml"))


def test_all_manifests_declare_semver():
    import yaml

    bad = []
    for m in _manifests():
        d = yaml.safe_load(m.read_text())
        v = str(d.get("version", "")).strip().strip('"')
        if not _SEMVER.match(v):
            bad.append(f"{m.parent.name}: version={v!r}")
    assert not bad, f"manifests without semver: {bad}"


def _render_template(dest: Path) -> Path:
    tpl = PLUGINS / "template"
    cfg = json.loads((tpl / "cookiecutter.json").read_text())
    ctx = {
        **cfg,
        "parser_name": "scaffoldtest",
        "artifact_type": "scaffold_evt",
        "extension": ".sct",
    }

    def sub(text: str) -> str:
        for k, v in ctx.items():
            text = text.replace("{{cookiecutter.%s}}" % k, str(v))
            text = text.replace("{{ cookiecutter.%s }}" % k, str(v))
        return text

    src_dir = tpl / "{{cookiecutter.parser_name}}"
    out = dest / ctx["parser_name"]
    out.mkdir(parents=True)
    for f in src_dir.iterdir():
        target = out / sub(f.name)
        target.write_text(sub(f.read_text()), encoding="utf-8")
    return out


def test_template_scaffolds_loadable_parser():
    import importlib.util

    import yaml

    with tempfile.TemporaryDirectory() as td:
        out = _render_template(Path(td))
        # manifest renders with semver + chosen artifact type
        man = yaml.safe_load((out / "manifest.yaml").read_text())
        assert man["id"] == "scaffoldtest"
        assert _SEMVER.match(str(man["version"]).strip('"'))
        assert man["artifact_type"] == "scaffold_evt"
        # generated plugin imports + parses
        sys.path.insert(0, str(out))
        spec = importlib.util.spec_from_file_location(
            "scaffoldtest_plugin", out / "scaffoldtest_plugin.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        from base_plugin import PluginContext

        sample = out / "sample.sct"
        sample.write_text("alpha\nbeta\n")
        ctx = PluginContext(case_id="c", job_id="j", source_file_path=sample, source_minio_url="")
        plugin_cls = mod.scaffoldtestPlugin
        assert plugin_cls.can_handle(sample, "text/plain")
        events = list(plugin_cls(ctx).parse())
        assert len(events) == 2
        assert all(e["timestamp"] and e["message"] for e in events)
        assert all(e["artifact_type"] == "scaffold_evt" for e in events)


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
