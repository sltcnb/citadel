"""Test stub for the {{cookiecutter.parser_name}} parser."""
from pathlib import Path

from {{cookiecutter.parser_name}}_plugin import {{cookiecutter.parser_name}}Plugin


def test_can_handle_extension(tmp_path):
    f = tmp_path / "sample{{cookiecutter.extension}}"
    f.write_text("hello\n")
    assert {{cookiecutter.parser_name}}Plugin.can_handle(f, "{{cookiecutter.mime_type}}")


def test_parse_yields_events(tmp_path):
    f = tmp_path / "sample{{cookiecutter.extension}}"
    f.write_text("line one\nline two\n")
    from base_plugin import PluginContext
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=f, source_minio_url="")
    events = list({{cookiecutter.parser_name}}Plugin(ctx).parse())
    assert len(events) == 2
    assert all(e["timestamp"] and e["message"] for e in events)
