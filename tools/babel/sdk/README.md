# Babel Parser SDK

A Babel parser turns one artifact format into a stream of `ForensicEvent` dicts.
The contract is small and is defined by `BasePlugin` in
[`../base_plugin.py`](../base_plugin.py).

## The contract

Subclass `BasePlugin` and implement `parse()`:

```python
from base_plugin import BasePlugin, PluginContext

class MyParser(BasePlugin):
    PLUGIN_NAME = "myparser"
    PLUGIN_VERSION = "0.1.0"          # semver — bump on behaviour change
    DEFAULT_ARTIFACT_TYPE = "my_artifact"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 100             # 100 = dedicated, 10 = generic fallback

    def parse(self):
        for line in self.ctx.source_file_path.read_text().splitlines():
            yield {
                "timestamp": "2026-01-01T00:00:00Z",  # REQUIRED, ISO-8601 Z
                "message": line,                        # REQUIRED
                "artifact_type": self.DEFAULT_ARTIFACT_TYPE,
                "raw": {"line": line},                  # required for structured types
            }
```

- **`can_handle(file_path, mime_type)`** — default matches on extension / MIME /
  filename; override `get_handled_filenames()` for extension-less artifacts
  (e.g. `$MFT`, `NTUSER.DAT`).
- **`parse()`** — yield event dicts. Required keys: `timestamp` (ISO-8601 Z) +
  `message`. Recommended: `artifact_type`, `timestamp_desc`, `host`/`user`/
  `process`/`network`, and `raw` (required for structured types). Events conform
  to `../../contracts/forensic_event.schema.json`; Rosetta maps them to ECS.
- **`setup()` / `teardown()`** — open/close file handles.
- Errors: raise `PluginParseError` (skippable record) or `PluginFatalError`
  (abort the file).

## Manifest

Every parser ships a `manifest.yaml` declaring `id`, `name`, `version` (semver),
`supported_extensions`, `supported_mime_types`, `artifact_type`,
`handled_filenames`, `author`, `tags`.

## Scaffold a new parser

Use the cookiecutter template in [`../template/`](../template/):

```bash
cookiecutter tools/babel/template     # prompts for parser_name, artifact_type, extension
# or, without cookiecutter, copy the dir and replace the {{cookiecutter.*}} tokens
```

The generated package contains `manifest.yaml`, `<name>_plugin.py`, and a test
stub. Drop it under `tools/babel/` and the loader discovers it — no
registration needed.
