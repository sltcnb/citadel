"""
Strings fallback plugin — last-resort handler for any file not matched by
a specific plugin. Extracts printable ASCII strings (≥6 chars) from the
raw bytes using a pure-Python regex scan.

Priority 1 — absolute lowest. Only selected when no other plugin claims the file.

What lands in the index (intentionally small):
  - message:         short summary "[<file>] N strings; first: <preview>"
  - strings.preview: first PREVIEW_STRINGS (long but truncated) entries
  - raw.preview:     same preview list (for the detail panel)

What does NOT land in the index:
  - The full string dump. SQLite hives / ETL traces / sync DBs produce
    tens of thousands of strings that flood every `*keyword*` search and
    blow up the ES doc to multi-MB. The full content is kept in MinIO via
    the source_file pointer; analysts who really need it can `mc cat`.

If the file looks pure noise (very short average string length + no
discriminating tokens, e.g. random compressed/encrypted blobs), the
plugin yields nothing — better an empty timeline than a screen full of
"@XQ-(/C" lines.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

MIN_LEN = 6
MAX_BYTES = 50 * 1024 * 1024  # 50 MB scan cap
MAX_STRINGS = 50_000  # safety cap

# How many strings make it into the ES doc — small enough to keep search noise
# manageable, big enough to fingerprint the file (DLL names, table schemas,
# headers usually appear in the first ~50 strings).
PREVIEW_STRINGS = 50
# Per-string length cap so one weird 4 KB string can't blow up the doc.
PREVIEW_STRING_MAX = 240

# Suppress the event entirely if the file looks pure-noise. Heuristic:
# average string length < 8 AND no string longer than 24 chars → almost
# certainly random binary (compressed / encrypted blob, font glyphs, etc).
NOISE_AVG_LEN = 8
NOISE_MAX_LEN = 24

_RE = re.compile(rb"[\x20-\x7e]{" + str(MIN_LEN).encode() + rb",}")


class StringsFallbackPlugin(BasePlugin):
    PLUGIN_NAME = "strings"
    PLUGIN_VERSION = "2.1.0"
    DEFAULT_ARTIFACT_TYPE = "binary_files"
    SUPPORTED_EXTENSIONS = []
    # Intentionally empty: this is the last-resort catch-all (can_handle → True,
    # priority 1). It claims by behaviour, not MIME, so it never shadows a parser.
    SUPPORTED_MIME_TYPES = []
    PLUGIN_PRIORITY = 1

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        return True  # catch-all

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        # Filenames from tar/zip can contain surrogate bytes (\udcXX) when the
        # OS path bytes aren't valid UTF-8. Those tank json.dumps later. Strip
        # surrogates at source so every downstream consumer sees clean text.
        filename = fp.name.encode("utf-8", errors="replace").decode("utf-8")
        ext = fp.suffix.lower().lstrip(".")

        try:
            data = fp.read_bytes()
        except Exception as exc:
            raise PluginFatalError(f"Cannot read file: {exc}")

        if len(data) > MAX_BYTES:
            data = data[:MAX_BYTES]

        # Text vs binary classification. A UTF-8-decodable / high-printable-ratio
        # file (e.g. apport.log, a generic application log) is TEXT, not a binary
        # blob — labelling it "binary_files" was misleading. We still emit a
        # strings-style preview, but with the correct artifact_type so the
        # timeline + a future generic-log parser can treat it as text.
        sample = data[:8192]
        is_text = False
        if sample:
            try:
                sample.decode("utf-8")
                is_text = True
            except UnicodeDecodeError:
                printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (9, 10, 13))
                is_text = printable / len(sample) >= 0.90
        atype = "generic_text" if is_text else "binary_files"

        strings = [m.group(0).decode("ascii", errors="replace") for m in _RE.finditer(data)][
            :MAX_STRINGS
        ]

        if not strings:
            return

        # Pure-noise gate. Random/encrypted blobs produce strings that look
        # like "@XQ-(/C", "0a)h;", "<fW0F-" — short, no useful keywords.
        # Skip those entirely rather than pollute the timeline.
        max_len = max(len(s) for s in strings)
        avg_len = sum(len(s) for s in strings) / max(1, len(strings))
        if avg_len < NOISE_AVG_LEN and max_len < NOISE_MAX_LEN:
            self.log.debug(
                "Skipping %s — noise heuristic (avg=%.1f max=%d)",
                filename,
                avg_len,
                max_len,
            )
            return

        # Build the indexed preview: cap count + per-string length.
        preview = [
            (s if len(s) <= PREVIEW_STRING_MAX else s[:PREVIEW_STRING_MAX] + "…")
            for s in strings[:PREVIEW_STRINGS]
        ]
        truncated = len(strings) > PREVIEW_STRINGS

        try:
            mtime = datetime.fromtimestamp(fp.stat().st_mtime, tz=UTC).isoformat()
        except OSError:
            mtime = datetime.now(UTC).isoformat()
        size_bytes = fp.stat().st_size if fp.exists() else len(data)

        noun = "lines" if is_text else "strings"
        msg = f"[{filename}] {len(strings):,} {noun} — first: {strings[0][:120]}" + (
            f" (+{len(strings) - PREVIEW_STRINGS:,} more in source file)" if truncated else ""
        )

        yield {
            "timestamp": mtime,
            "timestamp_desc": "File mtime",
            "message": msg,
            "artifact_type": atype,
            # No `content` field — keeping the doc small. Analysts who really
            # need the full string dump can retrieve the source file from
            # MinIO via source_file (set by the ingest pipeline).
            "strings": {
                "filename": filename,
                "count": len(strings),
                "preview": preview,
                "truncated": truncated,
                "ext": ext,
            },
            "raw": {
                "filename": filename,
                "size_bytes": size_bytes,
                "ext": ext,
                "count": len(strings),
                "preview": preview,
                "truncated": truncated,
            },
        }
