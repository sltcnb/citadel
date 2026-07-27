"""MinIO retry policy + byte-complete upload behind module results.json.

Real symptom this covers: MinIO answered the results.json PUT with
``IncompleteBody`` ("You did not provide the number of bytes specified by the
Content-Length HTTP header") and, because that code was neither retried nor
caught, every affected module run was marked FAILED and dead-lettered — even
though its hits had already been indexed into Elasticsearch and the findings
store one step earlier.

Invariants asserted here:
  1. ``IncompleteBody`` and the other MinIO server transients are retried, so a
     single truncated PUT self-heals on the next attempt.
  2. Permission / signature errors still fail fast — retries must not mask them.
  3. Content-Length always matches the encoded body, including non-ASCII hits.
  4. A short write the server accepted is caught by re-reading the stored size,
     so a silently truncated results.json is never reported as a clean upload.
  5. Every retry re-sends the full body, never a drained stream.

Targets ``s3_retry`` directly — tasks/module_task.py imports celery, redis-py
and the minio SDK, none of which the dependency-light gate has (same isolation
as test_parse_metrics.py). Runnable standalone
(python3 tools/sluice/worker/tests/test_module_results_upload.py) to match the
convention in scripts/run_tests.sh.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import s3_retry  # noqa: E402

BUCKET = "forensics-cases"
KEY = "cases/daf36f1dccec/modules/2eeb7a768eaa4d97b5e6eabc57356f9b/results.json"

# The exact error string the field reported, verbatim.
INCOMPLETE_BODY = (
    "S3 operation failed; code: IncompleteBody, message: You did not provide the number "
    f"of bytes specified by the Content-Length HTTP header., resource: /{BUCKET}/{KEY}"
)

TRANSIENT_MESSAGES = [
    INCOMPLETE_BODY,
    "S3 operation failed; code: SlowDown",
    "S3 operation failed; code: InternalError",
    "S3 operation failed; code: RequestTimeout",
    "503 Service Unavailable",
    "Connection refused",
    "Remote end closed connection without response",
]

PERMANENT_MESSAGES = [
    "S3 operation failed; code: AccessDenied",
    "S3 operation failed; code: NoSuchBucket",
    "S3 operation failed; code: SignatureDoesNotMatch",
]


class _Stat:
    def __init__(self, size: int) -> None:
        self.size = size


class FakeMinio:
    """Records PUTs and reports a configurable stored size per object.

    ``put_object`` asserts the announced length matches the bytes actually
    readable from the stream — the desync that produces IncompleteBody for real.
    """

    def __init__(
        self,
        *,
        stored_size: int | None = None,
        fail_times: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.puts: list[tuple[str, int]] = []
        self._stored_size = stored_size
        self._fail_times = fail_times
        self._error = error or OSError(INCOMPLETE_BODY)

    def put_object(self, bucket, key, data, length=None, content_type=None):
        body = data.read()
        assert len(body) == length, f"Content-Length {length} != body {len(body)} bytes"
        if self._fail_times > 0:
            self._fail_times -= 1
            raise self._error
        self.puts.append((key, len(body)))

    def stat_object(self, bucket, key):
        for pkey, size in self.puts:
            if pkey == key:
                return _Stat(self._stored_size if self._stored_size is not None else size)
        raise OSError("NoSuchKey")


def _raises(exc_type, match, fn):
    """Assert fn() raises exc_type whose message contains *match*."""
    try:
        fn()
    except exc_type as exc:
        assert match in str(exc), f"expected {match!r} in {exc!r}"
        return
    raise AssertionError(f"expected {exc_type.__name__} containing {match!r}, nothing raised")


# ── transient classification ──────────────────────────────────────────────────


def test_field_transients_are_classified_retryable():
    """The exact server errors seen in the field must be retryable."""
    for message in TRANSIENT_MESSAGES:
        assert s3_retry.is_transient(OSError(message)), message


def test_permission_and_signature_errors_are_not_retryable():
    for message in PERMANENT_MESSAGES:
        assert not s3_retry.is_transient(OSError(message)), message


# ── minio_op retry loop ───────────────────────────────────────────────────────


def test_incomplete_body_is_retried_to_success():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(INCOMPLETE_BODY)
        return "ok"

    assert s3_retry.minio_op(flaky, max_tries=3, base_delay=0) == "ok"
    assert calls["n"] == 2


def test_non_transient_error_fails_fast():
    calls = {"n": 0}

    def broken():
        calls["n"] += 1
        raise OSError("S3 operation failed; code: AccessDenied")

    _raises(OSError, "AccessDenied", lambda: s3_retry.minio_op(broken, max_tries=3, base_delay=0))
    assert calls["n"] == 1, "a permission error must fail fast, not burn retries"


def test_exhausted_retries_reraise_the_last_error():
    def always_truncated():
        raise OSError(INCOMPLETE_BODY)

    _raises(
        OSError,
        "IncompleteBody",
        lambda: s3_retry.minio_op(always_truncated, max_tries=2, base_delay=0),
    )


# ── put_bytes_verified ────────────────────────────────────────────────────────


def test_put_verified_sends_exact_content_length_for_non_ascii():
    """Non-ASCII hits must not desync Content-Length from the encoded body."""
    payload = '[{"msg": "café — ünïcode ✓ 日本語"}]'.encode()
    assert len(payload) > len(payload.decode()), "fixture must be multi-byte"
    fake = FakeMinio()
    s3_retry.put_bytes_verified(fake, BUCKET, KEY, payload, "application/json")
    assert fake.puts == [(KEY, len(payload))]


def test_put_verified_handles_zero_hit_results():
    """A module with no hits still uploads a valid, verified 2-byte JSON array."""
    fake = FakeMinio()
    s3_retry.put_bytes_verified(fake, BUCKET, KEY, b"[]", "application/json")
    assert fake.puts == [(KEY, 2)]


def test_put_verified_rejects_a_silent_short_write():
    """A server that stored fewer bytes than we sent must be treated as a failure."""
    payload = b"[" + b"x" * 4096 + b"]"
    fake = FakeMinio(stored_size=len(payload) - 17)
    _raises(
        OSError,
        "IncompleteBody",
        lambda: s3_retry.put_bytes_verified(fake, BUCKET, KEY, payload, "application/json"),
    )


def test_put_verified_short_write_is_retried_to_success():
    """The size check raises a retryable error, so minio_op recovers the upload."""
    payload = b'[{"a": 1}]'
    fake = FakeMinio(fail_times=1)
    s3_retry.minio_op(
        lambda: s3_retry.put_bytes_verified(fake, BUCKET, KEY, payload, "application/json"),
        max_tries=3,
        base_delay=0,
    )
    assert fake.puts == [(KEY, len(payload))]


def test_retry_resends_the_full_body_not_a_drained_stream():
    """Each attempt must get a fresh buffer — a consumed stream would send 0 bytes."""
    payload = b'[{"hit": "x"}]' * 100
    fake = FakeMinio(fail_times=2)
    s3_retry.minio_op(
        lambda: s3_retry.put_bytes_verified(fake, BUCKET, KEY, payload, "application/json"),
        max_tries=4,
        base_delay=0,
    )
    assert fake.puts == [(KEY, len(payload))]


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
