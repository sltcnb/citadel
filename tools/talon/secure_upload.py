"""Talon — end-to-end resumable, encrypted bundle upload.

Ties the offline chunker (:mod:`agent_client`) to payload encryption
(:mod:`crypto`) and an in-process Collector servicer, so the full path — encrypt
→ stream → resume after interruption → decrypt → sha256-verify — is exercised
without grpcio or a network. The same ``send(chunks) -> UploadAck`` shape is what
the real gRPC ``UploadChunk`` RPC implements, so this is a faithful e2e harness.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import crypto
from agent_client import Chunk, UploadAck, blob_sha256, iter_chunks


@dataclass
class EncryptedChunk:
    """A Chunk whose ``data`` is AES-256-GCM ciphertext; ``chunk_sha256`` is over
    the *plaintext* so the server verifies integrity after decrypting."""

    session_id: str
    blob_sha256: str
    offset: int
    data: bytes  # sealed (nonce||ct||tag)
    chunk_sha256: str  # plaintext digest
    last: bool = False


def encrypt_stream(chunks: Iterator[Chunk], key: bytes) -> Iterator[EncryptedChunk]:
    for c in chunks:
        aad = f"{c.session_id}:{c.offset}".encode()
        yield EncryptedChunk(
            session_id=c.session_id,
            blob_sha256=c.blob_sha256,
            offset=c.offset,
            data=crypto.seal(key, c.data, aad=aad),
            chunk_sha256=c.chunk_sha256,
            last=c.last,
        )


class InProcessCollectorServicer:
    """In-process stand-in for the gRPC Collector.UploadChunk server.

    Decrypts each chunk, verifies the plaintext per-chunk sha256, writes it at the
    declared offset (resume-aware: a chunk whose offset is already covered is
    skipped), and on the final chunk verifies the full-blob sha256. ``fail_after``
    simulates a transport interruption once (returns a non-verified ack so the
    client resumes from ``bytes_received``)."""

    def __init__(self, key: bytes, dest: Path, *, fail_after: int | None = None) -> None:
        self.key = key
        self.dest = Path(dest)
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        self.received = 0
        self.expected_digest: str | None = None
        self._fail_after = fail_after

    def upload_chunk_stream(self, chunks: Iterator[EncryptedChunk]) -> UploadAck:
        sid = ""
        for i, ec in enumerate(chunks):
            sid = ec.session_id
            self.expected_digest = ec.blob_sha256
            if self._fail_after is not None and i >= self._fail_after:
                self._fail_after = None  # only interrupt once
                return UploadAck(session_id=sid, bytes_received=self.received, verified=False)
            aad = f"{ec.session_id}:{ec.offset}".encode()
            try:
                pt = crypto.open_(self.key, ec.data, aad=aad)
            except Exception as exc:  # noqa: BLE001
                return UploadAck(
                    session_id=sid,
                    bytes_received=self.received,
                    verified=False,
                    error=f"decrypt failed: {exc}",
                )
            if hashlib.sha256(pt).hexdigest() != ec.chunk_sha256:
                return UploadAck(
                    session_id=sid,
                    bytes_received=self.received,
                    verified=False,
                    error="chunk sha256 mismatch",
                )
            if ec.offset < self.received:
                continue  # already have these bytes (resume)
            if ec.offset != self.received:
                return UploadAck(
                    session_id=sid, bytes_received=self.received, verified=False, error="offset gap"
                )
            mode = "wb" if self.received == 0 else "r+b"
            with open(self.dest, mode) as fh:
                fh.seek(ec.offset)
                fh.write(pt)
            self.received += len(pt)
            if ec.last:
                ok = blob_sha256(self.dest) == self.expected_digest
                return UploadAck(
                    session_id=sid,
                    bytes_received=self.received,
                    verified=ok,
                    error="" if ok else "full sha256 mismatch",
                )
        return UploadAck(session_id=sid, bytes_received=self.received, verified=False)


def resilient_secure_upload(
    path: Path,
    servicer: InProcessCollectorServicer,
    key: bytes,
    *,
    session_id: str,
    chunk_size: int | None = None,
    max_attempts: int = 10,
) -> UploadAck:
    """Stream the encrypted blob, resuming from the server's ``bytes_received``
    until the server reports ``verified`` (or attempts are exhausted)."""
    path = Path(path)
    digest = blob_sha256(path)
    offset = 0
    ack = UploadAck()
    for _ in range(max_attempts):
        kw = {"start_offset": offset, "full_digest": digest}
        if chunk_size:
            kw["chunk_size"] = chunk_size
        plain = iter_chunks(path, session_id=session_id, **kw)
        ack = servicer.upload_chunk_stream(encrypt_stream(plain, key))
        if ack.verified:
            return ack
        if ack.error and "mismatch" in ack.error:
            raise RuntimeError(f"upload failed: {ack.error}")
        if ack.bytes_received <= offset and offset != 0:
            raise RuntimeError("no progress on resume")
        offset = ack.bytes_received
    return ack
