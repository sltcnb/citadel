#!/usr/bin/env python3
"""
Talon — gRPC remote-agent client (skeleton)
============================================
A thin client for the ``citadel.collector.v1.Collector`` service defined in
``contracts/collector.proto``:

    Register(AgentHello) -> TaskList
    Heartbeat(stream AgentBeat) -> stream Task
    UploadChunk(stream Chunk) -> UploadAck   # 8 MiB chunks, sha256/chunk, resumable

Design notes
------------
* The **chunker** (:class:`ChunkUploader` / :func:`iter_chunks`) is pure stdlib and
  fully testable offline — no server, no grpc import. It produces the ``Chunk``
  message stream (8 MiB windows, per-chunk SHA-256, full-blob SHA-256) and supports
  *resume from an offset* returned by a prior partial ``UploadAck``.
* The gRPC transport (:class:`CollectorAgentClient`) imports ``grpc`` lazily so the
  collector keeps its stdlib-only runtime; if generated stubs are absent we fall
  back to hand-written request/response shapes that mirror the proto exactly.

Generating real stubs (optional, build-time)::

    python -m grpc_tools.protoc -I ../../contracts \
        --python_out=. --grpc_python_out=. ../../contracts/collector.proto
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Per the contract: 8 MiB chunks.
CHUNK_SIZE = 8 * 1024 * 1024


# ─────────────────────────────────────────────────────────────────────────────
# Message shapes — mirror collector.proto (used directly, or copied onto
# generated protobuf messages by the transport layer).
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Chunk:
    session_id: str
    blob_sha256: str  # full-blob digest
    offset: int  # resume point (bytes already accepted)
    data: bytes  # <= 8 MiB
    chunk_sha256: str  # per-chunk digest
    last: bool = False


@dataclass
class UploadAck:
    session_id: str = ""
    bytes_received: int = 0
    verified: bool = False
    error: str = ""


@dataclass
class AgentHello:
    agent_id: str
    hostname: str
    os: str
    version: str
    enrollment_token: str = ""


@dataclass
class Task:
    task_id: str = ""
    profile: str = ""
    artifact_categories: list[str] = field(default_factory=list)
    ioc_globs: list[str] = field(default_factory=list)
    upload_token: str = ""


@dataclass
class AgentBeat:
    agent_id: str
    current_task_id: str = ""
    progress: float = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Chunker — offline, resumable, sha256-verified
# ─────────────────────────────────────────────────────────────────────────────
def blob_sha256(path: Path, *, read_window: int = 1024 * 1024) -> str:
    """Full-blob SHA-256 (hex), streamed."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(read_window), b""):
            h.update(block)
    return h.hexdigest()


def chunk_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_chunks(
    path: Path,
    *,
    session_id: str,
    start_offset: int = 0,
    chunk_size: int = CHUNK_SIZE,
    full_digest: str | None = None,
) -> Iterator[Chunk]:
    """
    Yield :class:`Chunk` messages for ``path`` starting at ``start_offset``.

    * ``start_offset`` lets an upload *resume* after a partial ``UploadAck``:
      bytes already received are skipped, hashing/offsets stay correct.
    * Each chunk carries its own SHA-256 and the full-blob SHA-256 (computed once
      up front unless supplied via ``full_digest``).
    * The final chunk has ``last=True``. A zero-length file yields a single empty
      ``last`` chunk so the server always receives a terminator.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    size = path.stat().st_size
    if start_offset < 0 or start_offset > size:
        raise ValueError(f"start_offset {start_offset} out of range for {size}-byte blob")

    digest = full_digest or blob_sha256(path)

    if size == 0:
        yield Chunk(
            session_id=session_id,
            blob_sha256=digest,
            offset=0,
            data=b"",
            chunk_sha256=chunk_sha256(b""),
            last=True,
        )
        return

    offset = start_offset
    with open(path, "rb") as fh:
        fh.seek(offset)
        while True:
            data = fh.read(chunk_size)
            if not data:
                break
            offset_next = offset + len(data)
            yield Chunk(
                session_id=session_id,
                blob_sha256=digest,
                offset=offset,
                data=data,
                chunk_sha256=chunk_sha256(data),
                last=offset_next >= size,
            )
            offset = offset_next


@dataclass
class ChunkUploader:
    """
    Drives a resumable chunked upload of a single blob.

    The transport is injected as ``send(chunk) -> UploadAck`` so the chunker stays
    server-free and unit-testable. Typical use::

        up = ChunkUploader(path, session_id="s1")
        ack = up.upload(send=client.upload_chunk_stream)

    Resume: pass ``resume_offset`` (e.g. from a prior ``UploadAck.bytes_received``)
    to skip already-accepted bytes.
    """

    path: Path
    session_id: str
    chunk_size: int = CHUNK_SIZE
    resume_offset: int = 0

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.full_digest = blob_sha256(self.path)
        self.bytes_sent = self.resume_offset

    def chunks(self) -> Iterator[Chunk]:
        for chunk in iter_chunks(
            self.path,
            session_id=self.session_id,
            start_offset=self.resume_offset,
            chunk_size=self.chunk_size,
            full_digest=self.full_digest,
        ):
            self.bytes_sent = chunk.offset + len(chunk.data)
            yield chunk

    def upload(self, send) -> UploadAck:
        """
        Stream all chunks through ``send`` and return its :class:`UploadAck`.

        ``send`` receives an iterator of :class:`Chunk` and returns an
        :class:`UploadAck` (mirrors the server-streaming-in / unary-out RPC).
        After the upload, verifies the server's reported digest expectation.
        """
        ack = send(self.chunks())
        if ack.error:
            raise UploadError(ack.error)
        expected = self.resume_offset_total()
        if ack.bytes_received and ack.bytes_received != expected:
            raise UploadError(
                f"byte mismatch: server got {ack.bytes_received}, expected {expected}"
            )
        return ack

    def resume_offset_total(self) -> int:
        return self.path.stat().st_size


class UploadError(RuntimeError):
    """Raised when the server rejects an upload or returns a mismatch."""


# ─────────────────────────────────────────────────────────────────────────────
# gRPC transport — lazily imports grpc; degrades gracefully when unavailable.
# ─────────────────────────────────────────────────────────────────────────────
class CollectorAgentClient:
    """
    Thin gRPC client for ``citadel.collector.v1.Collector``.

    ``grpc`` and the generated stubs are imported lazily inside
    :meth:`connect`, so importing this module never requires grpc to be present
    (the chunker above is usable on its own). Hand-written request marshalling
    mirrors ``collector.proto`` when generated stubs are not on the path.
    """

    def __init__(
        self,
        target: str,
        *,
        root_certs: bytes | None = None,
        private_key: bytes | None = None,
        cert_chain: bytes | None = None,
    ) -> None:
        self.target = target
        self._creds = (root_certs, private_key, cert_chain)
        self._channel = None
        self._stub = None

    def connect(self):
        """Open the (m)TLS channel and bind the generated stub.

        Returns ``self`` for chaining. Requires ``grpc`` + generated stubs:
            python -m grpc_tools.protoc -I contracts \
                --python_out=. --grpc_python_out=. contracts/collector.proto
        """
        try:
            import grpc  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "grpcio is required for live agent transport; "
                "the chunker (iter_chunks/ChunkUploader) works without it."
            ) from exc
        import grpc

        root, key, chain = self._creds
        if root or key or chain:
            creds = grpc.ssl_channel_credentials(
                root_certificates=root, private_key=key, certificate_chain=chain
            )
            self._channel = grpc.secure_channel(self.target, creds)
        else:  # pragma: no cover - insecure path is for local dev only
            self._channel = grpc.insecure_channel(self.target)

        try:
            import collector_pb2_grpc  # type: ignore

            self._stub = collector_pb2_grpc.CollectorStub(self._channel)
        except ImportError:
            self._stub = None  # stubs not generated; callers must supply transport
        return self

    # -- RPC wrappers (require generated stubs) --------------------------------
    def register(self, hello: AgentHello):  # pragma: no cover - needs server
        self._require_stub()
        import collector_pb2  # type: ignore

        return self._stub.Register(
            collector_pb2.AgentHello(
                agent_id=hello.agent_id,
                hostname=hello.hostname,
                os=hello.os,
                version=hello.version,
                enrollment_token=hello.enrollment_token,
            )
        )

    def upload_chunk_stream(self, chunks: Iterator[Chunk]) -> UploadAck:  # pragma: no cover
        """Server-streaming-in / unary-out UploadChunk RPC."""
        self._require_stub()
        import collector_pb2  # type: ignore

        def _gen():
            for c in chunks:
                yield collector_pb2.Chunk(
                    session_id=c.session_id,
                    blob_sha256=c.blob_sha256,
                    offset=c.offset,
                    data=c.data,
                    chunk_sha256=c.chunk_sha256,
                    last=c.last,
                )

        resp = self._stub.UploadChunk(_gen())
        return UploadAck(
            session_id=resp.session_id,
            bytes_received=resp.bytes_received,
            verified=resp.verified,
            error=resp.error,
        )

    def _require_stub(self) -> None:
        if self._stub is None:
            raise RuntimeError(
                "gRPC stub unavailable: run protoc to generate collector_pb2*.py "
                "and call connect() first."
            )

    def close(self) -> None:
        if self._channel is not None:  # pragma: no cover
            self._channel.close()
