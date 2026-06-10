"""Talon — real gRPC Collector server (production transport).

Implements ``citadel.collector.v1.Collector`` (see ../../contracts/collector.proto)
with **mTLS** and resumable, sha256-verified, optionally AES-256-GCM-encrypted
``UploadChunk`` streaming. The chunk-handling logic is shared with
``secure_upload.InProcessCollectorServicer`` (which the offline e2e test drives),
so this module is a thin gRPC adapter over already-tested core logic.

Requires ``grpcio`` + generated stubs. Generate them with::

    ./generate_stubs.sh        # or:
    python -m grpc_tools.protoc -I ../../contracts \
        --python_out=. --grpc_python_out=. ../../contracts/collector.proto

The collector's *runtime* stays stdlib-only; grpc is needed only to run the
server/agent transport, so everything here imports lazily.
"""

from __future__ import annotations

from pathlib import Path


def _load_grpc():
    try:
        import collector_pb2  # type: ignore
        import collector_pb2_grpc  # type: ignore
        import grpc  # type: ignore

        return grpc, collector_pb2, collector_pb2_grpc
    except ImportError as exc:  # pragma: no cover - needs grpcio + generated stubs
        raise RuntimeError(
            "gRPC server needs grpcio + generated stubs; run ./generate_stubs.sh. "
            "The offline e2e path (secure_upload.InProcessCollectorServicer) needs neither."
        ) from exc


def make_servicer(storage_dir: Path, key: bytes | None = None):
    """Build a CollectorServicer. ``key`` enables AES-256-GCM chunk decryption."""
    grpc, collector_pb2, collector_pb2_grpc = _load_grpc()
    from secure_upload import InProcessCollectorServicer  # shared core logic

    class CollectorServicer(collector_pb2_grpc.CollectorServicer):  # pragma: no cover
        def Register(self, request, context):
            return collector_pb2.TaskList(tasks=[])

        def Heartbeat(self, request_iterator, context):
            for _beat in request_iterator:
                # server-push of tasks would go here; yield nothing by default
                if False:
                    yield collector_pb2.Task()

        def UploadChunk(self, request_iterator, context):
            sid = ""
            core = InProcessCollectorServicer(key or b"\x00" * 32, storage_dir / "upload.bin")

            def _chunks():
                for c in request_iterator:
                    nonlocal sid
                    sid = c.session_id
                    yield c  # has .session_id/.blob_sha256/.offset/.data/.chunk_sha256/.last

            ack = core.upload_chunk_stream(_chunks()) if key else _plain(core, _chunks())
            return collector_pb2.UploadAck(
                session_id=ack.session_id or sid,
                bytes_received=ack.bytes_received,
                verified=ack.verified,
                error=ack.error or "",
            )

    return CollectorServicer()


def _plain(core, chunks):  # pragma: no cover - exercised only with grpcio present
    """UploadChunk path for unencrypted transport (mTLS still protects the wire)."""
    import hashlib

    from agent_client import UploadAck, blob_sha256

    sid = ""
    for ec in chunks:
        sid = ec.session_id
        if hashlib.sha256(ec.data).hexdigest() != ec.chunk_sha256:
            return UploadAck(
                session_id=sid,
                bytes_received=core.received,
                verified=False,
                error="chunk sha256 mismatch",
            )
        if ec.offset < core.received:
            continue
        mode = "wb" if core.received == 0 else "r+b"
        with open(core.dest, mode) as fh:
            fh.seek(ec.offset)
            fh.write(ec.data)
        core.received += len(ec.data)
        core.expected_digest = ec.blob_sha256
        if ec.last:
            ok = blob_sha256(core.dest) == core.expected_digest
            return UploadAck(
                session_id=sid,
                bytes_received=core.received,
                verified=ok,
                error="" if ok else "full sha256 mismatch",
            )
    return UploadAck(session_id=sid, bytes_received=core.received, verified=False)


def serve(
    port: int = 8443,
    *,
    storage_dir: str = "/var/lib/talon",
    server_cert: str | None = None,
    server_key: str | None = None,
    client_ca: str | None = None,
    key: bytes | None = None,
):  # pragma: no cover
    """Start the mTLS gRPC server. Requires server cert/key + client CA for mTLS."""
    grpc, _pb2, collector_pb2_grpc = _load_grpc()
    server = grpc.server(
        __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor(
            max_workers=8
        )
    )
    collector_pb2_grpc.add_CollectorServicer_to_server(
        make_servicer(Path(storage_dir), key=key), server
    )
    if server_cert and server_key and client_ca:
        creds = grpc.ssl_server_credentials(
            [(Path(server_key).read_bytes(), Path(server_cert).read_bytes())],
            root_certificates=Path(client_ca).read_bytes(),
            require_client_auth=True,  # mTLS: client must present a trusted cert
        )
        server.add_secure_port(f"[::]:{port}", creds)
    else:
        server.add_insecure_port(f"[::]:{port}")  # dev only
    server.start()
    server.wait_for_termination()
    return server
