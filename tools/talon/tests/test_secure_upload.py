"""E2E: resumable, ENCRYPTED bundle upload over the in-process Collector.

Standalone-runnable. Skips cleanly if 'cryptography' is unavailable.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import crypto  # noqa: E402


def _run():
    if not crypto.available():
        print("SKIP  cryptography not installed")
        return 0

    from secure_upload import InProcessCollectorServicer, resilient_secure_upload

    n = 0

    def check(cond, msg):
        assert cond, msg

    # --- handshake: X25519 -> identical AES key on both sides ---
    a_priv, a_pub = crypto.generate_keypair()
    s_priv, s_pub = crypto.generate_keypair()
    k_agent = crypto.derive_session_key(a_priv, s_pub)
    k_server = crypto.derive_session_key(s_priv, a_pub)
    check(k_agent == k_server and len(k_agent) == 32, "ECDH key disagreement")
    print("PASS  x25519_key_agreement")
    n += 1

    # --- seal/open round-trip with AAD binding ---
    blob = crypto.seal(k_agent, b"top secret", aad=b"s1:0")
    check(crypto.open_(k_server, blob, aad=b"s1:0") == b"top secret", "decrypt failed")
    try:
        crypto.open_(k_server, blob, aad=b"s1:999")  # wrong position
        raise AssertionError("AAD mismatch should fail")
    except Exception:
        pass
    print("PASS  aes_gcm_seal_open_aad")
    n += 1

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = td / "bundle.bin"
        payload = os.urandom(5 * 1024 * 1024 + 1234)  # multi-chunk at small chunk size
        src.write_bytes(payload)

        # --- happy path e2e ---
        srv = InProcessCollectorServicer(k_server, td / "out1.bin")
        ack = resilient_secure_upload(src, srv, k_agent, session_id="s1", chunk_size=1024 * 1024)
        check(ack.verified, f"not verified: {ack.error}")
        check((td / "out1.bin").read_bytes() == payload, "decrypted payload mismatch")
        check(ack.bytes_received == len(payload), "byte count mismatch")
        print("PASS  encrypted_e2e_happy_path")
        n += 1

        # --- resume after a simulated interruption ---
        srv2 = InProcessCollectorServicer(k_server, td / "out2.bin", fail_after=2)
        ack2 = resilient_secure_upload(src, srv2, k_agent, session_id="s2", chunk_size=1024 * 1024)
        check(ack2.verified, f"resume did not complete: {ack2.error}")
        check((td / "out2.bin").read_bytes() == payload, "resumed payload mismatch")
        print("PASS  encrypted_e2e_resumes_after_interruption")
        n += 1

        # --- tamper detection: flip a byte in transit ---
        srv3 = InProcessCollectorServicer(k_server, td / "out3.bin")
        from agent_client import blob_sha256, iter_chunks
        from secure_upload import encrypt_stream

        def tampered():
            for ec in encrypt_stream(
                iter_chunks(
                    src, session_id="s3", chunk_size=1024 * 1024, full_digest=blob_sha256(src)
                ),
                k_agent,
            ):
                ec.data = ec.data[:20] + bytes([ec.data[20] ^ 0xFF]) + ec.data[21:]
                yield ec

        ack3 = srv3.upload_chunk_stream(tampered())
        check(not ack3.verified and ack3.error, "tamper not detected")
        print("PASS  tamper_detected")
        n += 1

    print(f"\n{n}/{n} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
