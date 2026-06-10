"""Talon — payload encryption for the agent upload path.

X25519 ephemeral key agreement → HKDF-SHA256 → AES-256-GCM. Each chunk is sealed
under the derived session key with the chunk's byte ``offset`` bound in as
additional authenticated data (AAD), so a chunk cannot be silently replayed at a
different position. ``cryptography`` is imported lazily; callers that only need
the plaintext chunker never require it.

    server_priv, server_pub = generate_keypair()
    agent_priv, agent_pub   = generate_keypair()
    key = derive_session_key(agent_priv, server_pub)   # == derive on the server side
    blob = seal(key, b"secret", aad=b"s1:0")
    assert open_(key, blob, aad=b"s1:0") == b"secret"
"""

from __future__ import annotations

import os


def _require():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return (X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, hashes, serialization)
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "payload encryption requires the 'cryptography' package; "
            "the plaintext chunker works without it."
        ) from exc


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_bytes, public_bytes)`` for an X25519 keypair (raw, 32B each)."""
    X25519PrivateKey, _, _, _, _, serialization = _require()
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_b, pub_b


def derive_session_key(
    private_bytes: bytes, peer_public_bytes: bytes, *, info: bytes = b"citadel-talon-upload"
) -> bytes:
    """X25519 ECDH → HKDF-SHA256 → 32-byte AES-256 key. Symmetric across peers."""
    X25519PrivateKey, X25519PublicKey, _, HKDF, hashes, _ = _require()
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = priv.exchange(peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt. Output = nonce(12) || ciphertext||tag."""
    _, _, AESGCM, _, _, _ = _require()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def open_(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt of a ``seal`` output. Raises on tamper/AAD mismatch."""
    _, _, AESGCM, _, _, _ = _require()
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def available() -> bool:
    try:
        _require()
        return True
    except RuntimeError:
        return False
