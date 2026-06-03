"""Confidential session channel — WMK delivery into the CVM (identity-envelope.md §6).

The working-memory key (WMK) is the one user-held key that ever enters a remote machine. It
does so ONLY over a session key `SK` that is bound to the verified attestation:

  1. Client generates an ephemeral X25519 keypair; `client_eph_pub` is the attestation
     challenge, so the CVM's quote binds `SHA-256(client_eph_pub)` in report_data
     (attestation.md §3-4) — the keystone verifies this BEFORE any key leaves the client.
  2. Both sides compute `SK = HKDF(X25519(·), info = "swifty/session/v1" ‖ client_eph_pub ‖
     cvm_pub)`. Binding BOTH public keys into the KDF info defeats unknown-key-share / a MITM
     who substitutes a key: a substituted key yields a different `SK`, so the sealed WMK
     won't open.
  3. Client seals WMK to `SK` (XChaCha20 envelope, purpose "wmk-delivery") and sends it; the
     CVM opens it in TEE RAM, uses it for the session, and discards it on session end (§6).

X25519 here matches CryptoKit's `Curve25519.KeyAgreement` and the gateway's `cryptography`
X25519 (all RFC 7748), so client and CVM derive the SAME SK.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from swifty_crypto.envelope import open as _open
from swifty_crypto.envelope import seal as _seal

SESSION_LABEL = b"swifty/session/v1"
WMK_DELIVERY_PURPOSE = "wmk-delivery"
KEY_LEN = 32


def x25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_bytes[32], public_bytes[32]) for an ephemeral session key."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes_raw(),
        priv.public_key().public_bytes_raw(),
    )


def x25519_public(private_bytes: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_bytes).public_key().public_bytes_raw()


def derive_session_key(my_private: bytes, their_public: bytes, *, client_pub: bytes, cvm_pub: bytes) -> bytes:
    """SK from ECDH + HKDF, binding both endpoints' public keys (anti-UKS/MITM).

    Both sides pass the SAME `client_pub`/`cvm_pub` (the channel identities) and their own
    `my_private` + the peer's `their_public`; the ECDH is symmetric so they agree on SK."""
    if len(client_pub) != KEY_LEN or len(cvm_pub) != KEY_LEN:
        raise ValueError("public keys must be 32 bytes")
    if len(my_private) != KEY_LEN or len(their_public) != KEY_LEN:
        raise ValueError("session keys must be 32 bytes")
    # `cryptography`'s exchange() raises on an all-zero (low-order/identity) result, so a
    # substituted low-order peer key fails closed here (the Swift side mirrors this).
    shared = X25519PrivateKey.from_private_bytes(my_private).exchange(
        X25519PublicKey.from_public_bytes(their_public)
    )
    info = SESSION_LABEL + client_pub + cvm_pub  # fixed-length pubs -> unambiguous
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(shared)


def seal_wmk(session_key: bytes, wmk: bytes, *, account_id: str, v: int = 1) -> dict:
    """Client seals WMK to the session key for delivery into the CVM (§6)."""
    return _seal(session_key, wmk, account_id=account_id, purpose=WMK_DELIVERY_PURPOSE, v=v)


def open_wmk(session_key: bytes, envelope: dict, *, account_id: str) -> bytes:
    """CVM opens the sealed WMK (in TEE RAM). Fails closed on any tamper / wrong session."""
    return _open(session_key, envelope, account_id=account_id, purpose=WMK_DELIVERY_PURPOSE)
