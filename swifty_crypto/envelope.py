"""Encryption envelope (contracts/identity-envelope.md §4): XChaCha20-Poly1305 AEAD.

The server stores only opaque `envelope` dicts; it holds no key and cannot decrypt. The
AAD binds the blob to account+purpose+version, so a blob can't be replayed across users or
purposes (the AEAD tag covers the AAD; tampering it fails the open).
"""

from __future__ import annotations

import hashlib
import hmac

import nacl.bindings as sodium
import nacl.utils

ALG = "xchacha20poly1305"
NONCE_LEN = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24


def _aad(account_id: str, purpose: str, v: int) -> bytes:
    # length-delimited (newline) so the fields can't be re-segmented ambiguously (B1).
    return hashlib.sha256(f"{account_id}\n{purpose}\n{v}".encode()).digest()


def seal(key: bytes, plaintext: bytes, *, account_id: str, purpose: str, v: int, kid: str = "v1") -> dict:
    nonce = nacl.utils.random(NONCE_LEN)  # 24 random bytes per encryption (B4)
    aad = _aad(account_id, purpose, v)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return {"v": v, "alg": ALG, "kid": kid, "nonce": nonce, "aad": aad, "ct": ct}


def open(  # noqa: A001 - contract API name (identity-envelope §4)
    key: bytes,
    envelope: dict,
    *,
    account_id: str | None = None,
    purpose: str | None = None,
) -> bytes:
    """Decrypt + verify. Raises on any tamper — never returns data for a modified
    ciphertext or AAD.

    Callers SHOULD pass `account_id` + `purpose`: when given, the stored AAD is
    re-derived from those authoritative inputs and checked, so the §4 user+purpose+version
    binding is enforced on READ (not just trusted from the stored field). Omitting them
    (the bare contract `open(key, envelope)` form) decrypts against the stored AAD only."""
    aad = envelope["aad"]
    if account_id is not None and purpose is not None:
        expected = _aad(account_id, purpose, envelope["v"])
        if not hmac.compare_digest(expected, aad):
            raise ValueError("AAD does not bind to the expected account_id/purpose/v")
        aad = expected
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        envelope["ct"], aad, envelope["nonce"], key
    )
