"""Swifty identity & encryption reference implementation (contracts/identity-envelope.md).

The authoritative reference the Swift client + CVM must match. Established primitives only:
Argon2id + XChaCha20-Poly1305 + X25519/Ed25519 via libsodium (pynacl) and HKDF-SHA256.
"""

from swifty_crypto.envelope import open, seal  # noqa: A004 - `open` is the contract API name
from swifty_crypto.kdf import (
    argon2id,
    coding_transcript_root,
    coding_wmk,
    derive_account_id,
    derive_coding_root,
    derive_ed25519_private,
    derive_ed25519_public,
    derive_transcript_root,
    derive_wmk,
    hkdf,
)
from swifty_crypto.ratchet import (
    TranscriptRatchet,
    device_transcript_root,
    message_key_at,
    parse_transcript_kid,
    step_from_kid,
    transcript_kid,
)
from swifty_crypto.padding import pad, unpad
from swifty_crypto.session import (
    derive_session_key,
    open_wmk,
    seal_wmk,
    x25519_keypair,
    x25519_public,
)

__all__ = [
    "argon2id",
    "hkdf",
    "derive_account_id",
    "derive_wmk",
    "derive_transcript_root",
    "derive_coding_root",
    "coding_wmk",
    "coding_transcript_root",
    "derive_ed25519_private",
    "derive_ed25519_public",
    "seal",
    "open",
    "TranscriptRatchet",
    "message_key_at",
    "device_transcript_root",
    "transcript_kid",
    "parse_transcript_kid",
    "step_from_kid",
    "derive_session_key",
    "seal_wmk",
    "open_wmk",
    "x25519_keypair",
    "x25519_public",
    "pad",
    "unpad",
]
