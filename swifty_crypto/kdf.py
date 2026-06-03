"""Seed -> key derivation (contracts/identity-envelope.md §3).

Established primitives only (charter): Argon2id (libsodium/pynacl), HKDF-SHA256
(cryptography), Ed25519 (cryptography). This is the REFERENCE implementation the Swift
client + the CVM must match. account_id is BOUND to the gateway-auth key (Gate-0 amendment
B2-bis) so the gateway can verify ownership at onboarding — yet `derive_account_id` still
takes ONLY the seed-root (zero-PII; the key is itself seed-derived).
"""

from __future__ import annotations

import base64
import hashlib

import nacl.pwhash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT_LEN = 32
KEY_LEN = 32
MIN_SECRET_LEN = 16  # the seed must be high-entropy; this is NOT a password-stretch for short secrets

# §10 production Argon2id baseline (m=256MiB, t=3, p=1). Production call-sites MUST pass
# these; the function default (64MiB) is the reference/test value only.
ARGON2ID_MEMLIMIT_PRODUCTION = 256 * 1024 * 1024
ARGON2ID_OPSLIMIT_PRODUCTION = 3

# HKDF domain-separation labels (§3).
ACCOUNT_ID_LABEL = "swifty/account-id/v1"   # generic sub-key (kept for domain-sep parity)
WMK_LABEL = "swifty/working-mem/v1"
TRANSCRIPT_LABEL = "swifty/transcript/v1"
METADATA_LABEL = "swifty/metadata/v1"
GATEWAY_AUTH_LABEL = "swifty/gateway-auth/v1"  # -> Ed25519 signing key
CODING_LABEL = "swifty/coding/v1"              # -> independent coding-tier key tree (B7)
# Distinct coding-tier leaf labels (not the personal ones) so the label->function mapping
# is bijective and auditable (B7).
CODING_WMK_LABEL = "swifty/coding/working-mem/v1"
CODING_TRANSCRIPT_LABEL = "swifty/coding/transcript/v1"

# account_id = urlsafe_b64(SHA-256(domain || ed25519_pub)) — matches gateway ids.derive_account_id.
_ACCOUNT_ID_DOMAIN = b"swifty/account/v1"


def argon2id(seed: bytes, salt: bytes, *, opslimit: int = 3, memlimit: int = 64 * 1024 * 1024) -> bytes:
    """seed -> root (§3).

    The `salt` is a FIXED app-domain constant (e.g. b"swifty/v1"); it is hashed to the
    16-byte libsodium salt. Security rests on `seed` being a high-entropy 256-bit secret
    (B3 rationale) — this is NOT a stretch for low-entropy secrets (a PIN/password, e.g.
    SVR §8.2, needs a per-user RANDOM salt instead). NOTE: §10 production baseline is
    m=256MiB,t=3,p=1 (use ARGON2ID_MEMLIMIT_PRODUCTION); the 64MiB default is reference/test."""
    if len(seed) < MIN_SECRET_LEN:
        raise ValueError("seed too short; argon2id here assumes a high-entropy 256-bit secret")
    salt16 = hashlib.sha256(salt).digest()[: nacl.pwhash.argon2id.SALTBYTES]
    return nacl.pwhash.argon2id.kdf(ROOT_LEN, seed, salt16, opslimit=opslimit, memlimit=memlimit)


def hkdf(root: bytes, label: str, length: int = KEY_LEN) -> bytes:
    """root + domain-separation label -> sub-key (§3). Deterministic."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label.encode()).derive(root)


def derive_wmk(root: bytes) -> bytes:
    return hkdf(root, WMK_LABEL)


def derive_coding_root(root: bytes) -> bytes:
    """Independent per-tier key tree for the coding tier (identity-envelope §3 / B7). The
    coding CVM receives ONLY this root; the personal WMK/transcript_root are NOT derivable
    from it (HKDF is one-way, so `coding_root` can't recover `root`). Worst-case blast
    radius of a coding-CVM compromise = coding-project data, never personal history."""
    return hkdf(root, CODING_LABEL)


def coding_wmk(coding_root: bytes) -> bytes:
    """Working-memory key WITHIN the coding tier (from coding_root, distinct label)."""
    return hkdf(coding_root, CODING_WMK_LABEL)


def coding_transcript_root(coding_root: bytes) -> bytes:
    return hkdf(coding_root, CODING_TRANSCRIPT_LABEL)


def derive_transcript_root(root: bytes) -> bytes:
    return hkdf(root, TRANSCRIPT_LABEL)


def derive_ed25519_private(root: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hkdf(root, GATEWAY_AUTH_LABEL))


def derive_ed25519_public(root: bytes) -> bytes:
    return derive_ed25519_private(root).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_account_id(root: bytes) -> str:
    """Zero-PII routing id, BOUND to the seed-derived Ed25519 key (B2-bis). Takes only root."""
    digest = hashlib.sha256(_ACCOUNT_ID_DOMAIN + derive_ed25519_public(root)).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")
