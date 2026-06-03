"""Validation for `account_id` — a 256-bit, zero-PII routing identifier
(`identity-envelope.md §3`, Gate-0 resolution B2: 256-bit, url-safe encoded).

Bounded + charset-restricted so attacker-controlled values can't bloat the canonical
signed message, the registry, or any downstream interpolation. Accepts url-safe base64
(43 chars) or hex (64 chars); the [16,128] bound is generous but hard.
"""

from __future__ import annotations

import base64
import hashlib
import re

# url-safe base64 / hex alphabet; length bounded.
ACCOUNT_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")

# Domain-separated label binding account_id to the gateway-auth key.
_ACCOUNT_ID_LABEL = b"swifty/account/v1"


def validate_account_id(account_id: str) -> str:
    if not isinstance(account_id, str) or not ACCOUNT_ID_RE.fullmatch(account_id):
        raise ValueError("invalid account_id format")
    return account_id


def derive_account_id(ed25519_pub: bytes) -> str:
    """account_id BOUND to the auth key: url-safe b64 of SHA-256(label || ed25519_pub),
    no padding (43 chars). Because the value is a function of the registered key, the
    gateway can verify at onboarding that a caller owns the account_id it claims —
    eliminating account-id squatting (code-review iter-3 finding #1).

    PROPOSED amendment to identity-envelope.md §3/B2 (account_id was HKDF(root,...));
    DECISION TAKEN UNATTENDED, flagged for Josh ratification in
    docs/security/contract-review-sprint01.md. The client MUST derive account_id this way.
    Still zero-PII and deterministic from the seed (the key is seed-derived)."""
    digest = hashlib.sha256(_ACCOUNT_ID_LABEL + ed25519_pub).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")
