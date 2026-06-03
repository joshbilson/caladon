"""Multi-tenant seed-signature auth for the ciphertext-router gateway.

See `contracts/gateway-api.md §1`. The client derives an Ed25519 signing key from its seed
(`identity-envelope.md §1`, label `swifty/gateway-auth/v1`) and registers the public key at
onboarding. Every request carries:

    Authorization: Swifty acct=<account_id> ts=<unix> sig=<base64 Ed25519 sig>

signed over `canonical(acct, ts, METHOD, path)`. No bearer tokens, no PII. The gateway only
*verifies* — it never holds or derives any key. Verification is constant-time at the
crypto layer (Ed25519). Replays are bounded by a freshness window; full single-use nonce
tracking can layer on top later if needed.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.ids import validate_account_id

# Accept timestamps within ±window of now (anti-replay). Contract §1 says ±120s.
FRESHNESS_WINDOW_S = 120


class AuthError(Exception):
    """Any auth failure -> the route layer maps this to HTTP 401 (no PII in the message)."""


@dataclass(frozen=True)
class AuthRequest:
    account_id: str
    ts: int
    sig: bytes


def parse_auth_header(value: str | None) -> AuthRequest:
    """Parse `Authorization: Swifty acct=.. ts=.. sig=..`. Raises AuthError if malformed."""
    if not value or not value.startswith("Swifty "):
        raise AuthError("missing Swifty authorization")
    fields: dict[str, str] = {}
    for part in value.removeprefix("Swifty ").strip().split():
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v
    try:
        account_id = fields["acct"]
        ts = int(fields["ts"])
        sig = base64.b64decode(fields["sig"], validate=True)
    except (KeyError, ValueError) as exc:
        raise AuthError(f"malformed authorization: {exc}") from exc
    if not account_id or not sig:
        raise AuthError("empty account or signature")
    try:
        validate_account_id(account_id)
    except ValueError as exc:
        raise AuthError("invalid account id") from exc
    return AuthRequest(account_id=account_id, ts=ts, sig=sig)


def canonical(account_id: str, ts: int, method: str, path: str) -> bytes:
    """The exact bytes the client signs and the gateway verifies. Newline-delimited so the
    fields cannot be ambiguously re-segmented.

    `path` is the raw URI path component only — NO query string, NO trailing-slash
    normalisation. The gateway verifies against `request.url.path`; any reverse proxy in
    front MUST preserve the path byte-for-byte or signatures will fail (deploy note in
    contracts/gateway-api.md). `method` is upper-cased so case can't cause a mismatch."""
    return f"{account_id}\n{ts}\n{method.upper()}\n{path}".encode()


def verify(
    pubkey_raw: bytes,
    req: AuthRequest,
    method: str,
    path: str,
    *,
    now: int | None = None,
) -> None:
    """Verify freshness + Ed25519 signature. Raises AuthError on any failure; returns None
    on success. `pubkey_raw` is the 32-byte Ed25519 public key registered for the account."""
    current = int(time.time()) if now is None else now
    if abs(current - req.ts) > FRESHNESS_WINDOW_S:
        raise AuthError("stale or future timestamp")
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(
            req.sig, canonical(req.account_id, req.ts, method, path)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthError("invalid signature") from exc
