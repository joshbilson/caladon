"""Opaque encryption envelope — the ONLY content shape the ciphertext router accepts.

`identity-envelope.md §4`. The gateway is a ciphertext router: it validates that a blob is
a *well-formed envelope* and never anything else, but it CANNOT and MUST NOT decrypt it (it
holds no key) nor interpret `aad` semantics. Validation here is therefore purely STRUCTURAL
and FAIL-CLOSED — its job is to guarantee the router never accidentally stores or forwards
a plaintext field. `extra="forbid"` is load-bearing: a stray `content`/`text` key (i.e.
plaintext leaking in) is rejected, not silently passed through.
"""

from __future__ import annotations

import base64

from pydantic import BaseModel, ConfigDict, field_validator

ALLOWED_ALGS = {"xchacha20poly1305"}
XCHACHA20_NONCE_LEN = 24  # 192-bit nonce (identity-envelope.md §1)
POLY1305_TAG_LEN = 16     # AEAD ciphertext always includes at least the 16-byte tag


def _b64_bytes(value: str, field: str) -> bytes:
    """Strict base64 decode; any non-base64 input fails closed."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty base64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field} is not valid base64") from exc


class Envelope(BaseModel):
    """Wire form: nonce/aad/ct are base64 strings. No plaintext fields permitted."""

    model_config = ConfigDict(extra="forbid")  # reject any field that isn't part of the envelope

    v: int
    alg: str
    kid: str
    nonce: str  # base64 -> 24 bytes
    aad: str    # base64 (opaque to the router; binds account_id||purpose||v on the client)
    ct: str     # base64 (AEAD ciphertext + tag)

    @field_validator("v")
    @classmethod
    def _v_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("envelope version must be >= 1")
        return v

    @field_validator("alg")
    @classmethod
    def _alg_allowed(cls, v: str) -> str:
        if v not in ALLOWED_ALGS:
            raise ValueError(f"unsupported alg (allowed: {sorted(ALLOWED_ALGS)})")
        return v

    @field_validator("kid")
    @classmethod
    def _kid_nonempty(cls, v: str) -> str:
        if not v:
            raise ValueError("kid must be non-empty")
        return v

    @field_validator("nonce")
    @classmethod
    def _nonce_len(cls, v: str) -> str:
        if len(_b64_bytes(v, "nonce")) != XCHACHA20_NONCE_LEN:
            raise ValueError(f"nonce must decode to exactly {XCHACHA20_NONCE_LEN} bytes")
        return v

    @field_validator("aad")
    @classmethod
    def _aad_present(cls, v: str) -> str:
        _b64_bytes(v, "aad")  # must decode; opaque otherwise
        return v

    @field_validator("ct")
    @classmethod
    def _ct_has_tag(cls, v: str) -> str:
        if len(_b64_bytes(v, "ct")) < POLY1305_TAG_LEN:
            raise ValueError("ct too short to contain an AEAD tag")
        return v
