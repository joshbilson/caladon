"""POST /v1/session — WMK delivery into the attested CVM (identity-envelope.md §6).

After the client verifies the CVM's attestation (`GET /v1/attestation`, which now carries the
CVM `session_pub`), it derives the session key SK and seals its working-memory key (WMK) to
SK. This endpoint receives that sealed WMK and the client's ephemeral X25519 pub, derives the
SAME SK in-CVM, opens the WMK into TEE RAM, and holds it for the session — never persisted.

T1 (`cvm`) only: in T0 (`plain`, operator == user) there is no remote enclave to receive a
key, so this is 501 (not applicable). Fail-closed: any decode/derive/open failure -> 400 with
no key/plaintext detail in the error.

**Contract amendment (additive, for ratification):** this endpoint + the `session_pub` field
in the attestation evidence extend `gateway-api.md §2`. See contract-review-sprint01.md.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from app.config import Settings, get_settings
from app.deps import get_session_manager, require_account
from app.envelope import Envelope
from app.session import SessionManager

router = APIRouter()


class EstablishSession(BaseModel):
    # extra='forbid': a stray `account_id` (or any field) in the body is REJECTED, not
    # silently ignored — the account is taken ONLY from the seed-auth identity (no
    # confused-deputy where a client thinks the body selects the account).
    model_config = ConfigDict(extra="forbid")
    client_eph_pub: str   # base64, 32 raw bytes (X25519 ephemeral public key)
    sealed_wmk: Envelope  # WMK sealed to SK (XChaCha20 envelope, purpose "wmk-delivery")


@router.post("/v1/session")
async def establish_session(
    body: EstablishSession,
    account_id: str = Depends(require_account),
    settings: Settings = Depends(get_settings),
    sessions: SessionManager = Depends(get_session_manager),
) -> dict:
    if settings.run_mode != "cvm":
        # No remote TEE in T0 (operator == user) -> WMK delivery is not applicable.
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="session delivery requires cvm mode"
        )
    try:
        eph = base64.b64decode(body.client_eph_pub, validate=True)
        if len(eph) != 32:
            raise ValueError("client_eph_pub must be 32 bytes")
        sessions.establish(
            account_id,
            eph,
            nonce=base64.b64decode(body.sealed_wmk.nonce, validate=True),
            aad=base64.b64decode(body.sealed_wmk.aad, validate=True),
            ct=base64.b64decode(body.sealed_wmk.ct, validate=True),
            v=body.sealed_wmk.v,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed; never leak key/plaintext detail
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="session establishment failed"
        ) from exc
    return {"session": "established"}
