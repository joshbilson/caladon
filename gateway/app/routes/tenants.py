"""Tenant onboarding (contracts/gateway-api.md §2: POST /v1/accounts).

Registration requires **proof of possession**: the request must be signed by the very
Ed25519 key being registered, over canonical(account_id, ts, POST, /v1/accounts). This
binds account_id <-> key holder so nobody can register an account_id they don't control.
The gateway cannot verify that account_id was HKDF-derived from the same seed as the key
(it has no seed) — that binding is the client's responsibility; documented as such.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from app.accounts import AccountRegistry
from app.deps import get_account_registry
from app.ids import derive_account_id
from app.seed_auth import AuthError, parse_auth_header, verify

router = APIRouter()


class RegisterAccount(BaseModel):
    account_id: str
    ed25519_pub: str  # base64, 32 raw bytes
    kem_pub: str      # base64


@router.post("/v1/accounts")
async def register_account(
    body: RegisterAccount,
    request: Request,
    response: Response,
    registry: AccountRegistry = Depends(get_account_registry),
) -> dict:
    # Proof of possession: the auth header must be signed by body.ed25519_pub and its
    # acct must equal body.account_id.
    try:
        auth = parse_auth_header(request.headers.get("authorization"))
        if auth.account_id != body.account_id:
            raise AuthError("account mismatch")
        pub = base64.b64decode(body.ed25519_pub, validate=True)
        verify(pub, auth, request.method, request.url.path)
    except (AuthError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized") from exc

    # Anti-squatting: account_id MUST be the value bound to the registered key, so a caller
    # can only ever register an account_id it controls (ids.derive_account_id).
    if body.account_id != derive_account_id(pub):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="account_id not bound to key")

    try:
        acct, created = registry.register(body.account_id, body.ed25519_pub, body.kem_pub)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid registration") from exc

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return {"account_id": acct.account_id}
