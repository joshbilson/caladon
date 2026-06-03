"""GET /v1/attestation — the pre-send attestation handshake (contracts/gateway-api.md §2).

The client passes `challenge = SHA-256(eph_pub)` (attestation.md §3) and receives the
Agent CVM's evidence bundle to verify fail-closed before transmitting anything.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.attestation import AttestationError, AttestationProvider
from app.deps import get_attestation_provider, require_account

router = APIRouter()


@router.get("/v1/attestation")
async def attestation(
    challenge: str,
    account_id: str = Depends(require_account),
    provider: AttestationProvider = Depends(get_attestation_provider),
) -> dict:
    challenge = challenge.strip()
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing challenge")
    try:
        return provider.evidence_for(challenge)
    except AttestationError as exc:
        # Fail-closed: no evidence -> the client must not proceed.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="attestation unavailable"
        ) from exc
