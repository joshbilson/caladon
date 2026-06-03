"""Transcript read endpoint — ciphertext router (gateway-api.md §2).

`GET /v1/messages` returns the tenant's transcript as **opaque envelopes** newest-last.
Seed-authed (multi-tenant); the gateway never decrypts and never touches Letta here — the
transcript is client-ratcheted ciphertext (identity-envelope.md §5.1). This SUPERSEDES the
M1b bearer + plaintext-Message path for the confidential target.
"""

from fastapi import APIRouter, Depends

from app.deps import get_transcript_store, require_account
from app.transcript import TranscriptStore

router = APIRouter()


@router.get("/v1/messages")
async def list_messages(
    limit: int = 50,
    account_id: str = Depends(require_account),
    store: TranscriptStore = Depends(get_transcript_store),
) -> list[dict]:
    # Only the authenticated tenant's own log is addressable (isolation). Opaque envelopes.
    limit = max(0, min(limit, 500))  # clamp; never an unbounded read
    return store.list(account_id, limit=limit)
