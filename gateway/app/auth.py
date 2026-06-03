import secrets

from fastapi import Depends, Header, HTTPException, status

from app.config import Settings, get_settings


async def require_token(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> str:
    tokens = settings.token_set()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    presented = authorization.removeprefix("Bearer ").strip()
    # constant-time compare against each configured token
    if not any(secrets.compare_digest(presented, t) for t in tokens):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return presented
