"""GET /v1/models — the attested model catalog for the in-app model picker.

Returns ONLY models that run in a hardware TEE (the attested allowlist). The app populates its
picker from this so a user can switch models instantly and mid-session; the gateway then routes
each turn to the chosen attested model (see routes/chat.py). Seed-authed like every tenant route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import models_catalog
from app.config import Settings, get_settings
from app.deps import require_account

router = APIRouter()


@router.get("/v1/models")
async def models(
    account_id: str = Depends(require_account),
    settings: Settings = Depends(get_settings),
) -> dict:
    if not settings.inference_base:
        return {"models": [], "default": settings.inference_model, "keepwarm": []}
    catalog = await models_catalog.fetch_attested_models(base_url=settings.inference_base, api_key=settings.inference_key)
    return {
        "models": catalog,
        "default": settings.inference_model,
        "keepwarm": settings.keepwarm_set(),
    }
