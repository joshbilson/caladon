"""GET /v1/models — the model catalog for the in-app model picker.

Returns the FULL provider catalog, each entry flagged `attested` (True = runs in a hardware TEE,
confidential end-to-end; False = a non-confidential CLOUD model the gateway forwards to a third
party in the clear). The app populates its picker from this and LABELS the non-attested ones so the
user chooses knowingly; the gateway then routes each turn to the chosen model (see routes/chat.py).

PUBLIC (no seed-auth): the catalog is non-secret public provider metadata (the same list RedPill
publishes), and the single-origin shim — which holds NO key — proxies this route server-side to the
SPA's /api/models. Requiring auth here would force the keyless shim to forge a seed signature it
cannot produce. Nothing secret is exposed; the RedPill API key stays in the CVM and is never
returned. Prompts remain sealed end-to-end on the separate /v1/chat path.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import models_catalog
from app.config import Settings, get_settings

router = APIRouter()


@router.get("/v1/models")
async def models(settings: Settings = Depends(get_settings)) -> dict:
    if not settings.inference_base:
        return {"models": [], "default": settings.inference_model, "keepwarm": []}
    catalog = await models_catalog.fetch_all_models(base_url=settings.inference_base, api_key=settings.inference_key)
    return {
        "models": catalog,
        "default": settings.inference_model,
        "keepwarm": settings.keepwarm_set(),
    }
