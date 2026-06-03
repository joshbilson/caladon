from fastapi import APIRouter, Depends

from app.config import Settings, get_settings

router = APIRouter()


@router.get("/health")
async def health(settings: Settings = Depends(get_settings)) -> dict:
    # mode reflects the deployment trust tier (docs/deployment-tiers.md); no auth.
    return {"status": "ok", "mode": settings.run_mode}
