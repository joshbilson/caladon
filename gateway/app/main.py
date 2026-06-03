import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI

from app.config import get_settings
from app.deps import require_account
from app.routes import attestation, chat, health, messages, models, session, tenants

_log = logging.getLogger("swifty.keepwarm")


async def _keep_warm(app: FastAPI) -> None:
    """Periodically ping the curated attested models so they stay hot (no cold-start delay when a
    user picks one). One tiny non-streaming completion per model per interval. Best-effort: any
    error is swallowed (a model being briefly unreachable must not crash the loop)."""
    from app import inference_backend

    s = get_settings()
    targets = s.keepwarm_set()
    if not (s.inference_base and s.keepwarm_interval > 0 and targets):
        return
    while True:
        for m in targets:
            try:
                await inference_backend.complete(
                    base_url=s.inference_base, api_key=s.inference_key, model=m,
                    prompt="ok", timeout=min(60.0, s.inference_timeout),
                )
            except Exception as exc:  # noqa: BLE001 - keep-warm is best-effort
                _log.debug("keep-warm ping failed for %s: %s", m, type(exc).__name__)
        await asyncio.sleep(s.keepwarm_interval)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    task = asyncio.create_task(_keep_warm(app))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def create_app() -> FastAPI:
    app = FastAPI(title="Swifty Gateway", version="0.1.0", lifespan=_lifespan)
    app.include_router(health.router)
    app.include_router(tenants.router)
    app.include_router(attestation.router)
    app.include_router(session.router)   # POST /v1/session — WMK delivery into the CVM (§6)
    app.include_router(messages.router)  # seed-auth ciphertext router (envelope cutover done)
    app.include_router(models.router)     # GET /v1/models — attested catalog for the in-app picker
    app.include_router(chat.router)       # POST /v1/chat — sealed turn, per-request attested model

    @app.get("/v1/whoami")
    async def whoami(account_id: str = Depends(require_account)) -> dict:
        # Seed-signature auth (contracts/gateway-api.md §1); returns the routing account_id.
        return {"authenticated": True, "account_id": account_id, "tier": "chat"}

    return app


app = create_app()
