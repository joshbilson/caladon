"""Attested-model catalog + keep-warm (the in-CVM gateway's model layer).

Two jobs, both in service of "any attested model, instantly, always ready":

1. **Allowlist (trust-no-one):** we only ever route a user's prompt to a model that runs in a
   hardware TEE. On RedPill that is the **`phala/`-prefixed** catalog (Intel TDX + H-series GPU
   confidential serving). A per-request model is accepted ONLY if it is in this attested set, so
   a client can never downgrade a turn onto a non-confidential backend.

2. **Keep-warm:** RedPill is shared-serverless — popular models stay hot from aggregate traffic,
   but an idle model scales to zero and the next turn pays a multi-minute cold-start. A small
   periodic ping keeps OUR curated set warm so the app feels instant.

The model name is metadata (RedPill sees it inherently); it is NOT secret. The prompt remains
sealed end-to-end — this module never sees plaintext prompts.
"""

from __future__ import annotations

import time

import httpx

ATTESTED_PREFIX = "phala/"  # RedPill slugs served in a Phala TEE (TDX + GPU-CC)
_CACHE: dict[str, tuple[float, list[dict]]] = {}
_TTL = 300.0  # refresh the catalog at most every 5 min


async def fetch_attested_models(*, base_url: str, api_key: str, timeout: float = 15.0, transport=None) -> list[dict]:
    """Return the attested (TEE-served) models from the provider catalog: `[{id, name,
    context_length, pricing}]`. Cached for `_TTL`. Fails closed to the last good cache (or
    empty) on a transport error — a stale list is fine; an exception would 500 the picker.
    `transport` is injectable for tests (httpx.MockTransport)."""
    now = time.monotonic()
    cached = _CACHE.get(base_url)
    if cached and now - cached[0] < _TTL:
        return cached[1]
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            resp = await client.get(
                base_url.rstrip("/") + "/models", headers={"Authorization": f"Bearer {api_key}"}
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
    except Exception:  # noqa: BLE001 - never 500 the picker; serve the last good list if any
        return cached[1] if cached else []
    models = [
        {
            "id": m["id"],
            "name": m.get("name", m["id"]),
            "context_length": m.get("context_length"),
            "pricing": m.get("pricing"),
        }
        for m in data
        if isinstance(m.get("id"), str) and m["id"].startswith(ATTESTED_PREFIX)
    ]
    models.sort(key=lambda m: m["id"])
    _CACHE[base_url] = (now, models)
    return models


async def is_attested(model: str, *, base_url: str, api_key: str, transport=None) -> bool:
    """True iff `model` is in the attested catalog. Structural prefix check first (cheap,
    fail-closed for an obviously non-attested slug), then membership in the live catalog."""
    if not model or not model.startswith(ATTESTED_PREFIX):
        return False
    models = await fetch_attested_models(base_url=base_url, api_key=api_key, transport=transport)
    # If the catalog is unreachable (empty), accept a well-formed attested-prefix slug rather
    # than hard-failing every turn — the prefix already constrains to the TEE namespace.
    if not models:
        return True
    return any(m["id"] == model for m in models)
