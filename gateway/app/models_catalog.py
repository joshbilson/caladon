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


async def fetch_all_models(*, base_url: str, api_key: str, timeout: float = 15.0, transport=None) -> list[dict]:
    """Return the FULL provider catalog: `[{id, name, context_length, pricing, attested}]`.
    `attested` is True for TEE-served (`phala/`-prefixed) models — a turn routed to them stays
    confidential end-to-end; the rest are non-confidential CLOUD models (the gateway opens the
    sealed prompt in-CVM, then forwards it to a third-party provider in the clear). The app
    surfaces ALL of them but must LABEL the non-attested ones so the user chooses knowingly
    (product decision 2026-06-05). Cached for `_TTL`; fails closed to the last good cache (or
    empty) on a transport error. `transport` is injectable for tests (httpx.MockTransport)."""
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
            "attested": m["id"].startswith(ATTESTED_PREFIX),
        }
        for m in data
        if isinstance(m.get("id"), str)
    ]
    # Attested (confidential) first, then alphabetical — a sensible default order for the picker.
    models.sort(key=lambda m: (not m["attested"], m["id"]))
    _CACHE[base_url] = (now, models)
    return models


async def fetch_attested_models(*, base_url: str, api_key: str, timeout: float = 15.0, transport=None) -> list[dict]:
    """The attested (TEE-served) subset of the catalog — used for keep-warm + attestation checks."""
    catalog = await fetch_all_models(base_url=base_url, api_key=api_key, timeout=timeout, transport=transport)
    return [m for m in catalog if m.get("attested")]


async def is_known_model(model: str, *, base_url: str, api_key: str, transport=None) -> bool:
    """True iff `model` is a real slug in the FULL provider catalog (attested OR cloud). Gates a
    per-request CLOUD model switch (only when the deployment opts into cloud models): we still
    refuse a slug that isn't a real provider model, but we DON'T require it to be attested."""
    if not model:
        return False
    models = await fetch_all_models(base_url=base_url, api_key=api_key, transport=transport)
    if not models:
        return False
    return any(m["id"] == model for m in models)


async def is_attested(model: str, *, base_url: str, api_key: str, transport=None) -> bool:
    """True iff `model` is in the attested catalog. Structural prefix check first (cheap,
    fail-closed for an obviously non-attested slug), then membership in the live catalog."""
    if not model or not model.startswith(ATTESTED_PREFIX):
        return False
    models = await fetch_attested_models(base_url=base_url, api_key=api_key, transport=transport)
    # Fail CLOSED: an empty catalog (unreachable / not yet confirmed) means we cannot POSITIVELY
    # verify this slug is TEE-served — the `phala/` prefix is attacker-controllable metadata, not
    # proof. Return False so the caller keeps the configured attested default instead of honoring
    # an unverified per-request slug. Membership is granted only against a confirmed live catalog.
    if not models:
        return False
    return any(m["id"] == model for m in models)
