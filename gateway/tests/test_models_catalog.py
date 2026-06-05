"""Attested-model catalog + per-request model selection (trust-no-one allowlist).

The gateway only routes a turn to a TEE-served (`phala/`) model; a client can't downgrade onto a
non-confidential backend. /v1/models feeds the in-app picker (instant + mid-session switching).
"""

from __future__ import annotations

import base64
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app import models_catalog
from app.accounts import AccountRegistry
from app.config import Settings, get_settings
from app.deps import get_account_registry
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical

CATALOG = {
    "data": [
        {"id": "phala/kimi-k2.6", "name": "Kimi K2.6", "context_length": 262144, "pricing": {"prompt": "1"}},
        {"id": "phala/qwen3.6-35b-a3b-uncensored", "name": "Qwen Uncensored", "context_length": 131072},
        {"id": "qwen/qwen-2.5-7b-instruct", "name": "NON-attested upstream alias"},
        {"id": "openai/gpt-4o", "name": "NON-attested"},
    ]
}


def _catalog_transport(captured=None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append(str(request.url))
        return httpx.Response(200, json=CATALOG)

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _clear_cache():
    models_catalog._CACHE.clear()
    yield
    models_catalog._CACHE.clear()


async def test_fetch_filters_to_attested_only():
    out = await models_catalog.fetch_attested_models(
        base_url="https://api.x/v1", api_key="k", transport=_catalog_transport()
    )
    ids = [m["id"] for m in out]
    assert ids == ["phala/kimi-k2.6", "phala/qwen3.6-35b-a3b-uncensored"]  # only phala/, sorted
    assert all(m["id"].startswith("phala/") for m in out)
    assert all(m["attested"] is True for m in out)


async def test_fetch_all_models_returns_full_catalog_with_flag():
    out = await models_catalog.fetch_all_models(
        base_url="https://api.x/v1", api_key="k", transport=_catalog_transport()
    )
    ids = [m["id"] for m in out]
    # All 4 returned; attested (phala/) FIRST, each ordered by id; flag set per model.
    assert ids == [
        "phala/kimi-k2.6",
        "phala/qwen3.6-35b-a3b-uncensored",
        "openai/gpt-4o",
        "qwen/qwen-2.5-7b-instruct",
    ]
    flags = {m["id"]: m["attested"] for m in out}
    assert flags["phala/kimi-k2.6"] is True
    assert flags["openai/gpt-4o"] is False
    assert flags["qwen/qwen-2.5-7b-instruct"] is False


async def test_is_known_model():
    tx = _catalog_transport()
    base = dict(base_url="https://api.k/v1", api_key="k", transport=tx)
    assert await models_catalog.is_known_model("phala/kimi-k2.6", **base) is True   # attested, known
    assert await models_catalog.is_known_model("openai/gpt-4o", **base) is True     # cloud, known
    assert await models_catalog.is_known_model("openai/not-real", **base) is False  # not in catalog
    assert await models_catalog.is_known_model("", **base) is False


async def test_fetch_caches(monkeypatch):
    cap: list = []
    tx = _catalog_transport(cap)
    await models_catalog.fetch_attested_models(base_url="https://api.y/v1", api_key="k", transport=tx)
    await models_catalog.fetch_attested_models(base_url="https://api.y/v1", api_key="k", transport=tx)
    assert len(cap) == 1  # second call served from cache, not re-fetched


async def test_is_attested():
    tx = _catalog_transport()
    base = dict(base_url="https://api.z/v1", api_key="k", transport=tx)
    assert await models_catalog.is_attested("phala/kimi-k2.6", **base) is True
    assert await models_catalog.is_attested("qwen/qwen-2.5-7b-instruct", **base) is False  # not phala/
    assert await models_catalog.is_attested("openai/gpt-4o", **base) is False
    assert await models_catalog.is_attested("", **base) is False


async def test_unreachable_catalog_fails_closed_to_empty():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    out = await models_catalog.fetch_attested_models(
        base_url="https://api.dead/v1", api_key="k", transport=httpx.MockTransport(boom)
    )
    assert out == []  # never raises; empty list


def _acct():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, derive_account_id(pub), base64.b64encode(pub).decode()


def _auth(priv, acct, method, path):
    ts = int(time.time())
    sig = priv.sign(canonical(acct, ts, method, path))
    return {"Authorization": f"Swifty acct={acct} ts={ts} sig={base64.b64encode(sig).decode()}"}


async def test_v1_models_route_returns_full_catalog_public(tmp_path, monkeypatch):
    """The picker route returns the FULL catalog (attested + cloud, each flagged) and is PUBLIC —
    the keyless shim proxies it server-side, so it must not require seed-auth. Non-secret data."""
    async def fake_fetch(*, base_url, api_key, **kw):
        return [
            {"id": "phala/kimi-k2.6", "name": "Kimi K2.6", "attested": True},
            {"id": "openai/gpt-4o", "name": "GPT-4o", "attested": False},
        ]

    monkeypatch.setattr(models_catalog, "fetch_all_models", fake_fetch)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(
        inference_base="https://api.x/v1", inference_model="phala/qwen3.6-35b-a3b-uncensored",
        keepwarm_models="phala/qwen3.6-35b-a3b-uncensored,phala/kimi-k2.6", device_tokens="x",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/v1/models")  # NO auth header — route is public
    assert resp.status_code == 200
    body = resp.json()
    ids = [m["id"] for m in body["models"]]
    assert ids == ["phala/kimi-k2.6", "openai/gpt-4o"]
    assert {m["id"]: m["attested"] for m in body["models"]} == {
        "phala/kimi-k2.6": True,
        "openai/gpt-4o": False,
    }
    assert body["default"] == "phala/qwen3.6-35b-a3b-uncensored"
    assert set(body["keepwarm"]) == {"phala/qwen3.6-35b-a3b-uncensored", "phala/kimi-k2.6"}


async def test_per_request_model_selection(monkeypatch):
    """Attested per-request model is honoured; a non-attested one falls back to the configured
    default (trust-no-one: never route a prompt to a non-confidential model)."""
    from app import deps, inference_backend
    from app import models_catalog as mc

    captured: dict = {}

    async def fake_complete(*, base_url, api_key, model, prompt, timeout):
        captured["model"] = model
        return "ok"

    async def fake_is_attested(model, **kw):
        return model == "phala/kimi-k2.6"

    monkeypatch.setattr(inference_backend, "complete", fake_complete)
    monkeypatch.setattr(mc, "is_attested", fake_is_attested)

    # allow_cloud_models=False makes this the strict path: a non-attested slug must fall back.
    complete = deps.get_inference(
        Settings(inference_base="https://api.x/v1", inference_model="phala/default", allow_cloud_models=False)
    )
    await complete("hi", "phala/kimi-k2.6")
    assert captured["model"] == "phala/kimi-k2.6"        # attested override honoured
    await complete("hi", "phala/not-attested")
    assert captured["model"] == "phala/default"          # non-attested -> default (strict)
    await complete("hi", None)
    assert captured["model"] == "phala/default"          # unset -> default


async def test_per_request_cloud_model_opt_in(monkeypatch):
    """With GATEWAY_ALLOW_CLOUD_MODELS=true, a KNOWN non-attested (cloud) slug is honoured; an
    UNKNOWN slug still falls back to the default (fail-closed on garbage)."""
    from app import deps, inference_backend
    from app import models_catalog as mc

    captured: dict = {}

    async def fake_complete(*, base_url, api_key, model, prompt, timeout):
        captured["model"] = model
        return "ok"

    async def fake_is_attested(model, **kw):
        return model.startswith("phala/")

    async def fake_is_known(model, **kw):
        return model in {"openai/gpt-4o", "phala/default"}

    monkeypatch.setattr(inference_backend, "complete", fake_complete)
    monkeypatch.setattr(mc, "is_attested", fake_is_attested)
    monkeypatch.setattr(mc, "is_known_model", fake_is_known)

    complete = deps.get_inference(
        Settings(inference_base="https://api.x/v1", inference_model="phala/default", allow_cloud_models=True)
    )
    await complete("hi", "openai/gpt-4o")
    assert captured["model"] == "openai/gpt-4o"   # cloud model honoured under opt-in
    await complete("hi", "openai/not-real")
    assert captured["model"] == "phala/default"   # unknown slug -> default (fail-closed)
