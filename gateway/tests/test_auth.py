"""Tests for seed-signature auth on /v1/whoami (contracts/gateway-api.md §1)."""

from __future__ import annotations

import base64
import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app.accounts import AccountRegistry
from app.deps import get_account_registry
from app.main import create_app
from app.seed_auth import canonical

ACCT = "acct_0123456789abcdef"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(pub_raw).decode()


def _headers(priv, account_id, method, path, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = priv.sign(canonical(account_id, ts, method, path))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


@pytest_asyncio.fixture
async def seed_client(tmp_path):
    app = create_app()
    registry = AccountRegistry(tmp_path / "accounts.json")
    app.dependency_overrides[get_account_registry] = lambda: registry
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c, registry


async def test_missing_auth_401(seed_client):
    client, _ = seed_client
    assert (await client.get("/v1/whoami")).status_code == 401


async def test_unknown_account_401(seed_client):
    client, _ = seed_client
    priv, _pub = _keypair()  # never registered
    resp = await client.get("/v1/whoami", headers=_headers(priv, ACCT, "GET", "/v1/whoami"))
    assert resp.status_code == 401


async def test_bad_signature_401(seed_client):
    client, registry = seed_client
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    # sign for a different path -> signature won't match /v1/whoami
    resp = await client.get("/v1/whoami", headers=_headers(priv, ACCT, "GET", "/v1/other"))
    assert resp.status_code == 401


async def test_valid_request_200(seed_client):
    client, registry = seed_client
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    resp = await client.get("/v1/whoami", headers=_headers(priv, ACCT, "GET", "/v1/whoami"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is True
    assert body["account_id"] == ACCT


async def test_stale_timestamp_401(seed_client):
    client, registry = seed_client
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    headers = _headers(priv, ACCT, "GET", "/v1/whoami", ts=int(time.time()) - 9999)
    assert (await client.get("/v1/whoami", headers=headers)).status_code == 401
