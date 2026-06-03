"""Tests for GET /v1/attestation (contracts/gateway-api.md §2)."""

from __future__ import annotations

import base64
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app.accounts import AccountRegistry
from app.attestation import CvmAttestationProvider, PlainAttestationProvider
from app.deps import get_account_registry, get_attestation_provider
from app.main import create_app
from app.seed_auth import canonical

ACCT = "acct_0123456789abcdef"
PATH = "/v1/attestation"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(pub).decode()


def _headers(priv, account_id, path, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = priv.sign(canonical(account_id, ts, "GET", path))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


def _app(tmp_path, provider):
    app = create_app()
    registry = AccountRegistry(tmp_path / "accounts.json")
    app.dependency_overrides[get_account_registry] = lambda: registry
    app.dependency_overrides[get_attestation_provider] = lambda: provider
    return app, registry


async def test_requires_auth(tmp_path):
    app, _ = _app(tmp_path, PlainAttestationProvider())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get(f"{PATH}?challenge=abc")).status_code == 401


async def test_plain_mode_returns_none_regime(tmp_path):
    app, registry = _app(tmp_path, PlainAttestationProvider())
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"{PATH}?challenge=abc123", headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 200
    assert resp.json() == {"regime": "none", "tier": "self-host"}


async def test_cvm_mode_returns_bound_bundle(tmp_path):
    provider = CvmAttestationProvider(
        lambda ch: {"regime": "tdx-onchain", "challenge": ch, "intel_quote": "0400..."}
    )
    app, registry = _app(tmp_path, provider)
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"{PATH}?challenge=abc123", headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 200
    assert resp.json()["challenge"] == "abc123"
    assert resp.json()["regime"] == "tdx-onchain"


async def test_cvm_unbound_challenge_is_503(tmp_path):
    # the fetched bundle's challenge does NOT match the request -> fail-closed 503
    provider = CvmAttestationProvider(lambda ch: {"regime": "tdx-onchain", "challenge": "WRONG"})
    app, registry = _app(tmp_path, provider)
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"{PATH}?challenge=abc123", headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 503


async def test_missing_challenge_422(tmp_path):
    app, registry = _app(tmp_path, PlainAttestationProvider())
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(PATH, headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 422  # FastAPI required-param validation


async def test_cvm_fetch_network_error_is_503_not_500(tmp_path):
    def boom(challenge):
        raise ConnectionError("dstack agent unreachable")

    app, registry = _app(tmp_path, CvmAttestationProvider(boom))
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"{PATH}?challenge=abc123", headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 503  # any fetch error fails closed, never a 500 leak


async def test_cvm_bundle_without_challenge_key_is_503(tmp_path):
    app, registry = _app(tmp_path, CvmAttestationProvider(lambda ch: {"regime": "tdx-onchain"}))
    priv, pub = _keypair()
    registry.register(ACCT, pub, pub)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"{PATH}?challenge=abc123", headers=_headers(priv, ACCT, PATH))
    assert resp.status_code == 503


def test_invalid_run_mode_fails_loud():
    import pytest

    from app.config import Settings

    with pytest.raises(Exception):  # pydantic ValidationError on a non-Literal value
        Settings(run_mode="cvn")  # typo
