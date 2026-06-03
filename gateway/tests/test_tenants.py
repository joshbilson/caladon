"""Tests for tenant onboarding POST /v1/accounts (contracts/gateway-api.md §2).

account_id is bound to the Ed25519 key (ids.derive_account_id) — a caller can only
register the account_id derived from the key it proves possession of.
"""

from __future__ import annotations

import base64
import time

import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app.accounts import AccountRegistry
from app.deps import get_account_registry
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical

PATH = "/v1/accounts"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub_raw, base64.b64encode(pub_raw).decode()


def _acct(pub_raw: bytes) -> str:
    return derive_account_id(pub_raw)


def _pop_headers(priv, account_id, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = priv.sign(canonical(account_id, ts, "POST", PATH))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


@pytest_asyncio.fixture
async def client(tmp_path):
    app = create_app()
    registry = AccountRegistry(tmp_path / "accounts.json")
    app.dependency_overrides[get_account_registry] = lambda: registry
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_register_with_proof_of_possession_201(client):
    priv, pub_raw, pub = _keypair()
    acct = _acct(pub_raw)
    body = {"account_id": acct, "ed25519_pub": pub, "kem_pub": pub}
    resp = await client.post(PATH, json=body, headers=_pop_headers(priv, acct))
    assert resp.status_code == 201
    assert resp.json()["account_id"] == acct


async def test_register_is_idempotent_200(client):
    priv, pub_raw, pub = _keypair()
    acct = _acct(pub_raw)
    body = {"account_id": acct, "ed25519_pub": pub, "kem_pub": pub}
    assert (await client.post(PATH, json=body, headers=_pop_headers(priv, acct))).status_code == 201
    assert (await client.post(PATH, json=body, headers=_pop_headers(priv, acct))).status_code == 200


async def test_missing_proof_401(client):
    _, pub_raw, pub = _keypair()
    acct = _acct(pub_raw)
    body = {"account_id": acct, "ed25519_pub": pub, "kem_pub": pub}
    assert (await client.post(PATH, json=body)).status_code == 401


async def test_proof_by_wrong_key_401(client):
    """A request signed by a different key than the one being registered is rejected."""
    priv_attacker, _, _ = _keypair()
    _, victim_raw, victim_pub = _keypair()
    acct = _acct(victim_raw)
    body = {"account_id": acct, "ed25519_pub": victim_pub, "kem_pub": victim_pub}
    resp = await client.post(PATH, json=body, headers=_pop_headers(priv_attacker, acct))
    assert resp.status_code == 401


async def test_account_id_not_bound_to_key_400(client):
    """A validly PoP-signed request whose account_id is NOT derived from the key is rejected
    (anti-squatting): you cannot register an account_id you don't own."""
    priv, _pub_raw, pub = _keypair()
    wrong_acct = "wrong_0123456789abcdef"  # valid format, but != derive(key)
    body = {"account_id": wrong_acct, "ed25519_pub": pub, "kem_pub": pub}
    resp = await client.post(PATH, json=body, headers=_pop_headers(priv, wrong_acct))
    assert resp.status_code == 400
