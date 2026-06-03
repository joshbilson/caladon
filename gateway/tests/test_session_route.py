"""POST /v1/session — WMK delivery endpoint (gateway-api §2 amendment; identity-envelope §6)."""

from __future__ import annotations

import base64
import time

import nacl.bindings as sodium
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app import session as sess
from app.accounts import AccountRegistry
from app.config import Settings, get_settings
from app.deps import get_account_registry, get_session_manager
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical

WMK = b"\xab" * 32


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def _auth(priv, account_id, method, path):
    ts = int(time.time())
    sig = priv.sign(canonical(account_id, ts, method, path))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


def _sealed_wmk_body(client_eph_pub: bytes, sk: bytes, account_id: str) -> dict:
    aad = sess._aad(account_id, sess.WMK_DELIVERY_PURPOSE, 1)
    nonce = sodium.randombytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(WMK, aad, nonce, sk)
    return {
        "client_eph_pub": base64.b64encode(client_eph_pub).decode(),
        "sealed_wmk": {
            "v": 1, "alg": "xchacha20poly1305", "kid": "v1",
            "nonce": base64.b64encode(nonce).decode(),
            "aad": base64.b64encode(aad).decode(),
            "ct": base64.b64encode(ct).decode(),
        },
    }


@pytest_asyncio.fixture
async def ctx(tmp_path):
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "accounts.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    mgr = sess.SessionManager()
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(run_mode="cvm", device_tokens="x")
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield {"c": c, "priv": priv, "acct": acct, "mgr": mgr}


async def test_requires_auth(ctx):
    resp = await ctx["c"].post("/v1/session", json={"client_eph_pub": "AA==", "sealed_wmk": {}})
    assert resp.status_code == 401


async def test_establishes_session_and_holds_wmk(ctx):
    mgr = ctx["mgr"]
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    body = _sealed_wmk_body(cpub, sk, ctx["acct"])
    resp = await ctx["c"].post("/v1/session", json=body, headers=_auth(ctx["priv"], ctx["acct"], "POST", "/v1/session"))
    assert resp.status_code == 200
    assert resp.json()["session"] == "established"
    assert mgr.wmk_for(ctx["acct"]) == WMK  # WMK opened into TEE-RAM


async def test_bad_sealed_wmk_fails_closed(ctx):
    mgr = ctx["mgr"]
    cpriv, cpub = sess.x25519_keypair()
    # seal under a WRONG key -> open fails -> 400, no detail leak
    body = _sealed_wmk_body(cpub, b"\x00" * 32, ctx["acct"])
    resp = await ctx["c"].post("/v1/session", json=body, headers=_auth(ctx["priv"], ctx["acct"], "POST", "/v1/session"))
    assert resp.status_code == 400
    assert mgr.wmk_for(ctx["acct"]) is None


async def test_extra_body_field_rejected(ctx):
    # A stray account_id (confused-deputy attempt) in the body must be REJECTED (422), not
    # silently ignored — the account is taken only from the seed-auth identity.
    mgr = ctx["mgr"]
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    body = _sealed_wmk_body(cpub, sk, ctx["acct"])
    body["account_id"] = "someone_else_0123456789"
    resp = await ctx["c"].post("/v1/session", json=body, headers=_auth(ctx["priv"], ctx["acct"], "POST", "/v1/session"))
    assert resp.status_code == 422


async def test_plain_mode_not_applicable(tmp_path):
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(run_mode="plain", device_tokens="x")
    app.dependency_overrides[get_account_registry] = lambda: reg
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        cpriv, cpub = sess.x25519_keypair()
        body = _sealed_wmk_body(cpub, b"\x00" * 32, acct)
        resp = await c.post("/v1/session", json=body, headers=_auth(priv, acct, "POST", "/v1/session"))
    assert resp.status_code == 501
