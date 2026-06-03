"""GET /v1/messages — seed-authed ciphertext router (gateway-api.md §2).

Cut over from M1b bearer + plaintext Messages to seed-auth + opaque envelopes from the
per-tenant transcript store. Asserts auth, tenant isolation, the limit clamp, and that the
response carries ONLY envelope fields (no plaintext).
"""

from __future__ import annotations

import base64
import time

import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app.accounts import AccountRegistry
from app.deps import get_account_registry, get_transcript_store
from app.envelope import Envelope
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical
from app.transcript import TranscriptStore

ENVELOPE_FIELDS = {"v", "alg", "kid", "nonce", "aad", "ct"}


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def _env(tag: bytes) -> Envelope:
    return Envelope(
        v=1,
        alg="xchacha20poly1305",
        kid="t:0",
        nonce=base64.b64encode(b"\x00" * 24).decode(),
        aad=base64.b64encode(b"aad").decode(),
        ct=base64.b64encode(tag * 16).decode(),
    )


def _auth(priv, account_id: str, method: str, path: str) -> dict:
    ts = int(time.time())
    sig = priv.sign(canonical(account_id, ts, method, path))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


@pytest_asyncio.fixture
async def ctx(tmp_path):
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    acct_a, acct_b = derive_account_id(pub_a), derive_account_id(pub_b)

    reg = AccountRegistry(tmp_path / "accounts.json")
    kem = base64.b64encode(b"kem").decode()
    reg.register(acct_a, base64.b64encode(pub_a).decode(), kem)
    reg.register(acct_b, base64.b64encode(pub_b).decode(), kem)

    store = TranscriptStore(tmp_path / "transcripts.json")
    store.append(acct_a, _env(b"\x01"))
    store.append(acct_a, _env(b"\x02"))  # A has two envelopes; B has none

    app = create_app()
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_transcript_store] = lambda: store
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield {"c": c, "priv_a": priv_a, "acct_a": acct_a, "priv_b": priv_b, "acct_b": acct_b}


async def test_requires_seed_auth(ctx):
    resp = await ctx["c"].get("/v1/messages")
    assert resp.status_code == 401
    # legacy bearer no longer grants access to the ciphertext router
    resp = await ctx["c"].get("/v1/messages", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 401


async def test_returns_only_opaque_envelopes_newest_last(ctx):
    headers = _auth(ctx["priv_a"], ctx["acct_a"], "GET", "/v1/messages")
    resp = await ctx["c"].get("/v1/messages", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    # ONLY envelope fields — no plaintext (role/content) leaked
    for row in body:
        assert set(row) == ENVELOPE_FIELDS
    assert body[0]["ct"] == base64.b64encode(b"\x01" * 16).decode()  # chronological tail
    assert body[1]["ct"] == base64.b64encode(b"\x02" * 16).decode()


async def test_tenant_isolation(ctx):
    # B signs validly but has no transcript -> sees [], never A's envelopes
    headers = _auth(ctx["priv_b"], ctx["acct_b"], "GET", "/v1/messages")
    resp = await ctx["c"].get("/v1/messages", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_limit_clamped_and_applied(ctx):
    headers = _auth(ctx["priv_a"], ctx["acct_a"], "GET", "/v1/messages")
    resp = await ctx["c"].get("/v1/messages?limit=1", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["ct"] == base64.b64encode(b"\x02" * 16).decode()  # the newest one
