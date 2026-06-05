"""POST /v1/chat — confidential live turn (gateway-api §2-§3). Prompt sealed to SK in,
sealed deltas out; the client opens the deltas under SK to recover plaintext."""

from __future__ import annotations

import base64
import json
import time

import nacl.bindings as sodium
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app import session as sess
from app.accounts import AccountRegistry
from app.config import Settings, get_settings
from app.deps import get_account_registry, get_inference, get_letta, get_session_manager
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical
from tests.conftest import FakeLetta


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _auth(priv, account_id, method, path):
    ts = int(time.time())
    sig = priv.sign(canonical(account_id, ts, method, path))
    return {"Authorization": f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"}


def _seal_prompt(sk, account_id, text):
    nonce, aad, ct = sess._seal(sk, text.encode(), account_id=account_id, purpose=sess.CHAT_PURPOSE, v=1)
    return {"envelope": {"v": 1, "alg": "xchacha20poly1305", "kid": "chat",
                         "nonce": base64.b64encode(nonce).decode(),
                         "aad": base64.b64encode(aad).decode(),
                         "ct": base64.b64encode(ct).decode()}}


@pytest_asyncio.fixture
async def ctx(tmp_path):
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())

    mgr = sess.SessionManager()
    # establish a session: client derives SK, seals a WMK, delivers it
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    wn, wa, wc = sess._seal(sk, b"\xab" * 32, account_id=acct, purpose=sess.WMK_DELIVERY_PURPOSE, v=1)
    mgr.establish(acct, cpub, nonce=wn, aad=wa, ct=wc, v=1)

    fake = FakeLetta()

    async def _stream(text):
        assert text == "hello agent"  # the gateway decrypted the prompt correctly
        yield {"message_type": "assistant_message", "content": "Hi there"}

    fake.stream_chat = _stream  # type: ignore

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(run_mode="cvm", device_tokens="x")
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    app.dependency_overrides[get_letta] = lambda: fake
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield {"c": c, "priv": priv, "acct": acct, "sk": sk}


async def test_requires_auth(ctx):
    resp = await ctx["c"].post("/v1/chat", json={"envelope": {}})
    assert resp.status_code == 401


async def test_sealed_round_trip(ctx):
    body = _seal_prompt(ctx["sk"], ctx["acct"], "hello agent")
    resp = await ctx["c"].post("/v1/chat", json=body, headers=_auth(ctx["priv"], ctx["acct"], "POST", "/v1/chat"))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body_text = resp.text
    # No plaintext delta in the stream — only sealed envelopes
    assert "Hi there" not in body_text
    assert "event: token" in body_text and "event: done" in body_text and "event: receipt" in body_text

    # The client opens the token envelope under SK and recovers the plaintext delta.
    token_line = [ln for ln in body_text.splitlines() if ln.startswith("data:") and "envelope" in ln][0]
    env = json.loads(token_line[len("data:"):].strip())["envelope"]
    pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        base64.b64decode(env["ct"]), base64.b64decode(env["aad"]), base64.b64decode(env["nonce"]), ctx["sk"]
    )
    assert pt == b"Hi there"


async def test_tool_loop_path(tmp_path, monkeypatch):
    """tools:true routes the turn through the in-CVM tool loop on the function-calling model, seals
    each tool step + the final answer, and never leaks plaintext."""
    from app import inference_backend
    from app.deps import get_receipt_fetcher

    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    mgr = sess.SessionManager()
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    wn, wa, wc = sess._seal(sk, b"\xab" * 32, account_id=acct, purpose=sess.WMK_DELIVERY_PURPOSE, v=1)
    mgr.establish(acct, cpub, nonce=wn, aad=wa, ct=wc, v=1)

    seen = {}

    async def fake_with_tools(*, base_url, api_key, model, messages, tools, execute_tool, max_steps, timeout):
        seen["model"] = model
        seen["prompt"] = messages[0]["content"]
        seen["tool_names"] = [t["function"]["name"] for t in tools]
        return "The answer is 391.", [{"tool": "calculator", "args": {"expression": "23*17"}, "result": "391"}]

    monkeypatch.setattr(inference_backend, "complete_with_tools", fake_with_tools)

    async def dummy_complete(prompt, model=None):  # present so use_tools sees inference != None
        return "unused"

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(
        run_mode="cvm", device_tokens="x", inference_base="http://prov", inference_key="k",
        tool_model="phala/deepseek-v3.2", receipt_enabled=False,
    )
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    app.dependency_overrides[get_inference] = lambda: dummy_complete
    app.dependency_overrides[get_receipt_fetcher] = lambda: None
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        body = {**_seal_prompt(sk, acct, "what is 23*17"), "tools": True}
        resp = await c.post("/v1/chat", json=body, headers=_auth(priv, acct, "POST", "/v1/chat"))
    assert resp.status_code == 200
    text = resp.text
    assert seen["model"] == "phala/deepseek-v3.2"      # tool turn forced onto the FC-capable model
    assert seen["prompt"] == "what is 23*17"           # gateway decrypted the prompt
    assert "calculator" in seen["tool_names"]
    assert "391" not in text                            # nothing plaintext on the wire
    assert "event: tool" in text and "event: token" in text and "event: done" in text
    # Decrypt the sealed tool step + the final token.
    lines = [ln for ln in text.splitlines() if ln.startswith("data:") and "envelope" in ln]
    opened = []
    for ln in lines:
        env = json.loads(ln[len("data:"):].strip())["envelope"]
        opened.append(
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                base64.b64decode(env["ct"]), base64.b64decode(env["aad"]), base64.b64decode(env["nonce"]), sk
            ).decode()
        )
    assert any("calculator" in o and "391" in o for o in opened)   # the sealed tool step
    assert "The answer is 391." in opened                          # the sealed final answer


async def test_no_session_returns_428(tmp_path):
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    mgr = sess.SessionManager()  # no session established
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(run_mode="cvm", device_tokens="x")
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        body = {"envelope": {"v": 1, "alg": "xchacha20poly1305", "kid": "chat",
                             "nonce": base64.b64encode(b"\x00" * 24).decode(),
                             "aad": base64.b64encode(b"\x00" * 32).decode(),
                             "ct": base64.b64encode(b"\x00" * 32).decode()}}
        resp = await c.post("/v1/chat", json=body, headers=_auth(priv, acct, "POST", "/v1/chat"))
    assert resp.status_code == 428


async def test_inference_backend_round_trip(tmp_path):
    """v1 attested-inference path: the gateway opens the sealed prompt, calls the (faked)
    attested provider, and seals the answer back; the client recovers it under SK."""
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    reg = AccountRegistry(tmp_path / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    mgr = sess.SessionManager()
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    wn, wa, wc = sess._seal(sk, b"\xab" * 32, account_id=acct, purpose=sess.WMK_DELIVERY_PURPOSE, v=1)
    mgr.establish(acct, cpub, nonce=wn, aad=wa, ct=wc, v=1)

    seen = {}

    async def fake_complete(prompt, model=None):
        seen["prompt"] = prompt
        seen["model"] = model
        return "Hi from the enclave"

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(run_mode="cvm", device_tokens="x")
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    app.dependency_overrides[get_inference] = lambda: fake_complete
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        body = _seal_prompt(sk, acct, "hello enclave")
        resp = await c.post("/v1/chat", json=body, headers=_auth(priv, acct, "POST", "/v1/chat"))
    assert resp.status_code == 200
    assert seen["prompt"] == "hello enclave"          # gateway decrypted the prompt
    text = resp.text
    assert "Hi from the enclave" not in text          # answer never on the wire in plaintext
    assert "event: token" in text and "event: done" in text
    line = [ln for ln in text.splitlines() if ln.startswith("data:") and "envelope" in ln][0]
    env = json.loads(line[len("data:"):].strip())["envelope"]
    pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        base64.b64decode(env["ct"]), base64.b64decode(env["aad"]), base64.b64decode(env["nonce"]), sk
    )
    assert pt == b"Hi from the enclave"               # client recovers the sealed answer
