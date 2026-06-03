"""Per-response inference receipt (Caladon trust-fix-B).

RedPill is the attested-inference provider; its per-response attestation is the endpoint
`GET /v1/attestation/report?model=<slug>` (NOT a response header — `x-redpill-provider` varies,
we saw `phala` AND `near-ai`; see internal spike notes (d)). 2-PHASE ROLLOUT:

  OBSERVE (default): /v1/chat surfaces the receipt fields (provider/model/app_id/compose_hash/
    no_log/signing_address/quote_present) WITHOUT enforcing an allowlist.
  ENFORCE (allowlist set): the turn fails CLOSED — error event, reply dropped — if the serving
    enclave's app_id/compose_hash is not allowed OR no_log is not explicitly true.

The gateway does NOT verify the quote here (the in-client quote verification is the client's
job); the receipt only surfaces what the provider attests, flagged `quote_verified_pending`.
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from app import inference_backend, session as sess
from app.accounts import AccountRegistry
from app.config import Settings, get_settings
from app.deps import (
    get_account_registry,
    get_inference,
    get_receipt_fetcher,
    get_session_manager,
)
from app.ids import derive_account_id
from app.main import create_app
from app.seed_auth import canonical

# A representative RedPill /v1/attestation/report body (fields from the real spike sample,
# a captured attestation report — app_id/compose_hash/signing_address).
SAMPLE_REPORT = {
    "signing_address": "0x4c4E5E69FAdffB8e55C306d867dc88792bd3221D",
    "signing_algo": "ecdsa",
    "request_nonce": "d722376784b491577d7b92566d84abba0ddad02bcb41b5f4dd520779376bace9",
    "intel_quote": "0400020081000000deadbeef",
    "nvidia_payload": "cafe",
    "info": {
        "app_id": "9d31963336e6b0bdf8ba4c27b97442a818dd05fd",
        "compose_hash": "537b750f6e99972db6d6ea24232ecf0c5826136f3e32704ad2936de75fca14a1",
        "instance_id": "abc",
    },
    "no_log": True,
}


# --------------------------------------------------------------------------------------------
# Unit: parse_report / fetch_receipt
# --------------------------------------------------------------------------------------------

def test_parse_report_projects_honest_fields():
    out = inference_backend.parse_report("phala/kimi-k2.6", SAMPLE_REPORT)
    assert out["available"] is True
    assert out["model"] == "phala/kimi-k2.6"
    assert out["app_id"] == "9d31963336e6b0bdf8ba4c27b97442a818dd05fd"
    assert out["compose_hash"] == "537b750f6e99972db6d6ea24232ecf0c5826136f3e32704ad2936de75fca14a1"
    assert out["no_log"] is True
    assert out["signing_address"] == "0x4c4E5E69FAdffB8e55C306d867dc88792bd3221D"
    assert out["signing_algo"] == "ecdsa"
    assert out["quote_present"] is True
    # The gateway does NOT verify the quote — the client does. Honest flag.
    assert out["quote_verified_pending"] is True


def test_parse_report_no_log_unknown_when_absent():
    report = {k: v for k, v in SAMPLE_REPORT.items() if k != "no_log"}
    out = inference_backend.parse_report("phala/x", report)
    assert out["no_log"] is None  # absence is unknown, never silently True


def test_parse_report_no_quote_marks_quote_absent():
    report = {"info": {"app_id": "a"}, "signing_address": "0xabc"}
    out = inference_backend.parse_report("phala/x", report)
    assert out["quote_present"] is False


async def test_fetch_receipt_parses_endpoint():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=SAMPLE_REPORT)

    out = await inference_backend.fetch_receipt(
        base_url="https://api.x/v1", api_key="k", model="phala/kimi-k2.6",
        transport=httpx.MockTransport(handler),
    )
    assert out["available"] is True
    assert "attestation/report" in seen["url"]
    assert "model=phala%2Fkimi-k2.6" in seen["url"] or "model=phala/kimi-k2.6" in seen["url"]
    assert seen["auth"] == "Bearer k"
    assert out["no_log"] is True


async def test_fetch_receipt_fails_soft_on_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    out = await inference_backend.fetch_receipt(
        base_url="https://api.dead/v1", api_key="k", model="phala/x",
        transport=httpx.MockTransport(boom),
    )
    assert out["available"] is False  # never raises
    assert out["reason"] == inference_backend.RECEIPT_UNAVAILABLE


async def test_fetch_receipt_fails_soft_on_http_error():
    out = await inference_backend.fetch_receipt(
        base_url="https://api.x/v1", api_key="k", model="phala/x",
        transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")),
    )
    assert out["available"] is False


# --------------------------------------------------------------------------------------------
# Config: observe vs enforce derivation
# --------------------------------------------------------------------------------------------

def test_receipt_enforce_off_by_default():
    s = Settings(inference_base="https://api.x/v1")
    assert s.receipt_enforce() is False  # observe by default (no allowlist)


def test_receipt_enforce_on_when_app_ids_set():
    s = Settings(inference_base="https://api.x/v1", inference_allowed_app_ids="aaa, bbb")
    assert s.receipt_enforce() is True
    assert s.allowed_app_ids() == {"aaa", "bbb"}


def test_receipt_enforce_on_when_compose_hashes_set():
    s = Settings(inference_base="https://api.x/v1", inference_allowed_compose_hashes="h1")
    assert s.receipt_enforce() is True
    assert s.allowed_compose_hashes() == {"h1"}


def test_receipt_disabled_overrides_enforce():
    s = Settings(inference_base="https://api.x/v1", inference_allowed_app_ids="aaa", receipt_enabled=False)
    assert s.receipt_enforce() is False  # disabled receipt -> no enforcement at all


# --------------------------------------------------------------------------------------------
# Route: /v1/chat receipt SSE event (observe + enforce, fail-closed)
# --------------------------------------------------------------------------------------------

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


def _receipt_line(text: str) -> dict:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() == "event: receipt":
            data = lines[i + 1]
            assert data.startswith("data:")
            return json.loads(data[len("data:"):].strip())
    raise AssertionError("no receipt event in stream")


async def _run_chat(*, settings, receipt_fetcher, inference, prompt="hello enclave"):
    """Drive /v1/chat once with injected inference + receipt fetcher; return the raw SSE text."""
    priv, pub = _keypair()
    acct = derive_account_id(pub)
    # The account registry is file-backed; use a temp file per call.
    import tempfile
    import pathlib

    reg = AccountRegistry(pathlib.Path(tempfile.mkdtemp()) / "a.json")
    reg.register(acct, base64.b64encode(pub).decode(), base64.b64encode(b"kem").decode())
    mgr = sess.SessionManager()
    cpriv, cpub = sess.x25519_keypair()
    sk = sess.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    wn, wa, wc = sess._seal(sk, b"\xab" * 32, account_id=acct, purpose=sess.WMK_DELIVERY_PURPOSE, v=1)
    mgr.establish(acct, cpub, nonce=wn, aad=wa, ct=wc, v=1)

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_account_registry] = lambda: reg
    app.dependency_overrides[get_session_manager] = lambda: mgr
    app.dependency_overrides[get_inference] = lambda: inference
    app.dependency_overrides[get_receipt_fetcher] = lambda: receipt_fetcher
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        body = _seal_prompt(sk, acct, prompt)
        resp = await c.post("/v1/chat", json=body, headers=_auth(priv, acct, "POST", "/v1/chat"))
    return resp


async def _ok_inference(prompt, model=None):
    return "Hi from the enclave"


async def test_observe_mode_emits_real_receipt_fields():
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x")
    assert settings.receipt_enforce() is False

    async def fetch(model):
        return inference_backend.parse_report(model, SAMPLE_REPORT)

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=_ok_inference)
    assert resp.status_code == 200
    text = resp.text
    # Observe mode still produces the sealed reply and a real receipt (no sentinel).
    assert "event: token" in text and "event: done" in text
    assert "pending-attested-inference" not in text  # the old sentinel is gone
    receipt = _receipt_line(text)
    assert receipt["cvm_attested"] is True
    inf = receipt["inference"]
    assert inf["provider"] == "redpill"
    assert inf["model"] == "phala/kimi-k2.6"
    assert inf["app_id"] == "9d31963336e6b0bdf8ba4c27b97442a818dd05fd"
    assert inf["compose_hash"] == "537b750f6e99972db6d6ea24232ecf0c5826136f3e32704ad2936de75fca14a1"
    assert inf["no_log"] is True
    assert inf["signing_address"] == "0x4c4E5E69FAdffB8e55C306d867dc88792bd3221D"
    assert inf["quote_present"] is True
    assert inf["quote_verified_pending"] is True  # client verifies, not the gateway
    assert inf["mode"] == "observe"


async def test_observe_mode_unavailable_receipt_still_completes():
    """A flaky report endpoint must NOT block the turn in observe mode."""
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x")

    async def fetch(model):
        return {"available": False, "model": model, "reason": inference_backend.RECEIPT_UNAVAILABLE}

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=_ok_inference)
    text = resp.text
    assert "event: token" in text and "event: done" in text  # turn completed
    receipt = _receipt_line(text)
    assert receipt["inference"]["receipt"] == inference_backend.RECEIPT_UNAVAILABLE
    assert "event: error" not in text


async def test_enforce_mode_fails_closed_on_disallowed_app_id():
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x",
                        inference_allowed_app_ids="some-other-allowed-app-id")
    assert settings.receipt_enforce() is True

    inference_called = {"n": 0}

    async def counting_inference(prompt, model=None):
        inference_called["n"] += 1
        return "Hi from the enclave"

    async def fetch(model):
        return inference_backend.parse_report(model, SAMPLE_REPORT)  # app_id NOT in allowlist

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=counting_inference)
    text = resp.text
    # Fail CLOSED: error event, NO sealed token, reply dropped (inference never even ran).
    assert "event: error" in text
    assert "attestation_rejected" in text
    assert "app_id_not_allowed" in text
    assert "event: token" not in text
    assert "Hi from the enclave" not in text
    assert inference_called["n"] == 0  # we rejected before spending an inference call


async def test_enforce_mode_fails_closed_on_no_log_not_true():
    # app_id IS allowed, but the provider did not assert no_log -> still fail closed.
    report = {k: v for k, v in SAMPLE_REPORT.items() if k != "no_log"}
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x",
                        inference_allowed_app_ids=SAMPLE_REPORT["info"]["app_id"])

    async def fetch(model):
        return inference_backend.parse_report(model, report)

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=_ok_inference)
    text = resp.text
    assert "event: error" in text and "no_log_not_asserted" in text
    assert "event: token" not in text


async def test_enforce_mode_fails_closed_on_unavailable_receipt():
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x",
                        inference_allowed_app_ids=SAMPLE_REPORT["info"]["app_id"])

    async def fetch(model):
        return {"available": False, "model": model, "reason": inference_backend.RECEIPT_UNAVAILABLE}

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=_ok_inference)
    text = resp.text
    assert "event: error" in text and "receipt_unavailable" in text
    assert "event: token" not in text


async def test_enforce_mode_passes_when_allowed():
    settings = Settings(run_mode="cvm", inference_base="https://api.x/v1",
                        inference_model="phala/kimi-k2.6", device_tokens="x",
                        inference_allowed_app_ids=SAMPLE_REPORT["info"]["app_id"],
                        inference_allowed_compose_hashes=SAMPLE_REPORT["info"]["compose_hash"])

    async def fetch(model):
        return inference_backend.parse_report(model, SAMPLE_REPORT)  # allowed + no_log true

    resp = await _run_chat(settings=settings, receipt_fetcher=fetch, inference=_ok_inference)
    text = resp.text
    assert "event: token" in text and "event: done" in text
    assert "event: error" not in text
    receipt = _receipt_line(text)
    assert receipt["inference"]["mode"] == "enforce"
    assert receipt["inference"]["app_id"] == SAMPLE_REPORT["info"]["app_id"]
