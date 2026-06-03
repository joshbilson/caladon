"""Tests for the multi-tenant seed-signature auth (contracts/gateway-api.md §1)."""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import seed_auth
from app.seed_auth import AuthError, AuthRequest, canonical, parse_auth_header, verify

# Valid account_id shape: url-safe, >=16 chars (a 256-bit id is ~43 url-safe chars).
ACCT = "acct_0123456789abcdef"
ACCT_A = "accountA_0123456789ab"
ACCT_B = "accountB_0123456789ab"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def _signed_header(priv, account_id, method, path, ts):
    sig = priv.sign(canonical(account_id, ts, method, path))
    return f"Swifty acct={account_id} ts={ts} sig={base64.b64encode(sig).decode()}"


def test_valid_request_verifies():
    priv, pub = _keypair()
    ts = int(time.time())
    req = parse_auth_header(_signed_header(priv, ACCT, "POST", "/v1/chat", ts))
    verify(pub, req, "POST", "/v1/chat", now=ts)  # no raise == pass


def test_tampered_signature_rejected():
    priv, pub = _keypair()
    ts = int(time.time())
    req = parse_auth_header(_signed_header(priv, ACCT, "POST", "/v1/chat", ts))
    bad = AuthRequest(req.account_id, req.ts, req.sig[:-1] + bytes([req.sig[-1] ^ 0x01]))
    with pytest.raises(AuthError):
        verify(pub, bad, "POST", "/v1/chat", now=ts)


def test_wrong_method_or_path_rejected():
    priv, pub = _keypair()
    ts = int(time.time())
    req = parse_auth_header(_signed_header(priv, ACCT, "POST", "/v1/chat", ts))
    with pytest.raises(AuthError):
        verify(pub, req, "GET", "/v1/chat", now=ts)
    with pytest.raises(AuthError):
        verify(pub, req, "POST", "/v1/messages", now=ts)


def test_stale_and_future_timestamps_rejected():
    priv, pub = _keypair()
    ts = int(time.time())
    req = parse_auth_header(_signed_header(priv, ACCT, "POST", "/v1/chat", ts))
    with pytest.raises(AuthError):
        verify(pub, req, "POST", "/v1/chat", now=ts + seed_auth.FRESHNESS_WINDOW_S + 5)
    with pytest.raises(AuthError):
        verify(pub, req, "POST", "/v1/chat", now=ts - seed_auth.FRESHNESS_WINDOW_S - 5)


def test_signature_only_verifies_under_the_signing_accounts_key():
    """Routing invariant: the route MUST look up the pubkey for req.account_id. A request
    signed by account A's key will NOT verify if the gateway supplies a different account's
    pubkey (the crypto check enforces account<->key binding)."""
    priv_a, _ = _keypair()
    _, pub_b = _keypair()
    ts = int(time.time())
    req = parse_auth_header(_signed_header(priv_a, ACCT_A, "POST", "/v1/chat", ts))
    with pytest.raises(AuthError):
        verify(pub_b, req, "POST", "/v1/chat", now=ts)


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer xyz",
        "Swifty acct=a ts=notint sig=AAAA",
        "Swifty acct= ts=1 sig=",
        "Swifty ts=1 sig=AAAA",
        "Swifty acct=short ts=1 sig=AAAA",          # account_id too short
        "Swifty acct=bad!chars$$$$$$$$ ts=1 sig=AAAA",  # illegal charset
    ],
)
def test_malformed_headers_rejected(header):
    with pytest.raises(AuthError):
        parse_auth_header(header)


def test_canonical_is_deterministic_and_unambiguous():
    a = canonical("acct", 100, "post", "/v1/chat")
    assert a == canonical("acct", 100, "POST", "/v1/chat")  # method upper-cased
    assert canonical("ac", 100, "POST", "/x") != canonical("acct", 100, "POST", "/x")
