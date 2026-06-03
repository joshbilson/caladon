"""Tests for the dstack guest-agent quote fetch (deps._dstack_fetch).

Verifies the in-CVM GetQuote/Info shape (Phala Cloud dstack 0.5.x guest agent): we POST
{"report_data": <challenge-hex>} to /GetQuote over the guest-agent socket, the agent binds the
challenge VERBATIM into report_data[0:32], and we assemble the regime-tagged evidence bundle the
CvmAttestationProvider + SwiftyKit client consume. httpx.MockTransport stands in for the socket.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.attestation import AttestationError
from app.deps import _dstack_fetch

CHALLENGE = "ab" * 32  # 64 hex chars == 32-byte SHA-256(client eph_pub)


def _agent(*, quote="0400" + "00" * 100, report_data=None, info=None, captured=None) -> httpx.MockTransport:
    rd = report_data if report_data is not None else CHALLENGE + "00" * 32  # verbatim + zero-pad to 64B
    info = info if info is not None else {"compose_hash": "c0ffee", "app_id": "app123", "instance_id": "i1"}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if captured is not None:
            captured.append((request.url.path, body))
        if request.url.path.endswith("/GetQuote"):
            return httpx.Response(200, json={"quote": quote, "event_log": "[]", "report_data": rd, "vm_config": "{}"})
        if request.url.path.endswith("/Info"):
            return httpx.Response(200, json=info)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_fetch_builds_bound_bundle():
    captured: list = []
    fetch = _dstack_fetch("http://dstack/GetQuote", transport=_agent(captured=captured))
    bundle = fetch(CHALLENGE)
    # Request shape: POST /GetQuote with report_data == the challenge (snake_case, not "nonce").
    get = next(b for p, b in captured if p.endswith("/GetQuote"))
    assert get == {"report_data": CHALLENGE}
    assert any(p.endswith("/Info") for p, _ in captured)
    # Bundle shape the provider/client consume.
    assert bundle["regime"] == "tdx-onchain"
    assert bundle["challenge"] == CHALLENGE
    assert bundle["intel_quote"].startswith("0400")
    assert bundle["event_log"] == "[]"
    assert bundle["info"]["compose_hash"] == "c0ffee"
    assert bundle["info"]["app_id"] == "app123"


def test_fetch_rejects_unbound_report_data():
    # The agent's returned report_data must begin with our challenge; otherwise fail closed.
    fetch = _dstack_fetch("http://dstack/GetQuote", transport=_agent(report_data="dead" + "00" * 30))
    with pytest.raises(AttestationError):
        fetch(CHALLENGE)


def test_fetch_accepts_0x_prefixed_report_data():
    fetch = _dstack_fetch("http://dstack/GetQuote", transport=_agent(report_data="0x" + CHALLENGE + "00" * 32))
    assert fetch(CHALLENGE)["challenge"] == CHALLENGE


def test_fetch_no_quote_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"event_log": "[]"})  # no quote field

    fetch = _dstack_fetch("http://dstack/GetQuote", transport=httpx.MockTransport(handler))
    with pytest.raises(AttestationError):
        fetch(CHALLENGE)


def test_unconfigured_url_fails_closed():
    with pytest.raises(AttestationError):
        _dstack_fetch("")(CHALLENGE)


def test_info_failure_is_nonfatal():
    # /Info errors but the quote is present -> the bundle still returns (the quote is the proof).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/GetQuote"):
            return httpx.Response(200, json={"quote": "0400ff", "report_data": CHALLENGE + "00" * 32})
        return httpx.Response(500)

    bundle = _dstack_fetch("http://dstack/GetQuote", transport=httpx.MockTransport(handler))(CHALLENGE)
    assert bundle["intel_quote"] == "0400ff"
    assert "info" not in bundle
