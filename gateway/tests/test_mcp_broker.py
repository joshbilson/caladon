"""Tests for the in-CVM tool broker — especially the fail-closed egress allowlist + SSRF guard.

These are trust-critical: a regression here could let an in-CVM tool reach a host the operator never
allowlisted, or an internal/metadata endpoint. Public literal IPs are used for the allowed path so
DNS resolution stays deterministic (no network).
"""

from __future__ import annotations

import httpx
import pytest

from app import mcp_broker

PUBLIC_IP = "93.184.216.34"  # literal public IP → ip_address parses, not private → not internal


def test_calculator_evaluates():
    assert mcp_broker.calculate("23*17") == "391"
    assert mcp_broker.calculate("2 ** 8 + 1") == "257"
    assert float(mcp_broker.calculate("10/4")) == 2.5


def test_calculator_rejects_code():
    for expr in ["__import__('os')", "open('/etc/passwd')", "x + 1", "2**999999"]:
        with pytest.raises(Exception):
            mcp_broker.calculate(expr)


def test_egress_allowlist_fail_closed():
    # Empty allowlist -> nothing reachable.
    assert mcp_broker.host_allowed("https://example.com/x", set()) is False
    # Host not in the allowlist -> refused.
    assert mcp_broker.host_allowed("https://evil.com/x", {"example.com"}) is False
    # Non-http scheme refused even if "host" matches.
    assert mcp_broker.host_allowed("file:///etc/passwd", {"etc"}) is False


def test_ssrf_internal_targets_blocked_even_if_allowlisted():
    assert mcp_broker.host_allowed("http://localhost/x", {"localhost"}) is False
    assert mcp_broker.host_allowed("http://127.0.0.1/x", {"127.0.0.1"}) is False
    assert mcp_broker.host_allowed("http://169.254.169.254/latest/meta-data", {"169.254.169.254"}) is False
    assert mcp_broker.host_allowed("http://10.0.0.5/x", {"10.0.0.5"}) is False


def test_public_allowlisted_host_permitted():
    assert mcp_broker.host_allowed(f"https://{PUBLIC_IP}/x", {PUBLIC_IP}) is True


def test_tool_specs_gate_web_fetch_on_allowlist():
    assert all(s["function"]["name"] != "web_fetch" for s in mcp_broker.tool_specs(set()))
    names = [s["function"]["name"] for s in mcp_broker.tool_specs({"example.com"})]
    assert "web_fetch" in names and "calculator" in names


@pytest.mark.asyncio
async def test_executor_calculator_no_egress():
    execute = mcp_broker.build_executor(set())
    assert await execute("calculator", {"expression": "6*7"}) == "42"


@pytest.mark.asyncio
async def test_executor_web_fetch_refused_when_not_allowlisted():
    execute = mcp_broker.build_executor(set())
    with pytest.raises(PermissionError):
        await execute("web_fetch", {"url": "https://example.com"})


@pytest.mark.asyncio
async def test_executor_web_fetch_allowed_path():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="hello from allowlisted host")

    execute = mcp_broker.build_executor({PUBLIC_IP}, transport=httpx.MockTransport(handler))
    out = await execute("web_fetch", {"url": f"https://{PUBLIC_IP}/page"})
    assert out == "hello from allowlisted host"


@pytest.mark.asyncio
async def test_executor_unknown_tool_raises():
    execute = mcp_broker.build_executor(set())
    with pytest.raises(ValueError):
        await execute("rm_rf", {})
