"""In-CVM tool broker — executes tool calls INSIDE the attested CVM (trust-no-one).

This is the trust boundary for the in-CVM tool loop (inference_backend.complete_with_tools). The
model only ever sees tool *names + args*; the actual work runs here, in attested RAM, behind a
**fail-closed egress allowlist**. Built-in tools that need no network (e.g. `calculator`) always
work; tools that reach out (e.g. `web_fetch`) are refused unless their target host is explicitly
allowlisted via GATEWAY_MCP_ALLOWED_HOSTS — and even then SSRF-style internal targets
(localhost / private / link-local / metadata) are always blocked.

This is the foundation MCP, skills, and subagents build on. Keep the default posture FAIL-CLOSED:
an empty allowlist means no external egress at all.
"""

from __future__ import annotations

import ast
import ipaddress
import operator
import socket
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx

# --- OpenAI tool specs advertised to the model -------------------------------------------------

CALCULATOR_SPEC = {
    "type": "function",
    "function": {
        "name": "calculator",
        "description": "Evaluate a basic arithmetic expression (e.g. '23*17+4'). No variables.",
        "parameters": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
}

WEB_FETCH_SPEC = {
    "type": "function",
    "function": {
        "name": "web_fetch",
        "description": "Fetch the text of a URL. Only allowlisted hosts are reachable.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
}

# --- calculator (no egress) --------------------------------------------------------------------

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _safe_eval(node: ast.AST) -> float:
    """Evaluate a numeric arithmetic AST — numbers + + - * / // % ** and parentheses ONLY.

    No names, calls, attributes, subscripts, comprehensions — so there is no code-execution surface
    (this runs in-CVM on model-supplied text). Caps the exponent to avoid a DoS via huge ** results.
    """
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError("only numeric constants allowed")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        if isinstance(node.op, ast.Pow):
            right = _safe_eval(node.right)
            if abs(right) > 64:
                raise ValueError("exponent too large")
        return _BIN_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("unsupported expression")


def calculate(expression: str) -> str:
    tree = ast.parse(str(expression), mode="eval")
    return str(_safe_eval(tree))


# --- egress allowlist (the trust boundary) -----------------------------------------------------


def _is_internal_host(host: str) -> bool:
    """True if `host` is loopback/private/link-local/metadata — never reachable even if allowlisted
    (SSRF guard). Resolves DNS names too, so an allowlisted name pointing at 169.254.169.254 is
    still blocked. Fails CLOSED (treat resolution failure as internal/blocked)."""
    h = (host or "").strip().lower().strip("[]")
    if not h or h in {"localhost", "metadata", "metadata.google.internal"}:
        return True
    candidates: list[str] = [h]
    try:
        candidates += [info[4][0] for info in socket.getaddrinfo(h, None)]
    except Exception:  # noqa: BLE001 - can't resolve -> treat as internal/blocked (fail closed)
        return True
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def host_allowed(url: str, allowed_hosts: set[str], *, yolo: bool = False) -> bool:
    """Fail-closed: only http(s) URLs whose host is in `allowed_hosts` (exact or dot-suffix) AND not
    internal are reachable. Empty allowlist -> nothing is reachable.

    `yolo=True` (the app's "yolo mode" toggle, opted into per-turn by the user) BYPASSES the host
    allowlist — any external http(s) host is permitted. The SSRF guard is NEVER bypassed: even in
    yolo, loopback/private/link-local/reserved/metadata targets stay blocked, so a tool can't be
    tricked into reaching the CVM's own internals or cloud metadata. Yolo widens reach, not safety."""
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if not yolo:
        if not allowed_hosts:
            return False
        in_list = host in allowed_hosts or any(host == a or host.endswith("." + a) for a in allowed_hosts)
        if not in_list:
            return False
    return not _is_internal_host(host)


async def _web_fetch(
    url: str, allowed_hosts: set[str], *, yolo: bool, timeout: float, transport, max_chars: int
) -> str:
    if not host_allowed(url, allowed_hosts, yolo=yolo):
        raise PermissionError("host not in egress allowlist")
    async with httpx.AsyncClient(timeout=timeout, transport=transport, follow_redirects=False) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        text = resp.text
    return text[:max_chars]


# --- executor factory --------------------------------------------------------------------------

ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[str]]


def tool_specs(allowed_hosts: set[str], *, yolo: bool = False) -> list[dict[str, Any]]:
    """Tool specs to advertise. web_fetch is offered when at least one host is allowlisted OR yolo is
    on (no point dangling a tool that will always refuse)."""
    specs = [CALCULATOR_SPEC]
    if allowed_hosts or yolo:
        specs.append(WEB_FETCH_SPEC)
    return specs


def build_executor(
    allowed_hosts: set[str] | None = None,
    *,
    yolo: bool = False,
    timeout: float = 15.0,
    transport=None,
    max_chars: int = 8000,
) -> ToolExecutor:
    """Build the in-CVM `execute_tool(name, args)` closure for complete_with_tools. `allowed_hosts`
    is the egress allowlist (default empty = fail-closed, no external fetch); `yolo` bypasses the
    allowlist for external hosts (SSRF guard still applies). `transport` is injectable for tests."""
    hosts = set(allowed_hosts or set())

    async def execute_tool(name: str, args: dict[str, Any]) -> str:
        if name == "calculator":
            return calculate(args.get("expression", ""))
        if name == "web_fetch":
            return await _web_fetch(
                str(args.get("url", "")), hosts, yolo=yolo, timeout=timeout, transport=transport, max_chars=max_chars
            )
        raise ValueError(f"unknown tool: {name}")

    return execute_tool
