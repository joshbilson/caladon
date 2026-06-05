"""Direct attested-inference backend for the in-CVM gateway (v1 chat).

When `GATEWAY_INFERENCE_BASE` is set, `/v1/chat` opens the sealed prompt in TEE RAM and calls
this OpenAI-compatible provider (e.g. RedPill — itself attested TDX+GPU) directly, then seals
the answer back. This is the simplest confidential-chat backend; Letta agent-memory is a
later upgrade. The provider runs inside its own TEE, so plaintext only ever exists inside
attested boundaries (this CVM + the inference enclave).

`complete()` is injectable in tests; the real impl is a single non-streaming completion call
(v1). The per-response **attestation receipt** is a SEPARATE provider endpoint
(`GET /v1/attestation/report?model=<slug>`) — NOT a response header (the chat response carries
only `x-redpill-*`, and `x-redpill-provider` varies — we have seen `phala` AND `near-ai`). The
report returns `{intel_quote, nvidia_payload, signing_address, signing_algo, request_nonce,
info, ...}`; `fetch_receipt()` fetches and parses it into the honest fields the gateway surfaces.

Honest-claims note: the gateway does NOT verify the TDX/GPU quote here — the in-CLIENT quote
verification remains the client's job. The receipt only surfaces what the provider attests
(quote present, signer address, enclave identity), tagged `quote_verified_pending`.
"""

from __future__ import annotations

from typing import Any

import httpx

# Sentinel emitted in OBSERVE mode when the report endpoint is unreachable/malformed. The turn
# still completes (observe never blocks); the receipt just records that no provider attestation
# was obtainable for this response. In ENFORCE mode the caller treats this as a hard failure.
RECEIPT_UNAVAILABLE = "receipt-unavailable"


def parse_report(model: str, report: dict[str, Any]) -> dict[str, Any]:
    """Project a RedPill `/v1/attestation/report` body into the honest receipt fields we surface.

    We read only what the provider asserts — we do NOT verify the quote (that is the client's
    job; the gateway flags `quote_verified_pending=True`). `no_log` is read from whatever the
    provider exposes (top-level or under `info`); when the provider does not assert it, we leave
    it `None` (unknown) — ENFORCE mode treats unknown as not-allowed (fail closed)."""
    info = report.get("info") if isinstance(report.get("info"), dict) else {}
    app_id = info.get("app_id") or report.get("app_id")
    compose_hash = info.get("compose_hash") or report.get("compose_hash")
    quote_present = bool(report.get("intel_quote") or report.get("quote"))

    # `no_log` posture: accept a few honest spellings the provider might use; only an explicit
    # truthy assertion counts as True. Absence -> None (unknown), never silently True.
    no_log: bool | None = None
    for key in ("no_log", "no-log", "nolog"):
        for src in (report, info):
            if key in src:
                no_log = bool(src[key])
                break
        if no_log is not None:
            break

    return {
        "available": True,
        "model": model,
        "app_id": app_id,
        "compose_hash": compose_hash,
        "no_log": no_log,
        "signing_address": report.get("signing_address"),
        "signing_algo": report.get("signing_algo"),
        "quote_present": quote_present,
        # The gateway surfaces the provider attestation honestly; it does NOT verify the quote.
        # The client re-fetches/verifies the quote (Intel + NVIDIA roots) against this signer.
        "quote_verified_pending": True,
    }


async def fetch_receipt(
    *, base_url: str, api_key: str, model: str, timeout: float = 15.0, transport=None
) -> dict[str, Any]:
    """Fetch + parse the per-response attestation receipt for `model`.

    Fail-soft: any transport/HTTP/parse error returns `{"available": False, "reason": ...}` so
    OBSERVE mode never blocks a turn on a flaky report endpoint. The caller (ENFORCE mode)
    decides whether an unavailable receipt is fatal. `transport` is injectable for tests."""
    url = base_url.rstrip("/") + "/attestation/report"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            resp = await client.get(url, params={"model": model}, headers=headers)
            resp.raise_for_status()
            report = resp.json()
        if not isinstance(report, dict):
            raise ValueError("report is not a JSON object")
    except Exception as exc:  # noqa: BLE001 - fail soft; never raise into the chat stream
        return {"available": False, "model": model, "reason": RECEIPT_UNAVAILABLE, "detail": type(exc).__name__}
    return parse_report(model, report)


class ToolLoopError(RuntimeError):
    """Raised when the in-CVM tool loop cannot produce a final answer (step cap, malformed reply)."""


async def complete_with_tools(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    execute_tool,
    max_steps: int = 6,
    timeout: float = 120.0,
    transport=None,
) -> tuple[str, list[dict[str, Any]]]:
    """In-CVM tool loop (foundation for MCP / skills / subagents — see in-CVM plan).

    Drives an OpenAI-compatible chat completion that may call `tools`. Each tool call is executed
    INSIDE the CVM by `execute_tool(name, args) -> str` (an awaitable). `execute_tool` is the trust
    boundary: it is where the egress allowlist lives (it must refuse any host not explicitly
    allowed; default fail-closed). We never hand tool execution to the model/provider — only the
    tool *names+args* round-trip to the model; the work happens here in attested RAM.

    Returns `(final_text, step_log)` where step_log records each tool call/result for sealed
    `tool_call`/`tool_result` SSE events (the client renders the steps). Raises ToolLoopError on a
    malformed/empty final reply or if `max_steps` is exceeded (caller fails the turn closed — never
    echoes the prompt). Use ONLY models that return native structured `tool_calls`
    (phala/deepseek-v3.2, phala/gpt-oss-120b — verified 2026-06-06); qwen3.6-uncensored emits
    text-format tool calls and must not be routed here.

    `transport` is injectable for tests (httpx.MockTransport).
    """
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    convo = list(messages)
    step_log: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        for _step in range(max_steps):
            payload = {"model": model, "messages": convo, "tools": tools, "tool_choice": "auto", "stream": False}
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            try:
                message = data["choices"][0]["message"]
            except (KeyError, IndexError, TypeError) as exc:
                raise ToolLoopError("inference response missing choices[0].message") from exc

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                content = message.get("content")
                if not content or not content.strip():
                    raise ToolLoopError("inference returned empty content")
                return content, step_log

            # Append the assistant turn (with its tool_calls) verbatim, then execute each call
            # in-CVM and append a `tool` result message keyed by tool_call_id.
            convo.append(message)
            for call in tool_calls:
                fn = call.get("function", {}) or {}
                name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")
                try:
                    import json as _json

                    args = _json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except Exception:  # noqa: BLE001 - malformed args from the model; record + tell it
                    args = {}
                try:
                    result = await execute_tool(name, args)
                except Exception as exc:  # noqa: BLE001 - tool/egress refusal is fed back, not fatal
                    result = f"tool error: {type(exc).__name__}: {exc}"
                step_log.append({"tool": name, "args": args, "result": result})
                convo.append(
                    {"role": "tool", "tool_call_id": call.get("id", ""), "name": name, "content": str(result)}
                )

    raise ToolLoopError(f"tool loop exceeded {max_steps} steps")


async def complete(*, base_url: str, api_key: str, model: str, prompt: str, timeout: float = 120.0) -> str:
    """One OpenAI-compatible chat completion. Returns the assistant message text. Raises on a
    transport/HTTP error OR an empty/missing completion (the caller fails the turn closed —
    never echoes the prompt). `timeout` is generous: attested reasoning models (e.g.
    phala/qwen3.6-35b-a3b-uncensored) spend tokens on a hidden reasoning pass before content."""
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    # Fail closed on a malformed/empty reply rather than sealing a `None`/"" back to the client.
    # (A reasoning model can return content=null if a max_tokens cap is exhausted by reasoning;
    # we set no cap here, but guard regardless so a bad upstream reply is an error, not a seal.)
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("inference response missing choices[0].message.content") from exc
    if not content or not content.strip():
        raise RuntimeError("inference returned empty content")
    return content
