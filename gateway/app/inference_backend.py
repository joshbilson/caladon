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
