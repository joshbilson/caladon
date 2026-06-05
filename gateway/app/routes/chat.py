"""POST /v1/chat — the confidential live turn (gateway-api.md §2-§3, identity-envelope §6).

Seed-authed. The client seals its prompt to the session key SK (purpose "chat") and sends it
as an envelope; the in-CVM gateway opens it in TEE RAM (an established session is required —
deliver WMK first via POST /v1/session), streams the agent, and **seals each response delta
back under SK** as an envelope SSE event. The gateway never returns plaintext deltas. `cvm`
mode only (T0 has no attested boundary for this confidential path).
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

from app.config import Settings, get_settings
from app.deps import (
    get_inference,
    get_letta,
    get_receipt_fetcher,
    get_session_manager,
    require_account,
)
from app.envelope import Envelope
from app.letta_client import LettaClient
from app.session import SessionManager
from app.sse import format_sse, map_letta_event

router = APIRouter()


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: Envelope  # the prompt, sealed to the session SK (purpose "chat")
    # Optional per-request attested model slug (e.g. "phala/kimi-k2.6"). Lets the app switch
    # models instantly AND mid-session (the session key is model-independent, so no re-handshake).
    # The gateway honours it only if it is in the attested allowlist (models_catalog), else it
    # falls back to the configured default. Metadata, not secret (the relay can't see it inside
    # the in-CVM TLS; RedPill sees the model name inherently).
    model: str | None = None
    # In-CVM tool loop (MCP/skills/subagents). When true, the gateway runs the prompt through an
    # OpenAI tool loop, executing tools INSIDE the CVM (app/mcp_broker) behind the egress allowlist,
    # and routes the turn to a function-calling-capable attested model (settings.tool_model).
    tools: bool = False
    # The app's "yolo mode" toggle: bypass the host egress allowlist for THIS turn (the user opted
    # in). The SSRF guard still blocks loopback/private/metadata even in yolo.
    tools_yolo: bool = False


def _wire(nonce: bytes, aad: bytes, ct: bytes, v: int = 1) -> dict:
    """A sealed response delta as a wire envelope (base64), for the SSE payload."""
    return {
        "v": v, "alg": "xchacha20poly1305", "kid": "chat",
        "nonce": base64.b64encode(nonce).decode(),
        "aad": base64.b64encode(aad).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


# RedPill is the attested-inference provider (spike-notes.md (d)); its per-response provider is
# surfaced in the receipt. The chat response carries `x-redpill-provider` but it VARIES, so we
# tag the receipt provider as the upstream we routed to, not a per-turn value we can't bind.
_PROVIDER = "redpill"


def _enforce_violation(receipt: dict, settings: Settings) -> str | None:
    """In ENFORCE mode, return a short violation reason if the serving enclave is not allowed
    (or no_log is not explicitly true), else None. Fail CLOSED on an unavailable receipt."""
    if not receipt.get("available"):
        return "receipt_unavailable"
    app_ids = settings.allowed_app_ids()
    composes = settings.allowed_compose_hashes()
    if app_ids and receipt.get("app_id") not in app_ids:
        return "app_id_not_allowed"
    if composes and receipt.get("compose_hash") not in composes:
        return "compose_hash_not_allowed"
    if receipt.get("no_log") is not True:
        return "no_log_not_asserted"
    return None


def _receipt_payload(receipt: dict | None, settings: Settings, model: str) -> dict:
    """The honest `receipt` SSE body. `cvm_attested` is the in-CVM gateway attestation the client
    already verified at GET /v1/attestation; `inference` is the per-response PROVIDER attestation
    we just surfaced (NOT verified here — the in-client quote verification is still the client's
    job; we flag `quote_verified_pending`)."""
    if receipt is None:
        # Receipts disabled or no inference backend (e.g. Letta path) — be honest, don't fabricate.
        return {"cvm_attested": True, "inference": {"provider": _PROVIDER, "model": model, "receipt": "disabled"}}
    inference = {
        "provider": _PROVIDER,
        "model": receipt.get("model", model),
        "app_id": receipt.get("app_id"),
        "compose_hash": receipt.get("compose_hash"),
        "no_log": receipt.get("no_log"),
        "signing_address": receipt.get("signing_address"),
        "quote_present": receipt.get("quote_present", False),
        "quote_verified_pending": receipt.get("quote_verified_pending", True),
        "mode": "enforce" if settings.receipt_enforce() else "observe",
    }
    if not receipt.get("available"):
        inference["receipt"] = receipt.get("reason", "receipt-unavailable")
    return {"cvm_attested": True, "inference": inference}


@router.post("/v1/chat")
async def chat(
    req: ChatRequest,
    account_id: str = Depends(require_account),
    settings: Settings = Depends(get_settings),
    sessions: SessionManager = Depends(get_session_manager),
    letta: LettaClient = Depends(get_letta),
    inference=Depends(get_inference),
    receipt_fetcher=Depends(get_receipt_fetcher),
) -> StreamingResponse:
    if settings.run_mode != "cvm":
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="confidential chat requires cvm mode")
    if not sessions.has_session(account_id):
        # Clean 428 for the common no-session case. If a session is ended concurrently AFTER
        # this check, open_for raises KeyError below -> 400 (still fail-closed); benign race.
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="establish a session first (POST /v1/session)"
        )
    env = req.envelope
    try:
        prompt = sessions.open_for(
            account_id,
            nonce=base64.b64decode(env.nonce, validate=True),
            aad=base64.b64decode(env.aad, validate=True),
            ct=base64.b64decode(env.ct, validate=True),
            v=env.v,
        ).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - fail closed; never echo the prompt/key
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="could not open prompt") from exc

    def _seal_event(event: str, text: str) -> str:
        nonce, aad, ct = sessions.seal_for(account_id, text.encode("utf-8"))
        return format_sse(event, {"envelope": _wire(nonce, aad, ct)})

    # The model the gateway will route the turn to (for the receipt + the completion). The
    # per-request slug is honoured only if attested (deps.get_inference re-checks); the report
    # endpoint is keyed by this same slug, so the receipt reflects the serving enclave.
    # A TOOL turn is forced onto the function-calling-capable attested model (not every attested
    # model supports native tool_calls), so the receipt reflects THAT enclave.
    use_tools = bool(req.tools and settings.mcp_enabled and inference is not None)
    chosen_model = settings.tool_model if use_tools else (req.model or settings.inference_model)

    async def gen():
        try:
            if inference is not None:
                # v1: direct attested inference — one sealed completion on the chosen attested model.
                # Fetch the per-response provider attestation FIRST so ENFORCE mode can fail the
                # turn closed BEFORE any sealed reply is emitted (don't leak a reply on a turn we
                # would have rejected).
                receipt = None
                if receipt_fetcher is not None:
                    receipt = await receipt_fetcher(chosen_model)
                    if settings.receipt_enforce():
                        violation = _enforce_violation(receipt, settings)
                        if violation is not None:
                            # Fail CLOSED: emit an error + the (honest) receipt, and DROP the reply.
                            yield format_sse("receipt", _receipt_payload(receipt, settings, chosen_model))
                            yield format_sse(
                                "error",
                                {"code": "attestation_rejected", "message": "serving enclave not allowed", "reason": violation},
                            )
                            return
                if use_tools:
                    # In-CVM tool loop: run the prompt with tools, executing each call inside the CVM
                    # behind the egress allowlist (yolo bypasses the allowlist, never the SSRF guard).
                    from app import inference_backend, mcp_broker

                    allowed = settings.mcp_allowed_hosts_set()
                    executor = mcp_broker.build_executor(
                        allowed, yolo=req.tools_yolo, timeout=settings.receipt_timeout
                    )
                    specs = mcp_broker.tool_specs(allowed, yolo=req.tools_yolo)
                    final_text, step_log = await inference_backend.complete_with_tools(
                        base_url=settings.inference_base,
                        api_key=settings.inference_key,
                        model=chosen_model,
                        messages=[{"role": "user", "content": prompt}],
                        tools=specs,
                        execute_tool=executor,
                        max_steps=settings.tool_max_steps,
                        timeout=settings.inference_timeout,
                    )
                    # Surface each in-CVM tool step to the client, sealed (purpose "chat"), so the UI
                    # can show what ran. Args/results are the user's own turn data — sealed like the reply.
                    import json as _json

                    for step in step_log:
                        yield _seal_event("tool", _json.dumps(step)[:4000])
                    yield _seal_event("token", final_text)
                else:
                    yield _seal_event("token", await inference(prompt, req.model))
                yield format_sse("receipt", _receipt_payload(receipt, settings, chosen_model))
            else:
                # Letta agent path (memory). Streams sealed deltas (token/reasoning).
                async for evt in letta.stream_chat(prompt):
                    mapped = map_letta_event(evt)
                    if mapped is None:
                        continue
                    event, data = mapped
                    yield _seal_event(event, data.get("text") or "")
                # No per-response inference-provider receipt on the Letta path yet; the CVM
                # session itself is attested (client verified it at GET /v1/attestation).
                yield format_sse("receipt", _receipt_payload(None, settings, chosen_model))
            yield format_sse("done", {})
        except Exception:  # noqa: BLE001 - no plaintext/keys in errors (gateway-api §3)
            yield format_sse("error", {"code": "chat_failed", "message": "upstream error"})

    return StreamingResponse(gen(), media_type="text/event-stream")
