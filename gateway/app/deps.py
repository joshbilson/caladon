import threading

from fastapi import Depends, HTTPException, Request, status

from app.accounts import AccountRegistry
from app.attestation import (
    AttestationError,
    AttestationProvider,
    CvmAttestationProvider,
    PlainAttestationProvider,
)
from app.config import Settings, get_settings
from app.letta_client import LettaClient
from app.seed_auth import AuthError, parse_auth_header, verify
from app.session import SessionManager
from app.transcript import TranscriptStore

# One AccountRegistry per store path per process (it owns the file; see accounts.py).
_REGISTRIES: dict[str, AccountRegistry] = {}
_REGISTRIES_LOCK = threading.Lock()

# One TranscriptStore per store path per process (it owns the file; see transcript.py).
_TRANSCRIPTS: dict[str, TranscriptStore] = {}
_TRANSCRIPTS_LOCK = threading.Lock()

# ONE SessionManager per process: it owns the CVM's (write-once) session keypair + the
# per-account WMKs held in TEE RAM (§6). A second instance would mint a different CVM keypair,
# so clients that derived SK against the first would fail to deliver WMK to the second.
_SESSION_MANAGER: SessionManager | None = None
_SESSION_MANAGER_LOCK = threading.Lock()


def get_letta(settings: Settings = Depends(get_settings)) -> LettaClient:
    return LettaClient(settings.letta_base_url, settings.letta_password, settings.agent_id)


def get_account_registry(settings: Settings = Depends(get_settings)) -> AccountRegistry:
    # Lock the lazy init so concurrent requests can't construct duplicate registries
    # (which would split the in-memory cache and defeat the key-rebind guard).
    with _REGISTRIES_LOCK:
        reg = _REGISTRIES.get(settings.accounts_store)
        if reg is None:
            reg = AccountRegistry(settings.accounts_store)
            _REGISTRIES[settings.accounts_store] = reg
        return reg


def get_transcript_store(settings: Settings = Depends(get_settings)) -> TranscriptStore:
    # Same single-owner-per-path discipline as the registry: a split cache would let one
    # writer's appends be invisible to another and risk a truncated-read/lost-append.
    with _TRANSCRIPTS_LOCK:
        store = _TRANSCRIPTS.get(settings.transcript_store)
        if store is None:
            store = TranscriptStore(settings.transcript_store)
            _TRANSCRIPTS[settings.transcript_store] = store
        return store


def _dstack_fetch(quote_url: str, socket_path: str = "", *, transport=None):
    """Build the T1 evidence fetch from the dstack guest-agent (dstack 0.5.x).

    The guest agent is a UNIX-domain socket inside the CVM (default /var/run/dstack.sock), NOT
    a TCP host. We `POST {quote_url} {"report_data": <report_data-hex>}` over a UDS transport. The
    agent places report_data VERBATIM (no hashing) into the TDX quote, zero-padded to 64 bytes.
    The provider passes a 128-hex (64-byte) report_data binding BOTH pubkeys: report_data[0:32] =
    the challenge = SHA-256(client eph_pub), report_data[32:64] = SHA-256(cvm session_pub)
    (contracts/attestation-evidence.md §2.1d). When no report_data is supplied (plain/no session
    key) we fall back to the 64-hex challenge alone, so report_data[32:64] = 0. We then POST /Info
    for the CVM identity (compose_hash/app_id) the client pins. Returns the regime-tagged evidence
    bundle; the provider adds the CVM session_pub. Empty URL -> fail closed (503).

    Sync httpx; the handshake is infrequent (move to threadpool if it ever hits the hot path).
    `transport` is injectable for tests; in production it is an httpx UDS transport built from
    `socket_path` (or plain TCP when `socket_path` is empty, e.g. the dev simulator)."""
    if not quote_url:
        def _unconfigured(challenge: str, report_data: str | None = None) -> dict:
            raise AttestationError("dstack quote url not configured (GATEWAY_DSTACK_QUOTE_URL)")
        return _unconfigured

    # Derive the /Info endpoint from the quote URL (same host/socket, sibling path).
    info_url = quote_url.rsplit("/", 1)[0] + "/Info" if "/" in quote_url else ""

    def _fetch(challenge: str, report_data: str | None = None) -> dict:
        import httpx

        # report_data is the full hex written verbatim into the quote (challenge ‖
        # SHA-256(session_pub) when bound); default to the challenge alone (no session binding).
        rd_post = report_data if report_data is not None else challenge

        tx = transport if transport is not None else (
            httpx.HTTPTransport(uds=socket_path) if socket_path else None
        )
        with httpx.Client(transport=tx, timeout=10.0) as client:
            resp = client.post(quote_url, json={"report_data": rd_post})
            resp.raise_for_status()
            q = resp.json()
            quote = q.get("quote") or q.get("intel_quote")
            if not quote:
                raise AttestationError("dstack GetQuote returned no quote")
            # Fail-closed sanity check that the agent bound OUR challenge verbatim: the returned
            # report_data must begin with the challenge hex (the client re-checks this against
            # the parsed quote, but a mismatch here means a misconfigured/wrong agent -> 503).
            rd = (q.get("report_data") or "").lower().removeprefix("0x")
            if rd and not rd.startswith(challenge.lower()):
                raise AttestationError("dstack quote report_data is not bound to the challenge")

            bundle: dict = {"regime": "tdx-onchain", "challenge": challenge, "intel_quote": quote}
            if q.get("event_log"):
                bundle["event_log"] = q["event_log"]  # RTMR0..3 replay (client-side)

            # CVM identity for measurement-pinning (client reads info.compose_hash). Best-effort:
            # the quote alone is sufficient for the §2.1d binding, so a missing /Info is not fatal.
            if info_url:
                try:
                    info = client.post(info_url, json={}).json()
                    bundle["info"] = {
                        k: info[k]
                        for k in ("compose_hash", "app_id", "instance_id", "device_id", "app_name")
                        if isinstance(info.get(k), str)
                    }
                except Exception:  # noqa: BLE001 - identity is supplementary; the quote is the proof
                    pass
            return bundle

    return _fetch


def get_inference(settings: Settings = Depends(get_settings)):
    """Return an async `complete(prompt)->str` bound to the configured attested-inference
    provider, or None if `inference_base` is unset (then /v1/chat falls back to Letta).
    Tests override this dependency with a fake."""
    if not settings.inference_base:
        return None

    async def _complete(prompt: str, model: str | None = None) -> str:
        from app import inference_backend, models_catalog

        chosen = settings.inference_model
        if model and model != chosen:
            # Per-request model switch (instant + mid-session). TRUST-NO-ONE default: only honour
            # an ATTESTED (TEE-served) model; otherwise fall back to the configured attested
            # default rather than routing a prompt to a non-confidential backend.
            if await models_catalog.is_attested(
                model, base_url=settings.inference_base, api_key=settings.inference_key
            ):
                chosen = model
            elif settings.allow_cloud_models and await models_catalog.is_known_model(
                model, base_url=settings.inference_base, api_key=settings.inference_key
            ):
                # Deployment opted into CLOUD models: honour a real (non-attested) catalog slug.
                # The user picked a model the app LABELS non-confidential; the gateway forwards the
                # opened prompt to that third-party model. Still fail-closed for an UNKNOWN slug.
                chosen = model
        return await inference_backend.complete(
            base_url=settings.inference_base, api_key=settings.inference_key,
            model=chosen, prompt=prompt, timeout=settings.inference_timeout,
        )

    return _complete


def get_receipt_fetcher(settings: Settings = Depends(get_settings)):
    """Return an async `fetch(model)->dict` that fetches+parses the per-response attestation
    receipt from the configured provider, or None if receipts are disabled / inference is unset.
    Tests override this dependency with a fake report fetch (so /v1/chat receipt tests don't hit
    the network and test_chat.py can inject a fixed receipt)."""
    if not settings.inference_base or not settings.receipt_enabled:
        return None

    async def _fetch(model: str) -> dict:
        from app import inference_backend

        return await inference_backend.fetch_receipt(
            base_url=settings.inference_base, api_key=settings.inference_key,
            model=model, timeout=settings.receipt_timeout,
        )

    return _fetch


def get_session_manager() -> SessionManager:
    global _SESSION_MANAGER
    with _SESSION_MANAGER_LOCK:
        if _SESSION_MANAGER is None:
            _SESSION_MANAGER = SessionManager()
        return _SESSION_MANAGER


def get_attestation_provider(settings: Settings = Depends(get_settings)) -> AttestationProvider:
    # T1 returns real dstack evidence from the guest-agent quote endpoint; T0 has no remote
    # TEE to attest. Errors (unconfigured / network) fail closed (503) in evidence_for. The
    # CVM session pubkey is carried in the evidence so the client can derive SK (§6) against a
    # key the verified quote vouches for.
    if settings.run_mode == "cvm":
        return CvmAttestationProvider(
            _dstack_fetch(settings.dstack_quote_url, settings.dstack_socket),
            session_pub=get_session_manager().cvm_pub,
        )
    return PlainAttestationProvider()


async def require_account(
    request: Request,
    registry: AccountRegistry = Depends(get_account_registry),
) -> str:
    """Authenticate a request via seed-signature auth (contracts/gateway-api.md §1) and
    return the routing `account_id`. Any failure -> 401 (no PII in the detail)."""
    try:
        req = parse_auth_header(request.headers.get("authorization"))
        account = registry.get(req.account_id)
        if account is None:
            raise AuthError("unknown account")
        verify(account.ed25519_pub(), req, request.method, request.url.path)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized") from exc
    return req.account_id
