"""Attestation evidence providers for the gateway's GET /v1/attestation handshake.

The client fetches the evidence bundle for the tenant's Agent CVM and verifies it
fail-closed BEFORE sending the working-memory key or any prompt (contracts/attestation.md
§3-§4, contracts/attestation-evidence.md). The gateway is a passthrough: in T1 (cvm) it
returns the dstack TDX evidence with the client's challenge bound; in T0 (plain) there is
no remote TEE to attest (operator == user).
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Protocol, runtime_checkable


class AttestationError(Exception):
    """Evidence unavailable or not bound to the client's challenge -> 503 (fail-closed)."""


@runtime_checkable
class AttestationProvider(Protocol):
    def evidence_for(self, challenge: str) -> dict: ...


class PlainAttestationProvider:
    """T0 self-host: no remote TEE to attest. The client must opt into trusted-self-host."""

    def evidence_for(self, challenge: str) -> dict:
        return {"regime": "none", "tier": "self-host"}


class CvmAttestationProvider:
    """T1: returns the dstack TDX evidence bundle for the Agent CVM with the client's
    `challenge` bound into it (contracts/attestation-evidence.md §1). `fetch_quote` is
    wired to the dstack guest agent at CVM deploy; tests inject a fake."""

    def __init__(self, fetch_quote: Callable[[str], dict], session_pub: bytes | None = None) -> None:
        self._fetch = fetch_quote
        self._session_pub = session_pub

    def evidence_for(self, challenge: str) -> dict:
        try:
            bundle = self._fetch(challenge)
        except AttestationError:
            raise
        except Exception as exc:  # noqa: BLE001 - any fetch/parse failure -> fail closed (503)
            raise AttestationError("evidence fetch failed") from exc
        # Sanity-check the binding the client will independently verify: the evidence must
        # carry THIS challenge (else a stale/replayed quote could be served).
        if bundle.get("challenge") != challenge:
            raise AttestationError("challenge not bound in evidence")
        # The CVM's X25519 session pubkey (§6): the client derives SK against it to deliver
        # WMK. Our dstack /GetQuote binds the CHALLENGE (= SHA-256(client eph_pub)) verbatim into
        # report_data[0:32] (report_data[32:64]=0); session_pub is carried alongside the quote
        # here. HARDENING (deferred to the client live-verify rework, step 3): also bind
        # session_pub into report_data (e.g. report_data = challenge ‖ session_pub) so the
        # verified quote itself vouches for the session key, closing a session_pub-substitution
        # MITM. Today the §6 KDF already binds both pubs (anti-UKS), so a swap yields a dead SK.
        if self._session_pub is not None:
            bundle = {**bundle, "session_pub": base64.b64encode(self._session_pub).decode()}
        return bundle
