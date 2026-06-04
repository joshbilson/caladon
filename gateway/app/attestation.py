"""Attestation evidence providers for the gateway's GET /v1/attestation handshake.

The client fetches the evidence bundle for the tenant's Agent CVM and verifies it
fail-closed BEFORE sending the working-memory key or any prompt (contracts/attestation.md
§3-§4, contracts/attestation-evidence.md). The gateway is a passthrough: in T1 (cvm) it
returns the dstack TDX evidence with the client's challenge bound; in T0 (plain) there is
no remote TEE to attest (operator == user).
"""

from __future__ import annotations

import base64
import hashlib
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

    def __init__(
        self,
        fetch_quote: Callable[[str, str | None], dict],
        session_pub: bytes | None = None,
    ) -> None:
        self._fetch = fetch_quote
        self._session_pub = session_pub

    def evidence_for(self, challenge: str) -> dict:
        # Bind BOTH pubkeys into the quote's report_data (64 bytes):
        #   report_data[0:32]  = SHA-256(client eph_pub)  == the client `challenge` (64 hex)
        #   report_data[32:64] = SHA-256(cvm session_pub) (64 hex)
        # We POST the concatenated 128-hex string to /GetQuote so the dstack agent writes it
        # VERBATIM into the TDX quote. When there is no session key (non-cvm/plain), bind the
        # challenge alone (no second half) so plain quotes still verify report_data[0:32].
        report_data = challenge
        if self._session_pub is not None:
            report_data = challenge + hashlib.sha256(self._session_pub).hexdigest()
        try:
            bundle = self._fetch(challenge, report_data)
        except AttestationError:
            raise
        except Exception as exc:  # noqa: BLE001 - any fetch/parse failure -> fail closed (503)
            raise AttestationError("evidence fetch failed") from exc
        # Sanity-check the binding the client will independently verify: the evidence must
        # carry THIS challenge (else a stale/replayed quote could be served).
        if bundle.get("challenge") != challenge:
            raise AttestationError("challenge not bound in evidence")
        # The CVM's X25519 session pubkey (§6): the client derives SK against it to deliver WMK.
        # IMPLEMENTED (was deferred): the quote now binds session_pub too, so the verified quote
        # itself vouches for the session key — report_data = challenge ‖ SHA-256(session_pub),
        # i.e. report_data[0:32]=SHA-256(client eph_pub), report_data[32:64]=SHA-256(session_pub).
        # The client re-derives SHA-256(decoded session_pub) and refuses (BindingMismatch) unless
        # it equals report_data[32:64], closing the session_pub-substitution MITM BEFORE deriving
        # SK. The §6 KDF additionally binds both pubs (anti-UKS), so even a swap yields a dead SK.
        if self._session_pub is not None:
            bundle = {**bundle, "session_pub": base64.b64encode(self._session_pub).decode()}
        return bundle
