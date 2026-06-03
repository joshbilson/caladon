"""Executable spec for `contracts/attestation.md §10` (test obligations).

The attestation verifier is the client-side gate: before ANY plaintext (or the
WMK) leaves the phone, the client runs the §4 algorithm and MUST fail-closed on
any tampered evidence field. These tests encode §10 against the INTENDED verifier
interface that Agent D / the verifier author will land in Phase 3.

Skipped at import time until that module exists, so collection never errors.

Intended module: `swifty_attestation` exposing:

    class Evidence(TypedDict / dataclass):
        tdx_quote, mrtd, rtmr, compose_hash, app_id, dstack_cert,
        event_log, registry_ref, report_data        # §2.1
    class Receipt:  # §2.2 per-response
        sig, compose_hash, app_id, no_log

    verifier = swifty_attestation.Verifier(
        pinned_measurements=..., pinned_compose_hash=..., expected_app_id=...,
        pinned_inference_build=..., registry=...,
    )
    verifier.verify_session(evidence, eph_pub) -> SessionResult
        # .ok: bool ; .reason: str ; raises nothing — fail-closed via .ok=False
    verifier.verify_response(receipt, requested_model_slug) -> bool

A passing verify is REQUIRED before send; any tamper => .ok is False (refuse to
send). The fixtures below build a genuine evidence bundle from a known-good
fixture and then mutate one field per test.
"""

from __future__ import annotations

import pytest

att = pytest.importorskip(
    "swifty_attestation",
    reason="verifier lands in Phase 3: contracts/attestation.md §4/§10",
)


# These fixture factories assume Agent D / the verifier author ships a test
# helper that yields a genuine, self-consistent evidence bundle + verifier whose
# pinned set matches it. Named here so the contract is unambiguous.
@pytest.fixture
def genuine():
    """A self-consistent (evidence, eph_pub, verifier) triple where the happy
    path passes. `att.testing.genuine_bundle()` is the expected helper."""
    return att.testing.genuine_bundle()


# --------------------------------------------------------------------------- #
# §10: happy path — plaintext transmitted ONLY after all checks pass          #
# --------------------------------------------------------------------------- #
def test_happy_path_verifies(genuine) -> None:
    evidence, eph_pub, verifier = genuine
    result = verifier.verify_session(evidence, eph_pub)
    assert result.ok, f"genuine evidence rejected: {result.reason}"


# --------------------------------------------------------------------------- #
# §10: tamper each evidence field => refuse to send (fail-closed)             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "field",
    [
        "tdx_quote",     # §4.1 quote signature -> vendor root
        "mrtd",          # §4.3 measurement pinning
        "rtmr",          # §4.3 measurement pinning
        "compose_hash",  # §4.4 compose hash == registry
        "app_id",        # §4.5 expected agent-CVM id
        "report_data",   # §4.6 channel binding == SHA-256(eph_pub)
        "registry_ref",  # §4.4 on-chain registry match
    ],
)
def test_tampered_field_fails_closed(genuine, field) -> None:
    evidence, eph_pub, verifier = genuine
    tampered = att.testing.tamper(evidence, field)
    result = verifier.verify_session(tampered, eph_pub)
    assert not result.ok, (
        f"verifier accepted tampered {field!r} — MUST fail-closed and send nothing"
    )


def test_tcb_out_of_date_rejected(genuine) -> None:
    """§4.2: TCB OutOfDate/Revoked => reject (only SWHardeningNeeded allow-listed)."""
    evidence, eph_pub, verifier = genuine
    tampered = att.testing.tamper(evidence, "tcb_status", value="OutOfDate")
    assert not verifier.verify_session(tampered, eph_pub).ok


# --------------------------------------------------------------------------- #
# §10: replay a genuine quote against a fresh eph_pub => binding failure       #
# --------------------------------------------------------------------------- #
def test_replay_against_fresh_eph_pub_fails(genuine) -> None:
    """§3/§10: a quote captured from a genuine enclave (report_data binds the
    ORIGINAL eph_pub) MUST NOT verify against a different, fresh eph_pub."""
    evidence, _orig_eph_pub, verifier = genuine
    fresh_eph_pub = att.testing.fresh_eph_pub()
    result = verifier.verify_session(evidence, fresh_eph_pub)
    assert not result.ok, "replayed quote bound to old eph_pub accepted on new channel"


# --------------------------------------------------------------------------- #
# §10: per-response receipt tamper / mid-session compose-hash change           #
# --------------------------------------------------------------------------- #
def test_genuine_receipt_verifies(genuine) -> None:
    _evidence, _eph_pub, verifier = genuine
    receipt = att.testing.genuine_receipt()
    assert verifier.verify_response(receipt, requested_model_slug="qwen")


@pytest.mark.parametrize("field", ["sig", "compose_hash", "app_id"])
def test_tampered_receipt_dropped(genuine, field) -> None:
    """§4.9/§10: tampered per-response receipt => drop response, mark session
    untrusted, stop."""
    _evidence, _eph_pub, verifier = genuine
    receipt = att.testing.tamper(att.testing.genuine_receipt(), field)
    assert not verifier.verify_response(receipt, requested_model_slug="qwen")


def test_no_log_false_rejected(genuine) -> None:
    """§2.2/§4.9: x-phala-no-log must be true; false => reject."""
    _evidence, _eph_pub, verifier = genuine
    receipt = att.testing.tamper(att.testing.genuine_receipt(), "no_log", value=False)
    assert not verifier.verify_response(receipt, requested_model_slug="qwen")


def test_mid_session_compose_hash_change_marks_untrusted(genuine) -> None:
    """§4.9/§10: a mid-session swap (compose_hash changes on a later response)
    => response dropped AND session marked untrusted."""
    _evidence, _eph_pub, verifier = genuine
    swapped = att.testing.tamper(att.testing.genuine_receipt(), "compose_hash")
    assert not verifier.verify_response(swapped, requested_model_slug="qwen")
    assert verifier.session_untrusted, "session not marked untrusted after swap"


# --------------------------------------------------------------------------- #
# §10: network MITM with a self-signed cert => abort                          #
# --------------------------------------------------------------------------- #
def test_mitm_self_signed_cert_aborts(genuine) -> None:
    """§8/§10: a self-signed cert not matching the quote's report_data binding
    => abort (the channel binding catches the MITM)."""
    evidence, eph_pub, verifier = genuine
    mitm = att.testing.tamper(evidence, "dstack_cert", value="self-signed")
    assert not verifier.verify_session(mitm, eph_pub).ok


# --------------------------------------------------------------------------- #
# Notes for the Gate-0 contract review — anything that blocked a real test:    #
#   - §4.2 names "configurable allow-list of SWHardeningNeeded only" but does   #
#     not pin the diagnostic CODE per failure (§8 says "distinct diagnostic     #
#     code" but the codes themselves are unspecified). Tests assert .ok=False   #
#     but cannot yet assert a specific .reason code. Pin the code table in §8.   #
#   - The genuine fixture depends on a test helper (att.testing.genuine_bundle) #
#     that the contract does not mandate the verifier author ship. Flagging so  #
#     Gate-0 can require a deterministic test-vector bundle alongside the impl.  #
# --------------------------------------------------------------------------- #
