"""Extra crypto tests: account_id formula consistency, open() binding mode, seed guard.

(Complements the contract spec in test_identity_envelope_contract.py.)
"""

from __future__ import annotations

import base64
import hashlib

import pytest

crypto = pytest.importorskip("swifty_crypto")

SALT = b"swifty/v1"


@pytest.fixture
def root() -> bytes:
    return crypto.argon2id(b"\x01" * 32, SALT)


def test_account_id_matches_the_keybound_formula(root: bytes) -> None:
    """derive_account_id MUST equal urlsafe_b64_nopad(SHA256("swifty/account/v1" || pub)),
    i.e. the SAME formula gateway/app/ids.py uses, so a client-derived account_id verifies
    at onboarding (B2-bis). Recomputed independently here."""
    pub = crypto.derive_ed25519_public(root)
    expected = base64.urlsafe_b64encode(hashlib.sha256(b"swifty/account/v1" + pub).digest()).decode().rstrip("=")
    assert crypto.derive_account_id(root) == expected


def test_account_id_matches_gateway_ids_module(root: bytes) -> None:
    """Cross-check directly against the gateway's implementation (drift guard)."""
    ids = pytest.importorskip("app.ids", reason="gateway package not on path in this env")
    pub = crypto.derive_ed25519_public(root)
    assert crypto.derive_account_id(root) == ids.derive_account_id(pub)


def test_open_binding_mode_accepts_correct_context(root: bytes) -> None:
    wmk = crypto.derive_wmk(root)
    aid = crypto.derive_account_id(root)
    env = crypto.seal(wmk, b"mem", account_id=aid, purpose="working-mem", v=1)
    assert crypto.open(wmk, env, account_id=aid, purpose="working-mem") == b"mem"


def test_open_binding_mode_rejects_wrong_account_or_purpose(root: bytes) -> None:
    wmk = crypto.derive_wmk(root)
    aid = crypto.derive_account_id(root)
    env = crypto.seal(wmk, b"mem", account_id=aid, purpose="working-mem", v=1)
    with pytest.raises(Exception):
        crypto.open(wmk, env, account_id="someone_else_0123456789", purpose="working-mem")
    with pytest.raises(Exception):
        crypto.open(wmk, env, account_id=aid, purpose="transcript")


def test_argon2id_rejects_short_seed() -> None:
    with pytest.raises(ValueError):
        crypto.argon2id(b"short", SALT)


@pytest.mark.parametrize("seed", [b"\x01" * 32, b"\x02\x07" * 16])
def test_coding_tier_is_isolated_from_personal(seed: bytes) -> None:
    """B7: the coding tier is an INDEPENDENT key tree. The coding CVM gets only
    `coding_root`. The INFEASIBILITY of deriving personal keys from coding_root rests on
    HKDF-SHA256 one-wayness (coding_root = HKDF(root) can't recover root) — assumed, not
    unit-testable; here we assert the observable property: NO key material is shared between
    the tiers, across the FULL personal label set and >1 seed."""
    root = crypto.argon2id(seed, SALT)
    coding_root = crypto.derive_coding_root(root)
    personal = {
        crypto.derive_wmk(root),
        crypto.derive_transcript_root(root),
        crypto.hkdf(root, "swifty/metadata/v1"),
        crypto.derive_ed25519_public(root),
        root,
    }
    coding = {
        coding_root,
        crypto.coding_wmk(coding_root),
        crypto.coding_transcript_root(coding_root),
    }
    assert personal.isdisjoint(coding)


def test_ratchet_forward_secrecy(root: bytes) -> None:
    """Forward secrecy: from the COMPROMISED current chain key an attacker can only derive
    FUTURE message keys (forward); the past keys mk0/mk1 are not among anything derivable
    forward, and there is no API to ratchet BACKWARD. (Recovering mk0/mk1 from `compromised`
    would require inverting HKDF-SHA256, which is cryptographically assumed infeasible — not
    something a unit test can prove, only the construction's one-wayness guarantees it.)"""
    troot = crypto.derive_transcript_root(root)
    r = crypto.TranscriptRatchet(troot)
    _, mk0 = r.advance()
    _, mk1 = r.advance()
    past = {mk0, mk1}
    compromised = r._chain_key  # white-box: attacker grabs current state after 2 entries
    attacker = crypto.TranscriptRatchet(compromised)
    forward_keys = {attacker.advance()[1] for _ in range(5)}  # all keys derivable forward
    assert past.isdisjoint(forward_keys)  # no past key reappears going forward
    # there is no backward API on the ratchet (only advance() + step), so mk0/mk1 are
    # unreachable from `compromised` by construction.
    assert not hasattr(attacker, "rewind")


def test_ratchet_does_not_retain_prior_chain_key(root: bytes) -> None:
    """The ratchet keeps only the current chain key (no growing history of prior keys)."""
    r = crypto.TranscriptRatchet(crypto.derive_transcript_root(root))
    before = vars(r).copy()
    r.advance()
    after = vars(r)
    # same set of attributes (just _chain_key + _step), none accumulating prior keys
    assert set(before) == set(after)


def test_message_key_at_rejects_negative_step(root: bytes) -> None:
    with pytest.raises(ValueError):
        crypto.message_key_at(crypto.derive_transcript_root(root), -1)


def test_transcript_kid_roundtrips() -> None:
    assert crypto.step_from_kid(crypto.transcript_kid(0)) == 0
    assert crypto.step_from_kid(crypto.transcript_kid(42)) == 42
    with pytest.raises(ValueError):
        crypto.transcript_kid(-1)
    with pytest.raises(ValueError):
        crypto.step_from_kid("v1")  # not a transcript kid


def test_device_transcript_roots_are_independent(root: bytes) -> None:
    troot = crypto.derive_transcript_root(root)
    a = crypto.device_transcript_root(troot, "deviceA")
    b = crypto.device_transcript_root(troot, "deviceB")
    assert a != b
    assert a != troot and b != troot
    with pytest.raises(ValueError):
        crypto.device_transcript_root(troot, "")


def test_device_chain_replays_from_shared_root(root: bytes) -> None:
    """Multi-device: device A appends on its own chain; another device (same seed -> same
    transcript_root) re-derives A's per-device root and replays A's entries."""
    troot = crypto.derive_transcript_root(root)
    r = crypto.TranscriptRatchet(crypto.device_transcript_root(troot, "deviceA"))
    _, mk0 = r.advance()
    _, mk1 = r.advance()
    reader_root = crypto.device_transcript_root(troot, "deviceA")
    assert crypto.message_key_at(reader_root, 0) == mk0
    assert crypto.message_key_at(reader_root, 1) == mk1


def test_multidevice_kid_roundtrip() -> None:
    assert crypto.parse_transcript_kid(crypto.transcript_kid(5, device_id="phone")) == ("phone", 5)
    assert crypto.parse_transcript_kid(crypto.transcript_kid(5)) == (None, 5)
    assert crypto.step_from_kid(crypto.transcript_kid(7, device_id="mac")) == 7
    with pytest.raises(ValueError):
        crypto.transcript_kid(0, device_id="bad:id")  # device_id must not contain ':'
    with pytest.raises(ValueError):
        crypto.transcript_kid(0, device_id="bad/id")  # nor '/' (HKDF label separator)
    with pytest.raises(ValueError):
        crypto.device_transcript_root(b"\x00" * 32, "bad/id")
    with pytest.raises(ValueError):
        crypto.parse_transcript_kid("t:5")  # empty device_id must not parse
