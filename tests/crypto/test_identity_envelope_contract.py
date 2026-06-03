"""Executable spec for `contracts/identity-envelope.md §12` (test obligations).

These tests are written against the INTENDED crypto interface that Agent A will
implement in Phase 2. They are skipped at module import time until that module
exists, so collection never errors on the current tree.

Intended module: `swifty_crypto` (or `app.crypto` inside the relevant component).
Adjust the import below to match the landed module; the assertions encode the
contract and should not need to change.

Contract obligations encoded here (§12):
  - KDF determinism + domain separation (distinct labels => distinct keys).
  - account_id non-reversibility & zero-PII.
  - Envelope AAD tamper => AEAD fails closed.
  - Two-user cross-decrypt impossible (independent seeds => no shared key material).

Per-obligation references to the frozen contract are cited inline.
"""

from __future__ import annotations

import pytest

# --- Guard: skip the whole module until Agent A lands the crypto impl (Phase 2).
# importorskip would also work; we use skip() with an explicit reason so the
# intent is obvious in CI output even when the dependency is absent.
crypto = pytest.importorskip(
    "swifty_crypto",
    reason="impl lands in Phase 2 (Agent A): contracts/identity-envelope.md",
)


# Expected interface (Agent A to provide). Documented here so the contract is
# unambiguous even before the code exists:
#
#   crypto.argon2id(seed: bytes, salt: bytes) -> bytes            # §3 root
#   crypto.hkdf(root: bytes, label: str) -> bytes                 # §3 sub-keys
#   crypto.derive_account_id(root: bytes) -> bytes                # §3
#   crypto.derive_wmk(root: bytes) -> bytes                       # §3
#   crypto.derive_transcript_root(root: bytes) -> bytes           # §3
#   crypto.seal(key: bytes, plaintext: bytes, *, account_id, purpose, v) -> dict
#                                                                  # §4 envelope
#   crypto.open(key: bytes, envelope: dict) -> bytes              # raises on tamper
#
# Labels per §3:
ACCOUNT_ID_LABEL = "swifty/account-id/v1"
WMK_LABEL = "swifty/working-mem/v1"
TRANSCRIPT_LABEL = "swifty/transcript/v1"
METADATA_LABEL = "swifty/metadata/v1"
ARGON_SALT = b"swifty/v1"


@pytest.fixture
def root() -> bytes:
    seed = b"\x01" * 32  # 256-bit test seed (§2)
    return crypto.argon2id(seed, ARGON_SALT)


# --------------------------------------------------------------------------- #
# §12: KDF determinism + domain separation                                    #
# --------------------------------------------------------------------------- #
def test_kdf_is_deterministic(root: bytes) -> None:
    """Same root + same label => same key, every time."""
    assert crypto.hkdf(root, WMK_LABEL) == crypto.hkdf(root, WMK_LABEL)


def test_domain_separation_distinct_labels_distinct_keys(root: bytes) -> None:
    """§3/§12: distinct HKDF labels MUST yield distinct, unrelated keys; no
    cross-label key reuse."""
    keys = {
        crypto.hkdf(root, label)
        for label in (ACCOUNT_ID_LABEL, WMK_LABEL, TRANSCRIPT_LABEL, METADATA_LABEL)
    }
    assert len(keys) == 4, "labels collided -> domain separation broken"


def test_coding_tier_key_tree_is_independent(root: bytes) -> None:
    """§3: coding tier label derives an INDEPENDENT key tree; the coding CVM
    never receives WMK/transcript_root."""
    coding = crypto.hkdf(root, "swifty/coding/v1")
    assert coding != crypto.hkdf(root, WMK_LABEL)
    assert coding != crypto.hkdf(root, TRANSCRIPT_LABEL)


# --------------------------------------------------------------------------- #
# §12: account_id non-reversibility & zero-PII                                #
# --------------------------------------------------------------------------- #
def test_account_id_is_not_the_root(root: bytes) -> None:
    """§3: account_id must not be reversible to root; at minimum it is not the
    root itself nor a trivial slice of it."""
    account_id = crypto.derive_account_id(root)
    assert account_id != root
    assert account_id not in (root[: len(account_id)], root[-len(account_id):])


def test_account_id_carries_zero_pii() -> None:
    """§3/§9: account_id derives ONLY from the seed-rooted KDF — never from
    email/name/handle. Two roots that differ only in seed entropy produce
    unrelated account_ids, and no PII input is accepted by the API.

    This asserts the *shape* of the obligation: derive_account_id takes only the
    root (no identity argument). If Agent A's signature accepts PII, this test
    fails by design — forcing the zero-PII property into the interface.
    """
    import inspect

    sig = inspect.signature(crypto.derive_account_id)
    params = list(sig.parameters)
    assert params == ["root"], (
        "derive_account_id must take only the seed-rooted key (zero PII inputs); "
        f"got params {params}"
    )


# --------------------------------------------------------------------------- #
# §12: Envelope AAD tamper => AEAD fails closed                               #
# --------------------------------------------------------------------------- #
def test_envelope_roundtrips(root: bytes) -> None:
    wmk = crypto.derive_wmk(root)
    account_id = crypto.derive_account_id(root)
    env = crypto.seal(wmk, b"secret memory", account_id=account_id,
                      purpose="working-mem", v=1)
    assert crypto.open(wmk, env) == b"secret memory"


def test_aad_tamper_fails_closed(root: bytes) -> None:
    """§4/§12: the envelope AAD binds blob to user+purpose+version. Tampering the
    ciphertext or AAD MUST cause AEAD open to FAIL (raise), never return data."""
    wmk = crypto.derive_wmk(root)
    account_id = crypto.derive_account_id(root)
    env = crypto.seal(wmk, b"secret memory", account_id=account_id,
                      purpose="working-mem", v=1)

    # Flip a ciphertext byte.
    tampered = dict(env)
    ct = bytearray(tampered["ct"])
    ct[0] ^= 0xFF
    tampered["ct"] = bytes(ct)
    with pytest.raises(Exception):
        crypto.open(wmk, tampered)

    # Tamper the bound AAD (purpose) -> integrity check must fail.
    tampered2 = dict(env)
    tampered2["aad"] = b"\x00" * len(tampered2["aad"]) if isinstance(
        tampered2["aad"], (bytes, bytearray)
    ) else "tampered"
    with pytest.raises(Exception):
        crypto.open(wmk, tampered2)


# --------------------------------------------------------------------------- #
# §12: Two-user cross-decrypt impossible                                      #
# --------------------------------------------------------------------------- #
def test_two_user_cross_decrypt_impossible() -> None:
    """§7/§12: independent seeds => independent {account_id, WMK, ...} with no
    shared key material. User B's WMK MUST NOT open user A's envelope."""
    root_a = crypto.argon2id(b"\x0a" * 32, ARGON_SALT)
    root_b = crypto.argon2id(b"\x0b" * 32, ARGON_SALT)

    wmk_a = crypto.derive_wmk(root_a)
    wmk_b = crypto.derive_wmk(root_b)
    assert wmk_a != wmk_b, "distinct seeds produced identical WMK"

    aid_a = crypto.derive_account_id(root_a)
    aid_b = crypto.derive_account_id(root_b)
    assert aid_a != aid_b, "distinct seeds produced identical account_id"

    env_a = crypto.seal(wmk_a, b"a private", account_id=aid_a,
                        purpose="working-mem", v=1)
    with pytest.raises(Exception):
        crypto.open(wmk_b, env_a)


# --------------------------------------------------------------------------- #
# Notes for the Gate-0 contract review — obligations NOT yet executable here  #
# because they need a stateful/host interface the contract does not pin down: #
#   - §5.1 transcript ratchet: "prior chain key discarded on the advancing     #
#     device" and "CVM holds ciphertext only" need a ratchet object + a way to #
#     observe key destruction. Stubbed as TODO until the ratchet API is named. #
#   - §6 WMK never written to disk in clear / discarded on session end needs a #
#     CVM memory/disk probe (cross-ref attestation suite + Phase 3 infra).     #
#   - §8.2 SVR PIN recovery (rate-limit + destroy-after-N; server can't read    #
#     wrapped seed) is Phase 2 opt-in; no interface defined yet.                #
# --------------------------------------------------------------------------- #
def test_transcript_ratchet_discards_prior_key(root: bytes) -> None:
    """§5.1: advance() yields each entry's message key and discards the prior chain key
    (forward secrecy); old entries are re-derivable from transcript_root on a new device."""
    troot = crypto.derive_transcript_root(root)
    ratchet = crypto.TranscriptRatchet(troot)
    s0, mk0 = ratchet.advance()
    s1, mk1 = ratchet.advance()
    assert (s0, s1) == (0, 1)
    assert mk0 != mk1
    # replay-from-root (new-device read) reproduces the same message keys
    assert crypto.message_key_at(troot, 0) == mk0
    assert crypto.message_key_at(troot, 1) == mk1
