"""Confidential session channel (identity-envelope §6): X25519→SK + WMK delivery."""

from __future__ import annotations

import pytest

crypto = pytest.importorskip("swifty_crypto")

CLIENT_PRIV = b"\x11" * 32
CVM_PRIV = b"\x22" * 32


@pytest.fixture
def channel():
    client_pub = crypto.x25519_public(CLIENT_PRIV)
    cvm_pub = crypto.x25519_public(CVM_PRIV)
    return client_pub, cvm_pub


def test_both_sides_derive_the_same_session_key(channel):
    client_pub, cvm_pub = channel
    sk_client = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    sk_cvm = crypto.derive_session_key(CVM_PRIV, client_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    assert sk_client == sk_cvm
    assert len(sk_client) == 32


def test_session_key_matches_vector(channel):
    """Pin the SK so a Swift/parity drift is caught (vectors: priv=0x11·32 / 0x22·32)."""
    client_pub, cvm_pub = channel
    sk = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    assert sk.hex() == "6de96e935bc6ff553866ba3477ace6942c0a1c391efa9a0b7c22794bd9bd6253"


def test_wmk_delivery_round_trip(channel):
    client_pub, cvm_pub = channel
    sk_c = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    sk_v = crypto.derive_session_key(CVM_PRIV, client_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    root = crypto.argon2id(b"\x02" * 32, b"swifty/v1")
    wmk, aid = crypto.derive_wmk(root), crypto.derive_account_id(root)
    env = crypto.seal_wmk(sk_c, wmk, account_id=aid)
    assert crypto.open_wmk(sk_v, env, account_id=aid) == wmk


def test_substituted_key_yields_different_sk_and_fails_open(channel):
    """Anti-UKS/MITM: if the binding pubs differ (an attacker substituted a key), the SK
    differs and the sealed WMK won't open."""
    client_pub, cvm_pub = channel
    attacker_pub = crypto.x25519_public(b"\x33" * 32)
    sk_honest = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    # CVM binds the attacker's pub into info -> different SK
    sk_bound_wrong = crypto.derive_session_key(CVM_PRIV, client_pub, client_pub=client_pub, cvm_pub=attacker_pub)
    assert sk_honest != sk_bound_wrong
    env = crypto.seal_wmk(sk_honest, b"\xaa" * 32, account_id="acct_0123456789abcdef")
    with pytest.raises(Exception):
        crypto.open_wmk(sk_bound_wrong, env, account_id="acct_0123456789abcdef")


def test_tampered_envelope_fails(channel):
    client_pub, cvm_pub = channel
    sk = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    env = crypto.seal_wmk(sk, b"\xbb" * 32, account_id="acct_0123456789abcdef")
    env["ct"] = bytes([env["ct"][0] ^ 0x01]) + env["ct"][1:]
    with pytest.raises(Exception):
        crypto.open_wmk(sk, env, account_id="acct_0123456789abcdef")


def test_wrong_account_binding_fails(channel):
    client_pub, cvm_pub = channel
    sk = crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    env = crypto.seal_wmk(sk, b"\xcc" * 32, account_id="acct_0123456789abcdef")
    with pytest.raises(Exception):
        crypto.open_wmk(sk, env, account_id="someone_else_0123456789")


def test_low_order_point_fails_closed(channel):
    """A low-order/identity peer point (all-zero) yields an all-zero ECDH output;
    `cryptography` rejects it — pin that so a lib downgrade can't silently regress."""
    client_pub, cvm_pub = channel
    with pytest.raises(Exception):
        crypto.derive_session_key(CLIENT_PRIV, bytes(32), client_pub=client_pub, cvm_pub=cvm_pub)


def test_public_key_is_deterministic():
    assert crypto.x25519_public(CLIENT_PRIV) == crypto.x25519_public(CLIENT_PRIV)
    assert crypto.x25519_public(CLIENT_PRIV) != crypto.x25519_public(CVM_PRIV)


def test_derive_session_key_rejects_bad_pub_length(channel):
    client_pub, cvm_pub = channel
    with pytest.raises(ValueError):
        crypto.derive_session_key(CLIENT_PRIV, cvm_pub, client_pub=b"short", cvm_pub=cvm_pub)
