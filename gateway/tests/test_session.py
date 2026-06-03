"""Gateway session crypto (identity-envelope §6) — parity with swifty_crypto + SessionManager.

The hardcoded vectors were generated from the reference `swifty_crypto.session`/`.envelope`
(client priv 0x11·32, cvm priv 0x22·32). If the gateway's derivation/open ever diverges,
the client-derived SK / client-sealed WMK won't interoperate — these pin that.
"""

from __future__ import annotations

import nacl.bindings as sodium
import pytest

from app import session

# --- swifty_crypto reference vectors -------------------------------------------------------
CLIENT_PUB = bytes.fromhex("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13")
CVM_PUB = bytes.fromhex("0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20")
CVM_PRIV = b"\x22" * 32
SK = bytes.fromhex("6de96e935bc6ff553866ba3477ace6942c0a1c391efa9a0b7c22794bd9bd6253")
WMK = b"\xab" * 32
ACCT = "acct_0123456789abcdef"
NONCE = bytes.fromhex("7c5ef3b37253aa3f916b109b0951650d24138822ce8fdab4")
AAD = bytes.fromhex("ab12f0a85ff451f2a9497b8416524df7cd4241c441742fae6ef6ba98b1e7cf1f")
CT = bytes.fromhex("c49ecc485b89451f1ef1fa82382227c9465580f7717b89bf413e3f73327e7673cf44ea9b70a3db923a253b0c1bcf41aa")


def test_cvm_derives_the_same_session_key_as_the_client():
    # CVM side: my=cvm_priv, peer=client_pub; must equal the reference SK the client derived.
    sk = session.derive_session_key(CVM_PRIV, CLIENT_PUB, client_pub=CLIENT_PUB, cvm_pub=CVM_PUB)
    assert sk == SK


def test_open_wmk_opens_a_swifty_sealed_envelope():
    wmk = session.open_wmk(SK, nonce=NONCE, aad=AAD, ct=CT, v=1, account_id=ACCT)
    assert wmk == WMK


def test_open_wmk_rejects_tampered_ct():
    bad = bytes([CT[0] ^ 0x01]) + CT[1:]
    with pytest.raises(Exception):
        session.open_wmk(SK, nonce=NONCE, aad=AAD, ct=bad, v=1, account_id=ACCT)


def test_open_wmk_rejects_wrong_account_binding():
    with pytest.raises(ValueError):
        session.open_wmk(SK, nonce=NONCE, aad=AAD, ct=CT, v=1, account_id="someone_else_0123456789")


def test_derive_rejects_bad_lengths():
    with pytest.raises(ValueError):
        session.derive_session_key(CVM_PRIV, CLIENT_PUB, client_pub=b"short", cvm_pub=CVM_PUB)
    with pytest.raises(ValueError):
        session.derive_session_key(b"short", CLIENT_PUB, client_pub=CLIENT_PUB, cvm_pub=CVM_PUB)


def test_derive_rejects_identity_point():
    """The all-zero (identity) peer point -> all-zero ECDH output; `cryptography` raises its
    contributory-behaviour check -> fail closed (parity with the reference + the Swift
    client). Pinned so a backend swap can't silently regress. (Note: RFC 7748 X25519 does
    NOT mandate rejecting every small-subgroup point, so only the identity point is a
    guaranteed reject; the SK's anti-UKS binding covers substituted valid keys.)"""
    priv, _ = session.x25519_keypair()
    with pytest.raises(Exception):
        session.derive_session_key(priv, b"\x00" * 32, client_pub=b"\x00" * 32, cvm_pub=b"\x00" * 32)


# --- SessionManager round-trip (random CVM keypair; seal under the derived SK) --------------
def _seal(sk: bytes, msg: bytes, account_id: str, v: int = 1) -> dict:
    aad = session._aad(account_id, session.WMK_DELIVERY_PURPOSE, v)
    nonce = sodium.randombytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, sk)
    return {"nonce": nonce, "aad": aad, "ct": ct, "v": v}


def test_session_manager_round_trip_and_drop():
    mgr = session.SessionManager()
    client_priv, client_pub = session.x25519_keypair()
    # client derives SK from the CVM's published session pub + its own ephemeral
    sk = session.derive_session_key(client_priv, mgr.cvm_pub, client_pub=client_pub, cvm_pub=mgr.cvm_pub)
    env = _seal(sk, WMK, ACCT)
    assert mgr.has_session(ACCT) is False
    mgr.establish(ACCT, client_pub, nonce=env["nonce"], aad=env["aad"], ct=env["ct"], v=env["v"])
    assert mgr.wmk_for(ACCT) == WMK
    mgr.end(ACCT)
    assert mgr.wmk_for(ACCT) is None  # WMK dropped (§6 discard-on-end)


def test_session_manager_tenant_isolation():
    mgr = session.SessionManager()
    cpriv, cpub = session.x25519_keypair()
    sk = session.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    env = _seal(sk, WMK, "accountA_0123456789ab")
    mgr.establish("accountA_0123456789ab", cpub, nonce=env["nonce"], aad=env["aad"], ct=env["ct"], v=1)
    assert mgr.wmk_for("accountB_0123456789ab") is None  # B never sees A's WMK


def test_wmk_never_written_to_disk():
    # Structural: the manager keeps state in-memory only (no path/file attribute).
    mgr = session.SessionManager()
    assert not any("path" in a.lower() or "file" in a.lower() for a in vars(mgr))


def test_repr_redacts_secrets():
    """SK/WMK must never appear in repr (logs/tracebacks). The session object + manager redact."""
    mgr = session.SessionManager()
    cpriv, cpub = session.x25519_keypair()
    sk = session.derive_session_key(cpriv, mgr.cvm_pub, client_pub=cpub, cvm_pub=mgr.cvm_pub)
    env = _seal(sk, WMK, ACCT)
    mgr.establish(ACCT, cpub, nonce=env["nonce"], aad=env["aad"], ct=env["ct"], v=1)
    assert WMK.hex() not in repr(mgr) and "REDACTED" not in repr(mgr)  # mgr shows counts only
    sess = mgr._sessions[ACCT]
    assert "REDACTED" in repr(sess)
    assert WMK.hex() not in repr(sess) and sess.sk.hex() not in repr(sess)
