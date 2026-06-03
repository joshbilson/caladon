#!/usr/bin/env python3
"""Generate byte-parity vectors from the Python `swifty_crypto` REFERENCE → tests/vectors.json.

The reference is the oracle (NOT replaced). `tests/vectors.rs` asserts caladon-core produces
byte-identical output. Run from the repo root:

  PYTHONPATH=. uv run --with pynacl --with cryptography python caladon-core/tests/generate_vectors.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import nacl.bindings as sodium
import swifty_crypto as sc
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from swifty_crypto.envelope import _aad

HERE = os.path.dirname(os.path.abspath(__file__))
SALT = b"swifty/v1"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# ── Crockford base32 seed codec ──────────────────────────────────────────────────────────
# No module in swifty_crypto; the ORACLE is SwiftyKit/SeedCodec.swift (already parity-proven).
# This is a byte-for-byte transcription of that algorithm so the vectors are authoritative.
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CHECKSUM_LEN = 2
_GROUP = 4


def _b32_encode(data: bytes) -> str:
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_CROCKFORD[(buffer >> bits) & 0x1F])
    if bits > 0:
        out.append(_CROCKFORD[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def seed_encode(seed: bytes) -> str:
    chk = hashlib.sha256(seed).digest()[:_CHECKSUM_LEN]
    chars = _b32_encode(seed + chk)
    return "-".join(chars[i : i + _GROUP] for i in range(0, len(chars), _GROUP))


def main() -> None:
    seeds = [b"\x07" * 32, b"\x02" * 32, bytes(range(32))]
    argon2id = []
    for seed in seeds:
        # default (test) params t=3,m=64MiB
        root = sc.argon2id(seed, SALT)
        argon2id.append({"seed": b64(seed), "salt": b64(SALT), "opslimit": 3,
                         "memlimit": 64 * 1024 * 1024, "root": b64(root)})
    # one production-params vector (t=3, m=256MiB) to lock R1 at the real cost
    prod = sc.argon2id(seeds[0], SALT, opslimit=sc.kdf.ARGON2ID_OPSLIMIT_PRODUCTION,
                       memlimit=sc.kdf.ARGON2ID_MEMLIMIT_PRODUCTION)
    argon2id.append({"seed": b64(seeds[0]), "salt": b64(SALT), "opslimit": 3,
                     "memlimit": 256 * 1024 * 1024, "root": b64(prod)})

    hkdf = []
    account_id = []
    ed25519_pub = []
    roots = [sc.argon2id(s, SALT) for s in seeds]
    for root in roots:
        for label in ("swifty/working-mem/v1", "swifty/transcript/v1", "swifty/gateway-auth/v1",
                      "swifty/coding/v1"):
            hkdf.append({"root": b64(root), "label": label, "length": 32,
                         "out": b64(sc.hkdf(root, label))})
        account_id.append({"root": b64(root), "account_id": sc.derive_account_id(root)})
        ed25519_pub.append({"root": b64(root), "pub": b64(sc.derive_ed25519_public(root))})

    padding = []
    for n in (0, 1, 100, 252, 253, 1020, 4092, 70000, 300000):
        pt = bytes((i % 251) for i in range(n))
        padded = sc.pad(pt)
        padding.append({"plaintext": b64(pt), "padded_len": len(padded), "padded": b64(padded)})

    # ── envelope: XChaCha20-Poly1305-IETF seal/open (swifty_crypto/envelope.py) ──────────
    # `seal` draws a random nonce; we exercise the SAME primitive with a FIXED nonce so the
    # vector is byte-identical to `seal(...)` given that nonce. aad = _aad(account,purpose,v).
    envelope = []
    env_key = sc.hkdf(roots[0], "swifty/working-mem/v1")  # any 32-byte key
    env_cases = [
        ("acct-AAAAAAAAAAAA", "wmk-delivery", 1, b""),
        ("acct-AAAAAAAAAAAA", "chat", 1, b"hello, attested world"),
        ("acct-BBBBBBBBBBBB", "chat", 2, bytes(range(64))),
    ]
    for i, (aid, purpose, v, pt) in enumerate(env_cases):
        nonce = bytes(((i * 7 + j) % 256) for j in range(sc.envelope.NONCE_LEN))
        aad = _aad(aid, purpose, v)
        ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, nonce, env_key)
        envelope.append({"key": b64(env_key), "account_id": aid, "purpose": purpose, "v": v,
                         "nonce": b64(nonce), "aad": b64(aad), "plaintext": b64(pt), "ct": b64(ct)})

    # ── session: X25519 + HKDF session key, then seal WMK/chat (swifty_crypto/session.py) ─
    session = []
    # Deterministic test scalars (clamping is applied during scalar-mult; raw bytes here).
    client_priv = bytes([0x11] * 32)
    cvm_priv = bytes([0x22] * 32)
    client_pub = sc.x25519_public(client_priv)
    cvm_pub = sc.x25519_public(cvm_priv)
    # Client derives SK with (client_priv, cvm_pub); CVM derives the SAME with (cvm_priv, client_pub).
    sk_client = sc.derive_session_key(client_priv, cvm_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    sk_cvm = sc.derive_session_key(cvm_priv, client_pub, client_pub=client_pub, cvm_pub=cvm_pub)
    assert sk_client == sk_cvm, "session keys must agree"
    wmk = sc.derive_wmk(roots[0])
    s_acct = "acct-SESSION-AAAAAA"
    s_nonce = bytes((j * 3 + 1) % 256 for j in range(sc.envelope.NONCE_LEN))
    wmk_ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        wmk, _aad(s_acct, "wmk-delivery", 1), s_nonce, sk_client)
    chat_pt = b"prompt: what is the capital of France?"
    chat_nonce = bytes((j * 5 + 2) % 256 for j in range(sc.envelope.NONCE_LEN))
    chat_ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        chat_pt, _aad(s_acct, "chat", 1), chat_nonce, sk_client)
    session.append({
        "client_priv": b64(client_priv), "cvm_priv": b64(cvm_priv),
        "client_pub": b64(client_pub), "cvm_pub": b64(cvm_pub),
        "session_key": b64(sk_client), "account_id": s_acct,
        "wmk": b64(wmk), "wmk_nonce": b64(s_nonce), "wmk_v": 1, "wmk_ct": b64(wmk_ct),
        "chat_plaintext": b64(chat_pt), "chat_nonce": b64(chat_nonce), "chat_v": 1, "chat_ct": b64(chat_ct),
    })
    # A low-order point case: the X25519 small-order base points yield an all-zero shared secret.
    # cryptography raises in exchange(); Rust must reject. We just record the bad peer key bytes.
    low_order = []
    for label, pub in (("all_zero", bytes(32)), ("one", bytes([1]) + bytes(31)),
                       ("small_order_5", bytes([0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
                                                0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
                                                0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
                                                0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00]))):
        rejected = False
        try:
            X25519PrivateKey.from_private_bytes(client_priv).exchange(
                X25519PublicKey.from_public_bytes(pub))
        except Exception:
            rejected = True
        low_order.append({"label": label, "client_priv": b64(client_priv),
                          "peer_pub": b64(pub), "rejected": rejected})

    # ── ratchet: forward-secret transcript chain (swifty_crypto/ratchet.py) ───────────────
    ratchet_root = sc.derive_transcript_root(roots[0])
    msg_keys = [{"transcript_root": b64(ratchet_root), "step": s,
                 "message_key": b64(sc.message_key_at(ratchet_root, s))} for s in (0, 1, 2, 5, 17)]
    r = sc.TranscriptRatchet(ratchet_root)
    advance = []
    for _ in range(4):
        step, mk = r.advance()
        advance.append({"step": step, "message_key": b64(mk)})
    device_roots = [{"transcript_root": b64(ratchet_root), "device_id": did,
                     "device_root": b64(sc.device_transcript_root(ratchet_root, did))}
                    for did in ("phone", "laptop-2", "ABC")]
    kids = [{"step": st, "device_id": did, "kid": sc.transcript_kid(st, did)}
            for (st, did) in ((0, None), (5, None), (3, "phone"), (12, "laptop-2"))]

    # ── seed_auth: Ed25519 canonical + Authorization header (gateway/app/seed_auth.py) ────
    seed_auth = []
    for root in roots:
        ed_priv = sc.derive_ed25519_private(root)
        ed_seed = ed_priv.private_bytes_raw()
        ed_pub = sc.derive_ed25519_public(root)
        acct = sc.derive_account_id(root)
        for method, path, ts in (("GET", "/v1/models", 1717000000),
                                  ("POST", "/v1/chat", 1717000123)):
            canon = sc.seed_auth_canonical(acct, ts, method, path) if hasattr(sc, "seed_auth_canonical") \
                else f"{acct}\n{ts}\n{method.upper()}\n{path}".encode()
            sig = ed_priv.sign(canon)
            header = f"Swifty acct={acct} ts={ts} sig={base64.b64encode(sig).decode()}"
            seed_auth.append({"ed25519_seed": b64(ed_seed), "ed25519_pub": b64(ed_pub),
                              "account_id": acct, "ts": ts, "method": method, "path": path,
                              "canonical": b64(canon), "sig": b64(sig), "header": header})

    # ── seed_codec: Crockford base32 + checksum (oracle: SwiftyKit/SeedCodec.swift) ───────
    seed_codec = []
    for seed in (b"\x00" * 32, b"\xff" * 32, bytes(range(32)), bytes((i * 7) % 256 for i in range(32))):
        seed_codec.append({"seed": b64(seed), "encoded": seed_encode(seed)})

    vectors = {"argon2id": argon2id, "hkdf": hkdf, "account_id": account_id,
               "ed25519_pub": ed25519_pub, "padding": padding,
               "envelope": envelope, "session": session, "low_order": low_order,
               "ratchet_message_key": msg_keys, "ratchet_advance": advance,
               "ratchet_device_root": device_roots, "ratchet_kid": kids,
               "seed_auth": seed_auth, "seed_codec": seed_codec}
    with open(os.path.join(HERE, "vectors.json"), "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"wrote {os.path.join(HERE, 'vectors.json')}: "
          f"{len(argon2id)} argon2id, {len(hkdf)} hkdf, {len(account_id)} account_id, "
          f"{len(ed25519_pub)} ed25519, {len(padding)} padding, {len(envelope)} envelope, "
          f"{len(session)} session, {len(low_order)} low_order, {len(msg_keys)} msg_keys, "
          f"{len(advance)} advance, {len(device_roots)} device_root, {len(kids)} kid, "
          f"{len(seed_auth)} seed_auth, {len(seed_codec)} seed_codec")


if __name__ == "__main__":
    main()
