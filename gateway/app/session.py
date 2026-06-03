"""Confidential session channel — SERVER side (identity-envelope.md §6).

In `cvm` mode the in-CVM gateway is INSIDE the attested boundary, so it legitimately holds a
per-session working-memory key (WMK) in TEE RAM. It derives the session key
`SK = HKDF(X25519(cvm_session_priv, client_eph_pub), info = label ‖ client_pub ‖ cvm_pub)`,
opens the client-sealed WMK (XChaCha20-Poly1305), uses it for the session, and **never
persists it** (dropped on `end()` / process exit).

Byte-identical to the reference `swifty_crypto.session` / `.envelope` (parity-tested against
their vectors). Established primitives only: X25519 + HKDF-SHA256 via `cryptography`,
XChaCha20-Poly1305 via libsodium (`pynacl`) — `cryptography` has only IETF ChaCha20 (12-byte
nonce), not the 24-byte XChaCha20 the envelope uses.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import threading

import nacl.bindings as sodium
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_LABEL = b"swifty/session/v1"
WMK_DELIVERY_PURPOSE = "wmk-delivery"
CHAT_PURPOSE = "chat"  # live-turn prompt/response envelopes sealed to SK
KEY_LEN = 32
NONCE_LEN = 24  # XChaCha20-Poly1305-IETF


def x25519_keypair() -> tuple[bytes, bytes]:
    """(private_bytes[32], public_bytes[32]) for the CVM's ephemeral session key."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def derive_session_key(my_private: bytes, their_public: bytes, *, client_pub: bytes, cvm_pub: bytes) -> bytes:
    """SK from ECDH + HKDF, binding BOTH endpoints' public keys (anti-UKS/MITM). Matches
    swifty_crypto.session.derive_session_key exactly so client and CVM agree."""
    if len(client_pub) != KEY_LEN or len(cvm_pub) != KEY_LEN:
        raise ValueError("public keys must be 32 bytes")
    if len(my_private) != KEY_LEN or len(their_public) != KEY_LEN:
        raise ValueError("session keys must be 32 bytes")
    shared = X25519PrivateKey.from_private_bytes(my_private).exchange(
        X25519PublicKey.from_public_bytes(their_public)
    )
    info = SESSION_LABEL + client_pub + cvm_pub  # fixed-length pubs -> unambiguous
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(shared)


def _aad(account_id: str, purpose: str, v: int) -> bytes:
    # Matches swifty_crypto.envelope._aad (newline-delimited, SHA-256).
    return hashlib.sha256(f"{account_id}\n{purpose}\n{v}".encode()).digest()


def _open(session_key: bytes, *, nonce: bytes, aad: bytes, ct: bytes, v: int, account_id: str, purpose: str) -> bytes:
    """Open an SK-sealed blob. Fail-closed: re-derives the AAD from the authoritative
    account_id/purpose/v and constant-time-checks it against the wire AAD BEFORE the AEAD
    open (so a blob can't be replayed across accounts/purposes), then XChaCha20 decrypts (the
    tag also covers the AAD). Any tamper raises."""
    expected = _aad(account_id, purpose, v)
    if not hmac.compare_digest(expected, aad):
        raise ValueError("aad does not bind to this account/purpose/v")
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, expected, nonce, session_key)


def _seal(session_key: bytes, plaintext: bytes, *, account_id: str, purpose: str, v: int = 1) -> tuple[bytes, bytes, bytes]:
    """Seal under SK with a fresh CSPRNG nonce; aad binds account_id‖purpose‖v. Returns
    (nonce, aad, ct)."""
    aad = _aad(account_id, purpose, v)
    nonce = sodium.randombytes(NONCE_LEN)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, session_key)
    return nonce, aad, ct


def open_wmk(session_key: bytes, *, nonce: bytes, aad: bytes, ct: bytes, v: int, account_id: str) -> bytes:
    """Open the client-sealed WMK (purpose 'wmk-delivery')."""
    return _open(session_key, nonce=nonce, aad=aad, ct=ct, v=v, account_id=account_id, purpose=WMK_DELIVERY_PURPOSE)


@dataclasses.dataclass
class _Session:
    sk: bytes
    wmk: bytes

    def __repr__(self) -> str:  # never let SK/WMK reach a log/traceback/error-monitor
        return "<_Session sk=REDACTED wmk=REDACTED>"


class SessionManager:
    """Per-process holder of the CVM's session keypair + per-account established sessions
    {SK, WMK}. WMK lives ONLY in memory (TEE RAM analog) — never written to disk; dropped on
    `end()` or process exit (§6). Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cvm_priv, self._cvm_pub = x25519_keypair()  # ephemeral, per process, WRITE-ONCE
        self._sessions: dict[str, _Session] = {}

    def __repr__(self) -> str:  # redact: no SK/WMK in logs/tracebacks
        return f"<SessionManager sessions={len(self._sessions)} cvm_pub={self._cvm_pub.hex()[:16]}…>"

    @property
    def cvm_pub(self) -> bytes:
        """The CVM session public key the client needs (delivered, attestation-bound, in the
        evidence) to derive SK."""
        return self._cvm_pub

    def establish(self, account_id: str, client_eph_pub: bytes, *, nonce: bytes, aad: bytes, ct: bytes, v: int) -> None:
        """Derive SK from the client's ephemeral pub + open the sealed WMK into TEE RAM."""
        # Snapshot the WRITE-ONCE CVM keypair; safe to use lock-free (never reassigned). If
        # keypair rotation is ever added, move this read inside the lock.
        cvm_priv, cvm_pub = self._cvm_priv, self._cvm_pub
        sk = derive_session_key(cvm_priv, client_eph_pub, client_pub=client_eph_pub, cvm_pub=cvm_pub)
        wmk = open_wmk(sk, nonce=nonce, aad=aad, ct=ct, v=v, account_id=account_id)
        # Crypto runs lock-free (pure, no shared state); only the store is locked. Concurrent
        # establishes for the SAME account are content-idempotent (a tenant's WMK is
        # deterministic from its seed), so a last-write-wins overwrite is harmless.
        with self._lock:
            self._sessions[account_id] = _Session(sk=sk, wmk=wmk)

    def wmk_for(self, account_id: str) -> bytes | None:
        with self._lock:
            s = self._sessions.get(account_id)
            return s.wmk if s else None

    def has_session(self, account_id: str) -> bool:
        with self._lock:
            return account_id in self._sessions

    def open_for(self, account_id: str, *, nonce: bytes, aad: bytes, ct: bytes, v: int, purpose: str = CHAT_PURPOSE) -> bytes:
        """Open an SK-sealed blob (e.g. the live-turn prompt) for an established session.
        Raises KeyError if no session, or on any tamper (fail-closed). The session lookup +
        AEAD open happen UNDER the lock as one step, so SK never leaves the locked region and
        a concurrent end() can't slip between the check and the open (XChaCha20 of a small
        blob is microseconds — holding the lock is negligible)."""
        with self._lock:
            s = self._sessions.get(account_id)
            if s is None:
                raise KeyError("no established session")
            return _open(s.sk, nonce=nonce, aad=aad, ct=ct, v=v, account_id=account_id, purpose=purpose)

    def seal_for(self, account_id: str, plaintext: bytes, *, purpose: str = CHAT_PURPOSE, v: int = 1) -> tuple[bytes, bytes, bytes]:
        """Seal a response delta under the session SK (under the lock; SK never leaves).
        Raises KeyError if no session."""
        with self._lock:
            s = self._sessions.get(account_id)
            if s is None:
                raise KeyError("no established session")
            return _seal(s.sk, plaintext, account_id=account_id, purpose=purpose, v=v)

    def end(self, account_id: str) -> None:
        with self._lock:
            self._sessions.pop(account_id, None)
