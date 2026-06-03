//! Encryption envelope (contracts/identity-envelope.md §4): XChaCha20-Poly1305-IETF AEAD.
//! Byte-identical to `swifty_crypto/envelope.py` (the reference) and `SwiftyKit/Crypto.swift`.
//!
//! The server stores only opaque envelopes; it holds no key and cannot decrypt. The AAD binds
//! the blob to account+purpose+version (B1), so a blob can't be replayed across users or
//! purposes — the AEAD tag covers the AAD, so tampering it fails the open (fail-closed).
//!
//! `chacha20poly1305::XChaCha20Poly1305` is the libsodium `crypto_aead_xchacha20poly1305_ietf`
//! construction: 24-byte (192-bit) nonce, 16-byte Poly1305 tag appended to the ciphertext —
//! exactly what pynacl's `crypto_aead_xchacha20poly1305_ietf_encrypt` returns.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

pub const ALG: &str = "xchacha20poly1305";
/// XChaCha20-Poly1305-IETF NPUBBYTES (== libsodium crypto_aead_xchacha20poly1305_ietf_NPUBBYTES).
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Poly1305 tag length (libsodium ABYTES); appended to the ciphertext by the IETF construction.
pub const TAG_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    BadKeyLength,
    BadNonceLength,
    /// Decrypt/verify failed — ciphertext or AAD tampered, or wrong key/nonce.
    OpenFailed,
    SealFailed,
}

/// Envelope AAD = SHA-256("{account_id}\n{purpose}\n{v}") — byte-identical to
/// `swifty_crypto._aad` (newline-delimited so the fields can't be re-segmented; B1).
pub fn aad(account_id: &str, purpose: &str, v: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("{account_id}\n{purpose}\n{v}").as_bytes());
    h.finalize().into()
}

/// Deterministic seal with a caller-supplied 24-byte nonce — the parity entry point (Python's
/// `seal` draws a random nonce, so this mirrors the inner AEAD call for fixed-vector testing).
/// Returns the ciphertext+tag (`ct`), exactly as pynacl's
/// `crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)`.
pub fn seal_with_nonce(
    key: &[u8],
    plaintext: &[u8],
    account_id: &str,
    purpose: &str,
    v: i64,
    nonce: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if key.len() != KEY_LEN {
        return Err(EnvelopeError::BadKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::BadNonceLength);
    }
    let ad = aad(account_id, purpose, v);
    seal_raw(key, plaintext, &ad, nonce)
}

/// Low-level seal: AAD passed in directly (used by `session`, which derives its own AAD).
pub fn seal_raw(
    key: &[u8],
    plaintext: &[u8],
    ad: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if key.len() != KEY_LEN {
        return Err(EnvelopeError::BadKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::BadNonceLength);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| EnvelopeError::SealFailed)
}

/// Random-nonce seal (production path). Returns `(nonce, ct)`. A fresh CSPRNG 24-byte nonce per
/// call (identity-envelope §4/B4). Mirrors `swifty_crypto.seal` minus the dict wrapper.
pub fn seal(
    key: &[u8],
    plaintext: &[u8],
    account_id: &str,
    purpose: &str,
    v: i64,
) -> Result<([u8; NONCE_LEN], Vec<u8>), EnvelopeError> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = seal_with_nonce(key, plaintext, account_id, purpose, v, nonce.as_slice())?;
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce.as_slice());
    Ok((n, ct))
}

/// Decrypt + verify against the supplied AAD. Fails closed on ANY tamper (ct or AAD) — never
/// returns data for a modified envelope. Mirrors `swifty_crypto.open` / `SwiftyCrypto.open`.
pub fn open(key: &[u8], nonce: &[u8], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if key.len() != KEY_LEN {
        return Err(EnvelopeError::BadKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::BadNonceLength);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: ad,
            },
        )
        .map_err(|_| EnvelopeError::OpenFailed)
}

/// Convenience open that re-derives the AAD from account_id/purpose/v (enforces the §4 binding
/// on READ, matching Python's `open(..., account_id=, purpose=)` form).
pub fn open_bound(
    key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    account_id: &str,
    purpose: &str,
    v: i64,
) -> Result<Vec<u8>, EnvelopeError> {
    let ad = aad(account_id, purpose, v);
    open(key, nonce, &ad, ct)
}
