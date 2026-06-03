//! Passkey-PRF seed custody (Confer pattern; BUILD-BLUEPRINT §P1 `passkey.rs`).
//!
//! A WebAuthn PRF-extension evaluation yields a 32-byte secret (`prf32`) that never persists. We
//! derive a wrapping key from it (HKDF-SHA256, domain-separated) and seal the 32-byte account
//! seed under that key with XChaCha20-Poly1305 (the same AEAD as the rest of caladon-core). This
//! lets a passkey be the easy-default custody for the seed (hardware-backed), alongside the
//! Mullvad seed codec (sovereign/portable recovery).
//!
//! NEW module — no Python reference. Tested by round-trip + a fixed vector (the wrapping key is a
//! deterministic HKDF, so the KEY itself is a stable fixture even though the AEAD nonce is random).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::envelope::{self, EnvelopeError};

/// XChaCha20-Poly1305 nonce length (re-exported for callers building fixed nonces).
pub use crate::envelope::NONCE_LEN;

/// HKDF info label for the passkey-derived wrapping key (domain separation).
pub const WRAPPING_LABEL: &[u8] = b"caladon/passkey-wrapping/v1";
/// AAD binding the sealed blob to its purpose (so a wrapped-seed blob can't be replayed as some
/// other passkey-sealed payload). Bound via the AEAD tag.
pub const SEED_WRAP_AAD: &[u8] = b"caladon/passkey-seed/v1";

pub const PRF_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const SEED_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum PasskeyError {
    BadPrfLength,
    BadSeedLength,
    /// Unwrap failed — wrong passkey/PRF, or a tampered blob. Fail closed.
    UnwrapFailed,
    Envelope(EnvelopeError),
}

impl From<EnvelopeError> for PasskeyError {
    fn from(e: EnvelopeError) -> Self {
        PasskeyError::Envelope(e)
    }
}

/// Wrapping key = HKDF-SHA256(ikm = prf32, salt = None, info = "caladon/passkey-wrapping/v1") →
/// 32 bytes. Deterministic in `prf32`.
pub fn passkey_derive_wrapping_key(prf32: &[u8]) -> Result<[u8; KEY_LEN], PasskeyError> {
    if prf32.len() != PRF_LEN {
        return Err(PasskeyError::BadPrfLength);
    }
    let hk = Hkdf::<Sha256>::new(None, prf32);
    let mut key = [0u8; KEY_LEN];
    hk.expand(WRAPPING_LABEL, &mut key)
        .expect("hkdf expand within output bound");
    Ok(key)
}

/// Seal (wrap) the 32-byte seed under the passkey-derived wrapping key. Random 24-byte nonce.
/// Returns `(nonce, ct)`.
pub fn wrap_seed(
    prf32: &[u8],
    seed: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), PasskeyError> {
    if seed.len() != SEED_LEN {
        return Err(PasskeyError::BadSeedLength);
    }
    let key = passkey_derive_wrapping_key(prf32)?;
    // Random-nonce seal via the envelope core (XChaCha20-Poly1305-IETF). We bind a fixed AAD.
    let (nonce, ct) = seal_random(&key, seed, SEED_WRAP_AAD)?;
    Ok((nonce, ct))
}

/// Deterministic-nonce wrap (parity/fixed-vector entry point).
pub fn wrap_seed_with_nonce(
    prf32: &[u8],
    seed: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    if seed.len() != SEED_LEN {
        return Err(PasskeyError::BadSeedLength);
    }
    let key = passkey_derive_wrapping_key(prf32)?;
    Ok(envelope::seal_raw(&key, seed, SEED_WRAP_AAD, nonce)?)
}

/// Open (unwrap) the sealed seed. Fails closed on a wrong passkey/PRF or a tampered blob.
pub fn unwrap_seed(
    prf32: &[u8],
    nonce: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    let key = passkey_derive_wrapping_key(prf32)?;
    envelope::open(&key, nonce, SEED_WRAP_AAD, ct).map_err(|_| PasskeyError::UnwrapFailed)
}

/// Random-nonce seal helper over the envelope AEAD core (mirrors `envelope::seal` but with a
/// caller-supplied raw AAD instead of account/purpose/v).
fn seal_random(
    key: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), PasskeyError> {
    use chacha20poly1305::aead::{AeadCore, OsRng};
    use chacha20poly1305::XChaCha20Poly1305;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = envelope::seal_raw(key, plaintext, ad, nonce.as_slice())?;
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce.as_slice());
    Ok((n, ct))
}
