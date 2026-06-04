//! Seed → key derivation (contracts/identity-envelope.md §3). Byte-identical to
//! `swifty_crypto/kdf.py` (the reference). See internal spike notes for the invariants.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const ROOT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
const MIN_SECRET_LEN: usize = 16;

// libsodium SALTBYTES — the salt is hashed down to exactly 16 bytes.
const SALTBYTES: usize = 16;

// §10 production Argon2id baseline (memlimit BYTES, opslimit). The 64 MiB default is reference/test.
pub const ARGON2ID_MEMLIMIT_PRODUCTION: u32 = 256 * 1024 * 1024;
pub const ARGON2ID_OPSLIMIT_PRODUCTION: u32 = 3;

// CC-2: conservative FLOOR on the caller-supplied work factors so a caller can never silently
// weaken the seed→root KDF below the established libsodium "moderate" baseline. These match the
// reference/test minimum exactly (opslimit=3, memlimit=64 MiB), so all parity vectors stay green;
// they only reject params *weaker* than the baseline. Production should use the *_PRODUCTION
// values above; this is the hard lower bound, not the recommendation.
pub const ARGON2ID_OPSLIMIT_FLOOR: u32 = 3;
pub const ARGON2ID_MEMLIMIT_FLOOR: u32 = 64 * 1024 * 1024;

// HKDF domain-separation labels (§3) — must match kdf.py exactly.
pub const WMK_LABEL: &str = "swifty/working-mem/v1";
pub const TRANSCRIPT_LABEL: &str = "swifty/transcript/v1";
pub const GATEWAY_AUTH_LABEL: &str = "swifty/gateway-auth/v1";
pub const CODING_LABEL: &str = "swifty/coding/v1";
/// Device-local encrypted store (SQLite/SQLCipher `PRAGMA key`) — Batch-1 client store. New label
/// (no existing derivations), so it uses the forward `caladon/` brand. NEVER leaves the device.
pub const DEVICE_STORE_LABEL: &str = "caladon/device-store/v1";

const ACCOUNT_ID_DOMAIN: &[u8] = b"swifty/account/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum KdfError {
    SeedTooShort,
    BadParams,
    Argon2Failed,
    /// CC-2: opslimit/memlimit below the conservative floor (would weaken seed→root KDF).
    WeakParams,
}

/// seed → root (§3). The `salt` is a FIXED app-domain constant (e.g. b"swifty/v1"); it is
/// SHA-256'd to the 16-byte libsodium salt. `memlimit` is in BYTES (libsodium convention);
/// Argon2's m_cost is KiB, so m_cost = memlimit / 1024.
///
/// CRITICAL (R1, byte-parity vs libsodium `crypto_pwhash` Argon2id): the salt is
/// `sha256(salt)[..16]` (NOT the raw salt), the algorithm is Argon2id **v1.3**, lanes p = 1, and
/// `t_cost = opslimit`, `m_cost = memlimit/1024` KiB. Changing any of these breaks interop.
pub fn argon2id(seed: &[u8], salt: &[u8], opslimit: u32, memlimit_bytes: u32) -> Result<[u8; ROOT_LEN], KdfError> {
    if seed.len() < MIN_SECRET_LEN {
        return Err(KdfError::SeedTooShort);
    }
    // CC-2: fail closed on params weaker than the moderate baseline so the seed→root KDF can't be
    // silently downgraded. The floor equals the reference/test minimum, so parity vectors are
    // unaffected; only sub-baseline params are rejected.
    if opslimit < ARGON2ID_OPSLIMIT_FLOOR || memlimit_bytes < ARGON2ID_MEMLIMIT_FLOOR {
        return Err(KdfError::WeakParams);
    }
    let salt16 = &Sha256::digest(salt)[..SALTBYTES];
    let m_cost_kib = memlimit_bytes / 1024;
    let params = Params::new(m_cost_kib, opslimit, 1, Some(ROOT_LEN)).map_err(|_| KdfError::BadParams)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ROOT_LEN];
    a2.hash_password_into(seed, salt16, &mut out).map_err(|_| KdfError::Argon2Failed)?;
    Ok(out)
}

/// root + domain-separation label → sub-key (§3). HKDF-SHA256 with salt=None (RFC-5869 zero salt,
/// matching Python `cryptography`'s `HKDF(salt=None)`), info = the UTF-8 label.
pub fn hkdf(root: &[u8], label: &str, length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut okm = vec![0u8; length];
    hk.expand(label.as_bytes(), &mut okm).expect("hkdf expand within output bound");
    okm
}

pub fn derive_wmk(root: &[u8]) -> Vec<u8> {
    hkdf(root, WMK_LABEL, KEY_LEN)
}

pub fn derive_transcript_root(root: &[u8]) -> Vec<u8> {
    hkdf(root, TRANSCRIPT_LABEL, KEY_LEN)
}

/// The device-local store key (32 bytes) for the client's encrypted SQLite store (history + RAG +
/// FTS search). Single source of truth — both the WASM (web) and UniFFI (native) clients call this
/// so the key is byte-identical and never re-implemented in JS/Swift. Stays on the device.
pub fn derive_device_store_key(root: &[u8]) -> Vec<u8> {
    hkdf(root, DEVICE_STORE_LABEL, KEY_LEN)
}

/// The Ed25519 *public* key (32 bytes) for gateway seed-auth, derived from the root.
///
/// CC-3: the transient Ed25519 private seed (`sk_seed`/`seed`) is a secret; only the *public*
/// key leaves this function. We wipe those buffers before returning. (`SigningKey` itself is
/// `ZeroizeOnDrop` in ed25519-dalek, so `sk` clears on scope exit.)
pub fn derive_ed25519_public(root: &[u8]) -> [u8; 32] {
    let mut sk_seed = hkdf(root, GATEWAY_AUTH_LABEL, 32);
    let mut seed: [u8; 32] = sk_seed.as_slice().try_into().expect("hkdf returns 32 bytes");
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = sk.verifying_key().to_bytes();
    seed.zeroize();
    sk_seed.zeroize();
    pubkey
}

/// Zero-PII routing id, BOUND to the seed-derived Ed25519 key (B2-bis). Takes only the root.
/// `urlsafe_b64_nopad(sha256(b"swifty/account/v1" ‖ ed25519_pub))`.
pub fn derive_account_id(root: &[u8]) -> String {
    let pubkey = derive_ed25519_public(root);
    let mut h = Sha256::new();
    h.update(ACCOUNT_ID_DOMAIN);
    h.update(pubkey);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}
