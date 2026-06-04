//! `#[wasm_bindgen]` exports for the web client.
//!
//! - `verify_quote_sync`: the fail-closed attestation verdict. Collateral is FETCHED BY JS and
//!   passed in (no WASM networking). Returns the `Verdict` as a JS object (JSON).
//! - sealed-channel crypto: `derive_session_key`, `seal_wmk`/`open_wmk`, `seal_chat`/`open_chat`,
//!   `x25519_public`, `challenge_hex` — the web client's pre-send handshake + per-turn sealing.
//!
//! All byte arguments are `&[u8]` (JS `Uint8Array`); byte returns are `Vec<u8>` (`Uint8Array`).
//! Errors are returned as `JsError` (thrown in JS) so the web client fails closed on any tamper.

use wasm_bindgen::prelude::*;

use crate::attestation::{self, PinnedSet, Verdict};
use crate::{kdf, padding, passkey, seed_auth, seed_codec, session};

// ---------------------------------------------------------------------------------------------
// Attestation — the keystone verdict. Collateral is passed in (JS-fetched). No networking here.
// ---------------------------------------------------------------------------------------------

/// Verify a TDX quote, returning the `Verdict` as a JS value (`{ ok, reason, measurement_matched }`).
///
/// `pinned_json` is `{ "measurements": [...], "compose_hashes": [...], "workload_ids": [...] }`
/// (the client-shipped pin list; no TOFU). `collateral_json` is the PCS collateral JSON the JS
/// host fetched. `expected_challenge_hex` is lowercase-hex SHA-256(eph_pub) (the §4.6 client
/// binding); `expected_session_pub` is the RAW 32-byte CVM X25519 session pubkey (the JS host
/// base64-decodes `ev.session_pub`) — §4.6b checks report_data[32:64] == SHA-256(session_pub) so a
/// relay cannot substitute its own session key. Never throws on a verification FAILURE — it returns
/// a failing `Verdict` so the caller can branch on the specific reason; it only throws if
/// `pinned_json` is unparseable.
#[wasm_bindgen]
pub fn verify_quote_sync(
    quote_bytes: &[u8],
    collateral_json: &str,
    info_json: &str,
    now_secs: u64,
    expected_challenge_hex: &str,
    expected_session_pub: &[u8],
    pinned_json: &str,
) -> Result<JsValue, JsError> {
    let pinned = parse_pinned(pinned_json)?;
    let verdict: Verdict = attestation::verify_quote(
        quote_bytes,
        collateral_json,
        info_json,
        now_secs,
        expected_challenge_hex,
        expected_session_pub,
        &pinned,
    );
    serde_wasm_bindgen::to_value(&verdict).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(serde::Deserialize)]
struct PinnedJson {
    #[serde(default)]
    measurements: Vec<String>,
    #[serde(default)]
    compose_hashes: Vec<String>,
    #[serde(default)]
    workload_ids: Vec<String>,
}

fn parse_pinned(pinned_json: &str) -> Result<PinnedSet, JsError> {
    let p: PinnedJson =
        serde_json::from_str(pinned_json).map_err(|e| JsError::new(&format!("bad pinned set: {e}")))?;
    Ok(PinnedSet::new(
        p.measurements.into_iter().collect(),
        p.compose_hashes.into_iter().collect(),
        p.workload_ids.into_iter().collect(),
    ))
}

/// Lowercase-hex SHA-256(eph_pub) — the channel binding the verifier checks at §4.6.
#[wasm_bindgen]
pub fn challenge_hex(eph_pub: &[u8]) -> String {
    attestation::challenge_hex(eph_pub)
}

// ---------------------------------------------------------------------------------------------
// Identity — seed/passkey-derived root → account_id, WMK, and the seed-auth Authorization header.
// (The web client unwraps its seed via a passkey PRF, derives the root, then signs requests.)
// ---------------------------------------------------------------------------------------------

/// Argon2id(seed, salt) → 32-byte root. `memlimit_bytes` is libsodium-style bytes (m_cost = /1024).
/// Pass `SwiftyCrypto.{ops,mem}LimitProduction` equivalents (t=3, m=256MiB) in production.
#[wasm_bindgen]
pub fn argon2id(seed: &[u8], salt: &[u8], opslimit: u32, memlimit_bytes: u32) -> Result<Vec<u8>, JsError> {
    kdf::argon2id(seed, salt, opslimit, memlimit_bytes)
        .map(|r| r.to_vec())
        .map_err(|e| JsError::new(&format!("{e:?}")))
}

/// Zero-PII routing account_id (key-bound, B2-bis), from the root.
#[wasm_bindgen]
pub fn account_id(root: &[u8]) -> String {
    kdf::derive_account_id(root)
}

/// Raw Ed25519 public key (32 bytes) for gateway onboarding proof-of-possession (POST /v1/accounts):
/// the gateway checks the PoP signature + that account_id == key-bound(pub). Lets the web client
/// self-onboard a fresh identity (account_id alone is one-way, so the raw pub must be exported).
#[wasm_bindgen]
pub fn ed25519_public(root: &[u8]) -> Vec<u8> {
    kdf::derive_ed25519_public(root).to_vec()
}

/// The working-memory key (delivered into the CVM over the §6 session channel), from the root.
#[wasm_bindgen]
pub fn wmk(root: &[u8]) -> Vec<u8> {
    kdf::derive_wmk(root)
}

/// The device-local encrypted store key (32 bytes) for the client's SQLite/SQLCipher store
/// (history + RAG + FTS) — Batch-1 client foundation. Derived from the root; NEVER leaves the
/// device. Single source of truth (the native client uses the UniFFI export of the same kdf fn),
/// so the key is byte-identical and never re-implemented in JS/Swift (avoids an HKDF salt drift).
#[wasm_bindgen]
pub fn device_store_key(root: &[u8]) -> Vec<u8> {
    kdf::derive_device_store_key(root)
}

/// Build the `Authorization: Swifty acct=.. ts=.. sig=..` header for a request, signing with the
/// seed-derived Ed25519 key. Every signed gateway call uses this (the web client cannot reach the
/// gateway without it). Fails closed on a malformed account_id.
#[wasm_bindgen]
pub fn authorization_header(
    root: &[u8],
    account_id: &str,
    ts: i64,
    method: &str,
    path: &str,
) -> Result<String, JsError> {
    let ed_seed_vec = kdf::hkdf(root, kdf::GATEWAY_AUTH_LABEL, 32);
    let ed_seed: [u8; 32] = ed_seed_vec
        .try_into()
        .map_err(|_| JsError::new("derived ed25519 seed not 32 bytes"))?;
    seed_auth::authorization_header(&ed_seed, account_id, ts, method, path)
        .map_err(|e| JsError::new(&format!("{e:?}")))
}

// ---------------------------------------------------------------------------------------------
// Sealed channel — X25519 + HKDF session key, then XChaCha20-Poly1305 seal/open (purpose-bound).
// ---------------------------------------------------------------------------------------------

/// X25519 public key for a 32-byte private scalar (RFC 7748 clamped base-point multiply).
#[wasm_bindgen]
pub fn x25519_public(private_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    session::x25519_public(private_bytes)
        .map(|k| k.to_vec())
        .map_err(map_session_err)
}

/// SK = HKDF(X25519(my_private, their_public), info = label ‖ client_pub ‖ cvm_pub).
/// Fails closed on a low-order/identity peer key.
#[wasm_bindgen]
pub fn derive_session_key(
    my_private: &[u8],
    their_public: &[u8],
    client_pub: &[u8],
    cvm_pub: &[u8],
) -> Result<Vec<u8>, JsError> {
    session::derive_session_key(my_private, their_public, client_pub, cvm_pub)
        .map(|k| k.to_vec())
        .map_err(map_session_err)
}

/// Client seals the WMK to SK for delivery into the CVM (purpose "wmk-delivery"). Random nonce.
/// Returns `nonce ‖ ct` (24-byte nonce prefix) so JS handles one buffer.
#[wasm_bindgen]
pub fn seal_wmk(session_key: &[u8], wmk: &[u8], account_id: &str, v: i64) -> Result<Vec<u8>, JsError> {
    session::seal_wmk(session_key, wmk, account_id, v)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(map_session_err)
}

/// CVM opens a sealed WMK. `nonce_ct` is `nonce ‖ ct`. Fails closed on tamper.
#[wasm_bindgen]
pub fn open_wmk(session_key: &[u8], nonce_ct: &[u8], account_id: &str, v: i64) -> Result<Vec<u8>, JsError> {
    let (nonce, ct) = split_nonce(nonce_ct)?;
    session::open_wmk(session_key, nonce, ct, account_id, v).map_err(map_session_err)
}

/// Seal a live-turn payload (prompt / response delta) to SK (purpose "chat"). Random nonce.
/// Returns `nonce ‖ ct`.
#[wasm_bindgen]
pub fn seal_chat(session_key: &[u8], plaintext: &[u8], account_id: &str, v: i64) -> Result<Vec<u8>, JsError> {
    session::seal_chat(session_key, plaintext, account_id, v)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(map_session_err)
}

/// Open a sealed live-turn payload under SK. `nonce_ct` is `nonce ‖ ct`. Fails closed on tamper.
#[wasm_bindgen]
pub fn open_chat(session_key: &[u8], nonce_ct: &[u8], account_id: &str, v: i64) -> Result<Vec<u8>, JsError> {
    let (nonce, ct) = split_nonce(nonce_ct)?;
    session::open_chat(session_key, nonce, ct, account_id, v).map_err(map_session_err)
}

// ---------------------------------------------------------------------------------------------
// Passkey-PRF seed custody — derive a wrapping key from a WebAuthn PRF eval, then seal/open the
// 32-byte account seed under it (XChaCha20-Poly1305, domain-separated AAD). The PRF never persists.
// ---------------------------------------------------------------------------------------------

/// Wrapping key = HKDF-SHA256(ikm = prf32, info = "caladon/passkey-wrapping/v1") → 32 bytes.
/// Deterministic in `prf32`. Throws on a non-32-byte PRF.
#[wasm_bindgen]
pub fn passkey_derive_wrapping_key(prf32: &[u8]) -> Result<Vec<u8>, JsError> {
    passkey::passkey_derive_wrapping_key(prf32)
        .map(|k| k.to_vec())
        .map_err(map_passkey_err)
}

/// Seal (wrap) the 32-byte seed under the passkey-derived wrapping key. Random 24-byte nonce.
/// Returns `nonce ‖ ct` (24-byte nonce prefix) so JS handles one buffer.
#[wasm_bindgen]
pub fn passkey_wrap_seed(prf32: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
    passkey::wrap_seed(prf32, seed)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(map_passkey_err)
}

/// Open (unwrap) the sealed seed. `wrapped` is `nonce ‖ ct`. Fails closed (throws) on a wrong
/// passkey/PRF or a tampered blob.
#[wasm_bindgen]
pub fn passkey_unwrap_seed(prf32: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsError> {
    let (nonce, ct) = split_nonce(wrapped)?;
    passkey::unwrap_seed(prf32, nonce, ct).map_err(map_passkey_err)
}

// ---------------------------------------------------------------------------------------------
// Seed transcription codec — Mullvad-style Crockford base32 + 2-byte checksum, grouped in 4s.
// Sovereign/portable seed recovery (alongside passkey custody).
// ---------------------------------------------------------------------------------------------

/// Encode a 32-byte seed to the grouped Crockford-base32 + checksum recovery string.
#[wasm_bindgen]
pub fn seed_encode(seed: &[u8]) -> Result<String, JsError> {
    seed_codec::encode(seed).map_err(map_seed_err)
}

/// Decode a recovery string back to the 32-byte seed. Fails closed (throws) on a bad
/// checksum/length/character.
#[wasm_bindgen]
pub fn seed_decode(text: &str) -> Result<Vec<u8>, JsError> {
    seed_codec::decode(text).map_err(map_seed_err)
}

// ---------------------------------------------------------------------------------------------
// Metadata padding — the sealed-sender SIZE analog: `uint32_be(len) ‖ pt ‖ zero-fill` to a bucket.
// ---------------------------------------------------------------------------------------------

/// Pad to a fixed bucket so the wire length reveals only the bucket, not the exact plaintext size.
#[wasm_bindgen]
pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    padding::pad(plaintext).map_err(map_pad_err)
}

/// Recover the exact plaintext from a padded buffer. Fails closed (throws) on a malformed buffer.
#[wasm_bindgen]
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, JsError> {
    padding::unpad(padded).map_err(map_pad_err)
}

// --- helpers ---

fn map_passkey_err(e: passkey::PasskeyError) -> JsError {
    JsError::new(&format!("{e:?}"))
}

fn map_seed_err(e: seed_codec::SeedError) -> JsError {
    JsError::new(&format!("{e:?}"))
}

fn map_pad_err(e: padding::PadError) -> JsError {
    JsError::new(&format!("{e:?}"))
}

fn concat_nonce(nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

fn split_nonce(nonce_ct: &[u8]) -> Result<(&[u8], &[u8]), JsError> {
    if nonce_ct.len() < crate::envelope::NONCE_LEN {
        return Err(JsError::new("sealed payload shorter than the nonce"));
    }
    Ok(nonce_ct.split_at(crate::envelope::NONCE_LEN))
}

fn map_session_err(e: session::SessionError) -> JsError {
    JsError::new(&format!("{e:?}"))
}
