//! Client side of the gateway's seed-signature auth (contracts/gateway-api.md §1).
//! Byte-identical to `gateway/app/seed_auth.py` (canonical/verify) and `SwiftyKit/SeedAuth.swift`
//! (canonical/authorizationHeader). The Ed25519 signing key is derived from the seed root via
//! `kdf::derive_ed25519_*`; the canonical string + the `Authorization: Swifty acct=.. ts=.. sig=..`
//! format MUST byte-match the server or it 401s.
//!
//! Ed25519 (RFC 8032) signing is deterministic, so a given (key, message) yields the same
//! signature in ed25519-dalek, Python `cryptography`, and CryptoKit.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Accept timestamps within ±window of now (anti-replay). Contract §1 says ±120s.
pub const FRESHNESS_WINDOW_S: i64 = 120;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedAuthError {
    InvalidAccountId,
    MalformedHeader,
    StaleTimestamp,
    InvalidSignature,
}

/// account_id format the gateway accepts (gateway/app/ids.py): url-safe, 16-128 chars.
pub fn is_valid_account_id(id: &str) -> bool {
    let len = id.chars().count();
    if len < 16 || len > 128 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The exact bytes the client signs and the gateway verifies. Newline-delimited; method
/// upper-cased; `path` is the raw URI path (no query string, no trailing-slash normalisation).
pub fn canonical(account_id: &str, ts: i64, method: &str, path: &str) -> Vec<u8> {
    format!("{account_id}\n{ts}\n{}\n{path}", method.to_uppercase()).into_bytes()
}

/// Sign the canonical message with a 32-byte Ed25519 seed (the private scalar from
/// `kdf::derive_ed25519_*`). Returns the 64-byte signature.
pub fn sign(ed25519_seed: &[u8; 32], account_id: &str, ts: i64, method: &str, path: &str) -> [u8; 64] {
    let sk = SigningKey::from_bytes(ed25519_seed);
    let msg = canonical(account_id, ts, method, path);
    sk.sign(&msg).to_bytes()
}

/// Build the `Authorization` header value for a request: `Swifty acct=.. ts=.. sig=..` where
/// `sig` is the STANDARD (with-padding) base64 of the 64-byte Ed25519 signature — exactly the
/// Swift `signature.base64EncodedString()` / the gateway's `base64.b64decode(validate=True)`.
pub fn authorization_header(
    ed25519_seed: &[u8; 32],
    account_id: &str,
    ts: i64,
    method: &str,
    path: &str,
) -> Result<String, SeedAuthError> {
    if !is_valid_account_id(account_id) {
        return Err(SeedAuthError::InvalidAccountId);
    }
    let sig = sign(ed25519_seed, account_id, ts, method, path);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    Ok(format!("Swifty acct={account_id} ts={ts} sig={sig_b64}"))
}

/// Parsed `Authorization: Swifty acct=.. ts=.. sig=..`.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub account_id: String,
    pub ts: i64,
    pub sig: Vec<u8>,
}

/// Parse the header (gateway-side). Mirrors `seed_auth.parse_auth_header`.
pub fn parse_auth_header(value: &str) -> Result<AuthRequest, SeedAuthError> {
    let rest = value
        .strip_prefix("Swifty ")
        .ok_or(SeedAuthError::MalformedHeader)?;
    let mut account_id: Option<String> = None;
    let mut ts: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    for part in rest.split_whitespace() {
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "acct" => account_id = Some(v.to_string()),
                "ts" => ts = v.parse::<i64>().ok(),
                "sig" => {
                    sig = base64::engine::general_purpose::STANDARD.decode(v).ok();
                }
                _ => {}
            }
        }
    }
    let account_id = account_id.ok_or(SeedAuthError::MalformedHeader)?;
    let ts = ts.ok_or(SeedAuthError::MalformedHeader)?;
    let sig = sig.ok_or(SeedAuthError::MalformedHeader)?;
    if account_id.is_empty() || sig.is_empty() {
        return Err(SeedAuthError::MalformedHeader);
    }
    if !is_valid_account_id(&account_id) {
        return Err(SeedAuthError::InvalidAccountId);
    }
    Ok(AuthRequest { account_id, ts, sig })
}

/// Verify freshness + Ed25519 signature against the registered 32-byte public key. Mirrors
/// `seed_auth.verify`: stale/future timestamp or bad signature → error.
pub fn verify(
    pubkey_raw: &[u8; 32],
    req: &AuthRequest,
    method: &str,
    path: &str,
    now: i64,
) -> Result<(), SeedAuthError> {
    if (now - req.ts).abs() > FRESHNESS_WINDOW_S {
        return Err(SeedAuthError::StaleTimestamp);
    }
    let vk = VerifyingKey::from_bytes(pubkey_raw).map_err(|_| SeedAuthError::InvalidSignature)?;
    let sig_arr: [u8; 64] = req
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| SeedAuthError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    let msg = canonical(&req.account_id, req.ts, method, path);
    vk.verify(&msg, &signature)
        .map_err(|_| SeedAuthError::InvalidSignature)
}
