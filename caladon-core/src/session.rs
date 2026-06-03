//! Confidential session channel — WMK delivery into the CVM (identity-envelope.md §6).
//! Byte-identical to `swifty_crypto/session.py` and `SwiftyKit/Session.swift`; all three derive
//! the SAME session key so client and CVM agree (X25519 / RFC 7748 + HKDF-SHA256).
//!
//! The working-memory key (WMK) is the one user-held key that ever enters a remote machine, and
//! only over a session key `SK` bound to the verified attestation. `SK = HKDF(X25519(·),
//! info = "swifty/session/v1" ‖ client_pub ‖ cvm_pub)` — binding BOTH endpoints' public keys
//! into the KDF info defeats unknown-key-share / a MITM key substitution.
//!
//! CRITICAL: x25519-dalek does NOT raise on a low-order/identity peer key (the resulting shared
//! secret is all-zero); Python's `cryptography` DOES (`exchange()` raises), and Swift mirrors it.
//! We must reject explicitly here (fail-closed) or a substituted low-order key yields an
//! attacker-determined SK with no ECDH entropy.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::envelope::{self, EnvelopeError};

pub const SESSION_LABEL: &[u8] = b"swifty/session/v1";
pub const WMK_DELIVERY_PURPOSE: &str = "wmk-delivery";
pub const CHAT_PURPOSE: &str = "chat";
pub const KEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    BadPublicKeyLength,
    BadPrivateKeyLength,
    /// Peer key was low-order/identity (all-zero shared secret) — fail closed.
    LowOrderPoint,
    Envelope(EnvelopeError),
}

impl From<EnvelopeError> for SessionError {
    fn from(e: EnvelopeError) -> Self {
        SessionError::Envelope(e)
    }
}

/// X25519 public key (32 bytes) for an ephemeral/long-term private scalar. The scalar is clamped
/// during the base-point multiply (RFC 7748), matching CryptoKit + `cryptography`.
pub fn x25519_public(private_bytes: &[u8]) -> Result<[u8; 32], SessionError> {
    let priv_arr: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| SessionError::BadPrivateKeyLength)?;
    let secret = StaticSecret::from(priv_arr);
    Ok(PublicKey::from(&secret).to_bytes())
}

/// SK = HKDF(X25519(my_private, their_public), info = label ‖ client_pub ‖ cvm_pub).
/// Both sides pass the SAME client_pub/cvm_pub (the channel identities) and their own private +
/// the peer's public; the ECDH is symmetric so they agree on SK.
///
/// HKDF here is salt=None (RFC-5869 all-zero salt), matching Python's `HKDF(salt=None)` and
/// Swift's `hkdfDerivedSymmetricKey(salt: Data())`.
pub fn derive_session_key(
    my_private: &[u8],
    their_public: &[u8],
    client_pub: &[u8],
    cvm_pub: &[u8],
) -> Result<[u8; KEY_LEN], SessionError> {
    if client_pub.len() != KEY_LEN || cvm_pub.len() != KEY_LEN {
        return Err(SessionError::BadPublicKeyLength);
    }
    let priv_arr: [u8; 32] = my_private
        .try_into()
        .map_err(|_| SessionError::BadPrivateKeyLength)?;
    let pub_arr: [u8; 32] = their_public
        .try_into()
        .map_err(|_| SessionError::BadPublicKeyLength)?;

    let secret = StaticSecret::from(priv_arr);
    let peer = PublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&peer);

    // Reject a low-order/identity peer point. `was_contributory()` is false exactly when the
    // shared secret is the all-zero point; we also check the bytes directly as belt-and-braces.
    if !shared.was_contributory() || shared.as_bytes() == &[0u8; 32] {
        return Err(SessionError::LowOrderPoint);
    }

    let info: Vec<u8> = [SESSION_LABEL, client_pub, cvm_pub].concat();
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut sk = [0u8; KEY_LEN];
    hk.expand(&info, &mut sk)
        .expect("hkdf expand within output bound");
    Ok(sk)
}

/// Client seals WMK to the session key for delivery into the CVM (§6). Deterministic-nonce
/// parity entry point; production should use `seal_wmk` (random nonce).
pub fn seal_wmk_with_nonce(
    session_key: &[u8],
    wmk: &[u8],
    account_id: &str,
    v: i64,
    nonce: &[u8],
) -> Result<Vec<u8>, SessionError> {
    Ok(envelope::seal_with_nonce(
        session_key,
        wmk,
        account_id,
        WMK_DELIVERY_PURPOSE,
        v,
        nonce,
    )?)
}

/// Client seals WMK to the session key (random nonce, production path). Returns `(nonce, ct)`.
pub fn seal_wmk(
    session_key: &[u8],
    wmk: &[u8],
    account_id: &str,
    v: i64,
) -> Result<([u8; envelope::NONCE_LEN], Vec<u8>), SessionError> {
    Ok(envelope::seal(
        session_key,
        wmk,
        account_id,
        WMK_DELIVERY_PURPOSE,
        v,
    )?)
}

/// CVM opens the sealed WMK (in TEE RAM). Fails closed on any tamper / wrong session.
pub fn open_wmk(
    session_key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    account_id: &str,
    v: i64,
) -> Result<Vec<u8>, SessionError> {
    Ok(envelope::open_bound(
        session_key,
        nonce,
        ct,
        account_id,
        WMK_DELIVERY_PURPOSE,
        v,
    )?)
}

/// Seal a live-turn payload (prompt or response delta) to SK (purpose "chat").
pub fn seal_chat_with_nonce(
    session_key: &[u8],
    plaintext: &[u8],
    account_id: &str,
    v: i64,
    nonce: &[u8],
) -> Result<Vec<u8>, SessionError> {
    Ok(envelope::seal_with_nonce(
        session_key,
        plaintext,
        account_id,
        CHAT_PURPOSE,
        v,
        nonce,
    )?)
}

/// Random-nonce chat seal (production path). Returns `(nonce, ct)`.
pub fn seal_chat(
    session_key: &[u8],
    plaintext: &[u8],
    account_id: &str,
    v: i64,
) -> Result<([u8; envelope::NONCE_LEN], Vec<u8>), SessionError> {
    Ok(envelope::seal(session_key, plaintext, account_id, CHAT_PURPOSE, v)?)
}

/// Open a sealed live-turn payload under SK. Fails closed on tamper.
pub fn open_chat(
    session_key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    account_id: &str,
    v: i64,
) -> Result<Vec<u8>, SessionError> {
    Ok(envelope::open_bound(
        session_key,
        nonce,
        ct,
        account_id,
        CHAT_PURPOSE,
        v,
    )?)
}
