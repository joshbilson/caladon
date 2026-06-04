//! UniFFI bindings (native Swift xcframework) — PROC-MACRO mode.
//!
//! TOOLCHAIN NOTE (R2/P3): UniFFI's UDL `udl_derive` codegen is BROKEN on rustc 1.96 (the
//! installed toolchain) — `udl_derive(Enum)`/`udl_derive(Record)` expand to code rustc 1.96
//! rejects ("associated type <Variant> not found for Self"), reproduced with a 3-line minimal
//! crate on uniffi 0.28 AND 0.29. Proc-macro mode (`#[derive(uniffi::Record/Enum/Error)]` +
//! `#[uniffi::export]` + `setup_scaffolding!`) compiles cleanly on the same toolchain, so the
//! scaffolding here uses proc-macro mode. `src/caladon_core.udl` is retained as the authoritative
//! interface contract (and the shape these types/functions mirror exactly), ready for UDL-mode
//! bindgen once uniffi/rustc reconcile. See internal spike notes.
//!
//! This surface mirrors `SwiftyKit/Attestation.swift` (Verdict / VerdictReason). Collateral is
//! fetched by the caller (matching `DcapVerifier.swift`, which fetches PCS collateral and passes
//! it in) and handed to the offline, deterministic `verify_quote`.

use crate::attestation::{self, verdict};
use crate::{padding, passkey, seed_codec, session};

/// The A7 failure→code table (attestation-evidence.md §1). Mirrors the Swift `VerdictReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VerdictReason {
    Ok,
    QuoteSigInvalid,
    TcbOutOfDate,
    CollateralStale,
    MeasurementUnpinned,
    ComposeMismatch,
    AppIdMismatch,
    BindingMismatch,
    NoLogAbsent,
    RegimeUnsupported,
}

impl From<verdict::VerdictReason> for VerdictReason {
    fn from(r: verdict::VerdictReason) -> Self {
        match r {
            verdict::VerdictReason::Ok => VerdictReason::Ok,
            verdict::VerdictReason::QuoteSigInvalid => VerdictReason::QuoteSigInvalid,
            verdict::VerdictReason::TcbOutOfDate => VerdictReason::TcbOutOfDate,
            verdict::VerdictReason::CollateralStale => VerdictReason::CollateralStale,
            verdict::VerdictReason::MeasurementUnpinned => VerdictReason::MeasurementUnpinned,
            verdict::VerdictReason::ComposeMismatch => VerdictReason::ComposeMismatch,
            verdict::VerdictReason::AppIdMismatch => VerdictReason::AppIdMismatch,
            verdict::VerdictReason::BindingMismatch => VerdictReason::BindingMismatch,
            verdict::VerdictReason::NoLogAbsent => VerdictReason::NoLogAbsent,
            verdict::VerdictReason::RegimeUnsupported => VerdictReason::RegimeUnsupported,
        }
    }
}

/// The fail-closed verdict (mirrors the Swift `Verdict` + the `measurement_matched` diagnostic).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Verdict {
    pub ok: bool,
    pub reason: VerdictReason,
    pub measurement_matched: bool,
}

impl From<verdict::Verdict> for Verdict {
    fn from(v: verdict::Verdict) -> Self {
        Verdict {
            ok: v.ok,
            reason: v.reason.into(),
            measurement_matched: v.measurement_matched,
        }
    }
}

/// The client-shipped pinned set (no TOFU). `measurements` = hex(mr_td‖rtmr0‖rtmr1‖rtmr2).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PinnedSet {
    pub measurements: Vec<String>,
    pub compose_hashes: Vec<String>,
    pub workload_ids: Vec<String>,
}

impl PinnedSet {
    fn into_internal(self) -> verdict::PinnedSet {
        verdict::PinnedSet::new(
            self.measurements.into_iter().collect(),
            self.compose_hashes.into_iter().collect(),
            self.workload_ids.into_iter().collect(),
        )
    }
}

/// Sealed-channel error (mirrors the UDL `SealError`).
#[derive(Debug, uniffi::Error)]
pub enum SealError {
    BadKey,
    BadNonce,
    LowOrderPoint,
    OpenFailed,
    SealFailed,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SealError {}

impl From<session::SessionError> for SealError {
    fn from(e: session::SessionError) -> Self {
        use crate::envelope::EnvelopeError;
        match e {
            session::SessionError::BadPublicKeyLength => SealError::BadKey,
            session::SessionError::BadPrivateKeyLength => SealError::BadKey,
            session::SessionError::LowOrderPoint => SealError::LowOrderPoint,
            session::SessionError::Envelope(EnvelopeError::BadKeyLength) => SealError::BadKey,
            session::SessionError::Envelope(EnvelopeError::BadNonceLength) => SealError::BadNonce,
            session::SessionError::Envelope(EnvelopeError::OpenFailed) => SealError::OpenFailed,
            session::SessionError::Envelope(EnvelopeError::SealFailed) => SealError::SealFailed,
        }
    }
}

/// Passkey-PRF seed-custody error (mirrors the UDL `PasskeyError`).
#[derive(Debug, uniffi::Error)]
pub enum PasskeyError {
    BadPrfLength,
    BadSeedLength,
    /// Unwrap failed — wrong passkey/PRF, or a tampered blob. Fail closed.
    UnwrapFailed,
    Envelope,
}

impl core::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PasskeyError {}

impl From<passkey::PasskeyError> for PasskeyError {
    fn from(e: passkey::PasskeyError) -> Self {
        match e {
            passkey::PasskeyError::BadPrfLength => PasskeyError::BadPrfLength,
            passkey::PasskeyError::BadSeedLength => PasskeyError::BadSeedLength,
            passkey::PasskeyError::UnwrapFailed => PasskeyError::UnwrapFailed,
            passkey::PasskeyError::Envelope(_) => PasskeyError::Envelope,
        }
    }
}

/// Seed-codec error (mirrors the UDL `SeedError`).
#[derive(Debug, uniffi::Error)]
pub enum SeedError {
    BadLength,
    BadChecksum,
    BadCharacter,
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SeedError {}

impl From<seed_codec::SeedError> for SeedError {
    fn from(e: seed_codec::SeedError) -> Self {
        match e {
            seed_codec::SeedError::BadLength => SeedError::BadLength,
            seed_codec::SeedError::BadChecksum => SeedError::BadChecksum,
            seed_codec::SeedError::BadCharacter => SeedError::BadCharacter,
        }
    }
}

/// Metadata-padding error (mirrors the UDL `PadError`).
#[derive(Debug, uniffi::Error)]
pub enum PadError {
    TooLong,
    TooShort,
    DeclaredLenExceedsBuffer,
}

impl core::fmt::Display for PadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PadError {}

impl From<padding::PadError> for PadError {
    fn from(e: padding::PadError) -> Self {
        match e {
            padding::PadError::TooLong => PadError::TooLong,
            padding::PadError::TooShort => PadError::TooShort,
            padding::PadError::DeclaredLenExceedsBuffer => PadError::DeclaredLenExceedsBuffer,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Exported namespace functions.
// ---------------------------------------------------------------------------------------------

/// Lowercase-hex SHA-256(eph_pub) — the channel binding placed in report_data[0:32].
#[uniffi::export]
pub fn challenge_hex(eph_pub: Vec<u8>) -> String {
    attestation::challenge_hex(&eph_pub)
}

/// Fail-closed verification with collateral PASSED IN (offline/deterministic — the Swift
/// `DcapVerifier` fetches PCS collateral and hands it here). Never throws on a verification
/// FAILURE: returns a `Verdict` with `ok=false` and the specific reason.
/// `expected_challenge_hex` is lowercase-hex SHA-256(eph_pub) (the §4.6 client binding);
/// `expected_session_pub` is the RAW 32-byte CVM X25519 session pubkey (the caller base64-decodes
/// `ev.session_pub`) — §4.6b checks report_data[32:64] == SHA-256(session_pub) so a relay cannot
/// substitute its own session key and MITM the sealed channel.
#[uniffi::export]
pub fn verify_quote(
    quote_bytes: Vec<u8>,
    collateral_json: String,
    info_json: String,
    now_secs: u64,
    expected_challenge_hex: String,
    expected_session_pub: Vec<u8>,
    pinned: PinnedSet,
) -> Verdict {
    attestation::verify_quote(
        &quote_bytes,
        &collateral_json,
        &info_json,
        now_secs,
        &expected_challenge_hex,
        &expected_session_pub,
        &pinned.into_internal(),
    )
    .into()
}

/// X25519 public key for a 32-byte private scalar.
#[uniffi::export]
pub fn x25519_public(private_bytes: Vec<u8>) -> Result<Vec<u8>, SealError> {
    session::x25519_public(&private_bytes)
        .map(|k| k.to_vec())
        .map_err(Into::into)
}

/// SK = HKDF(X25519(my_private, their_public), info = label ‖ client_pub ‖ cvm_pub).
#[uniffi::export]
pub fn derive_session_key(
    my_private: Vec<u8>,
    their_public: Vec<u8>,
    client_pub: Vec<u8>,
    cvm_pub: Vec<u8>,
) -> Result<Vec<u8>, SealError> {
    session::derive_session_key(&my_private, &their_public, &client_pub, &cvm_pub)
        .map(|k| k.to_vec())
        .map_err(Into::into)
}

/// Seal the WMK to SK for CVM delivery. Returns `nonce ‖ ct`.
#[uniffi::export]
pub fn seal_wmk(session_key: Vec<u8>, wmk: Vec<u8>, account_id: String, v: i64) -> Result<Vec<u8>, SealError> {
    session::seal_wmk(&session_key, &wmk, &account_id, v)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(Into::into)
}

/// Open a sealed WMK (`nonce ‖ ct`). Fails closed on tamper.
#[uniffi::export]
pub fn open_wmk(session_key: Vec<u8>, nonce_ct: Vec<u8>, account_id: String, v: i64) -> Result<Vec<u8>, SealError> {
    let (nonce, ct) = split_nonce(&nonce_ct)?;
    session::open_wmk(&session_key, nonce, ct, &account_id, v).map_err(Into::into)
}

/// Seal a live-turn payload to SK (purpose "chat"). Returns `nonce ‖ ct`.
#[uniffi::export]
pub fn seal_chat(session_key: Vec<u8>, plaintext: Vec<u8>, account_id: String, v: i64) -> Result<Vec<u8>, SealError> {
    session::seal_chat(&session_key, &plaintext, &account_id, v)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(Into::into)
}

/// Open a sealed live-turn payload (`nonce ‖ ct`). Fails closed on tamper.
#[uniffi::export]
pub fn open_chat(session_key: Vec<u8>, nonce_ct: Vec<u8>, account_id: String, v: i64) -> Result<Vec<u8>, SealError> {
    let (nonce, ct) = split_nonce(&nonce_ct)?;
    session::open_chat(&session_key, nonce, ct, &account_id, v).map_err(Into::into)
}

// --- passkey-PRF seed custody ---

/// Wrapping key = HKDF-SHA256(ikm = prf32, info = "caladon/passkey-wrapping/v1") → 32 bytes.
/// Deterministic in `prf32`. Fails closed on a non-32-byte PRF.
#[uniffi::export]
pub fn passkey_derive_wrapping_key(prf32: Vec<u8>) -> Result<Vec<u8>, PasskeyError> {
    passkey::passkey_derive_wrapping_key(&prf32)
        .map(|k| k.to_vec())
        .map_err(Into::into)
}

/// Seal (wrap) the 32-byte seed under the passkey-derived wrapping key. Random 24-byte nonce.
/// Returns `nonce ‖ ct`.
#[uniffi::export]
pub fn passkey_wrap_seed(prf32: Vec<u8>, seed: Vec<u8>) -> Result<Vec<u8>, PasskeyError> {
    passkey::wrap_seed(&prf32, &seed)
        .map(|(n, ct)| concat_nonce(&n, &ct))
        .map_err(Into::into)
}

/// Open (unwrap) the sealed seed (`wrapped` = `nonce ‖ ct`). Fails closed on a wrong passkey/PRF
/// or a tampered blob.
#[uniffi::export]
pub fn passkey_unwrap_seed(prf32: Vec<u8>, wrapped: Vec<u8>) -> Result<Vec<u8>, PasskeyError> {
    let (nonce, ct) = split_nonce_passkey(&wrapped)?;
    passkey::unwrap_seed(&prf32, nonce, ct).map_err(Into::into)
}

// --- seed transcription codec ---

/// Encode a 32-byte seed to the grouped Crockford-base32 + checksum recovery string.
#[uniffi::export]
pub fn seed_encode(seed: Vec<u8>) -> Result<String, SeedError> {
    seed_codec::encode(&seed).map_err(Into::into)
}

/// Decode a recovery string back to the 32-byte seed. Fails closed on a bad
/// checksum/length/character.
#[uniffi::export]
pub fn seed_decode(text: String) -> Result<Vec<u8>, SeedError> {
    seed_codec::decode(&text).map_err(Into::into)
}

// --- metadata padding ---

/// Pad to a fixed bucket so the wire length reveals only the bucket, not the exact plaintext size.
#[uniffi::export]
pub fn pad(plaintext: Vec<u8>) -> Result<Vec<u8>, PadError> {
    padding::pad(&plaintext).map_err(Into::into)
}

/// Recover the exact plaintext from a padded buffer. Fails closed on a malformed buffer.
#[uniffi::export]
pub fn unpad(padded: Vec<u8>) -> Result<Vec<u8>, PadError> {
    padding::unpad(&padded).map_err(Into::into)
}

fn concat_nonce(nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

fn split_nonce_passkey(nonce_ct: &[u8]) -> Result<(&[u8], &[u8]), PasskeyError> {
    if nonce_ct.len() < crate::envelope::NONCE_LEN {
        return Err(PasskeyError::UnwrapFailed);
    }
    Ok(nonce_ct.split_at(crate::envelope::NONCE_LEN))
}

fn split_nonce(nonce_ct: &[u8]) -> Result<(&[u8], &[u8]), SealError> {
    if nonce_ct.len() < crate::envelope::NONCE_LEN {
        return Err(SealError::BadNonce);
    }
    Ok(nonce_ct.split_at(crate::envelope::NONCE_LEN))
}
