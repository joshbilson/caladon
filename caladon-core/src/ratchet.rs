//! Forward-secret transcript ratchet (identity-envelope.md §5.1; amendment B5). Byte-identical
//! to `swifty_crypto/ratchet.py` (the reference).
//!
//! A libsignal-style symmetric KDF chain held CLIENT-SIDE. Each `advance()` derives the next
//! entry's message key and replaces the chain key with its successor, discarding the prior chain
//! key — so a compromise of the *current* state cannot recover PAST message keys (forward secrecy
//! vs device-at-rest / server compromise). Reading old entries on a NEW device (restored from the
//! same seed) replays from `transcript_root` via `message_key_at` (O(step)).
//!
//! All keys are `kdf::hkdf(chain_key, label)` (HKDF-SHA256, salt=None, 32-byte output) — the same
//! primitive as the rest of the key tree, so parity follows from kdf parity.

use crate::kdf::hkdf;

const MSG_LABEL: &str = "swifty/transcript/msg/v1";
const CHAIN_LABEL: &str = "swifty/transcript/chain/v1";
const DEVICE_LABEL: &str = "swifty/transcript/device/v1"; // per-device sub-ratchet seed (MD1)
const KID_PREFIX: &str = "t"; // transcript-entry kid: "t{step}" or "t{device_id}:{step}"
const KEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    BadDeviceId,
    NegativeStep,
    BadKid,
}

/// ':' is the kid separator; '/' is the HKDF-label separator — both would break parsing / domain
/// separation, so reject them (matches `_validate_device_id`).
fn validate_device_id(device_id: &str) -> Result<(), RatchetError> {
    if device_id.is_empty() || device_id.contains(':') || device_id.contains('/') {
        return Err(RatchetError::BadDeviceId);
    }
    Ok(())
}

/// Per-device transcript chain seed (multi-device FS ratchet, MD1 / Sesame-style). Each device
/// derives an INDEPENDENT chain from the shared `transcript_root` + its `device_id`.
pub fn device_transcript_root(
    transcript_root: &[u8],
    device_id: &str,
) -> Result<Vec<u8>, RatchetError> {
    validate_device_id(device_id)?;
    let label = format!("{DEVICE_LABEL}/{device_id}");
    Ok(hkdf(transcript_root, &label, KEY_LEN))
}

/// Encode a transcript step (+ optional device) into the envelope `kid`. Single-device:
/// "t{step}"; multi-device: "t{device_id}:{step}".
pub fn transcript_kid(step: i64, device_id: Option<&str>) -> Result<String, RatchetError> {
    if step < 0 {
        return Err(RatchetError::NegativeStep);
    }
    match device_id {
        None => Ok(format!("{KID_PREFIX}{step}")),
        Some(d) => {
            validate_device_id(d)?;
            Ok(format!("{KID_PREFIX}{d}:{step}"))
        }
    }
}

/// Inverse of `transcript_kid` → (device_id|None, step). Errors on a non-kid.
pub fn parse_transcript_kid(kid: &str) -> Result<(Option<String>, i64), RatchetError> {
    let body = kid.strip_prefix(KID_PREFIX).ok_or(RatchetError::BadKid)?;
    if let Some(idx) = body.rfind(':') {
        let (device_id, step_str) = (&body[..idx], &body[idx + 1..]);
        if device_id.is_empty() {
            return Err(RatchetError::BadKid);
        }
        let step = step_str.parse::<i64>().map_err(|_| RatchetError::BadKid)?;
        Ok((Some(device_id.to_string()), step))
    } else {
        let step = body.parse::<i64>().map_err(|_| RatchetError::BadKid)?;
        Ok((None, step))
    }
}

/// Convenience: the step component only (ignores device). Errors on a non-kid.
pub fn step_from_kid(kid: &str) -> Result<i64, RatchetError> {
    Ok(parse_transcript_kid(kid)?.1)
}

/// Re-derive the message key for entry `step` by ratcheting the chain forward from
/// `transcript_root` (replay-from-root read path; O(step)).
pub fn message_key_at(transcript_root: &[u8], step: i64) -> Result<Vec<u8>, RatchetError> {
    if step < 0 {
        return Err(RatchetError::NegativeStep);
    }
    let mut chain_key = transcript_root.to_vec();
    for _ in 0..step {
        chain_key = hkdf(&chain_key, CHAIN_LABEL, KEY_LEN);
    }
    Ok(hkdf(&chain_key, MSG_LABEL, KEY_LEN))
}

/// Append-side, forward-secret ratchet. `advance()` → (step, message_key); the prior chain key is
/// overwritten (not retained) on each advance.
pub struct TranscriptRatchet {
    chain_key: Vec<u8>,
    step: i64,
}

impl TranscriptRatchet {
    pub fn new(transcript_root: &[u8]) -> Self {
        TranscriptRatchet {
            chain_key: transcript_root.to_vec(),
            step: -1,
        }
    }

    pub fn step(&self) -> i64 {
        self.step
    }

    /// Advance one step: derive the message key from the current chain key, then replace the
    /// chain key with its successor (discarding the prior — unrecoverable on-device).
    pub fn advance(&mut self) -> (i64, Vec<u8>) {
        self.step += 1;
        let message_key = hkdf(&self.chain_key, MSG_LABEL, KEY_LEN);
        self.chain_key = hkdf(&self.chain_key, CHAIN_LABEL, KEY_LEN);
        (self.step, message_key)
    }
}
