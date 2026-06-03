//! Attestation verdict types — the Rust mirror of `SwiftyKit/Attestation.swift`
//! (`Verdict` / `VerdictReason` / `PinnedSet`).
//!
//! This is the fail-closed DECISION surface (contracts/attestation.md §4): the client transmits
//! nothing unless the verdict is `ok`. Every non-ok path carries a DISTINCT reason so
//! TCB-out-of-date / sig-invalid / measurement-unpinned surface as separate diagnostics (§8).
//!
//! The string values of `VerdictReason` are kept BYTE-IDENTICAL to the Swift enum's raw values
//! (the A7 failure→code table, attestation-evidence.md §1) so the web (wasm) client, the native
//! (UniFFI) client and the Swift reference all speak the same code vocabulary.

use std::collections::BTreeSet;

/// Regime dispatch (contracts/attestation.md §4). Mirrors `SwiftyKit/Attestation.swift::Regime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"), derive(serde::Serialize, serde::Deserialize))]
pub enum Regime {
    /// Intel TDX attested via DCAP (dcap-qvl). The only regime this module verifies.
    TdxOnchain,
    /// SEV-SNP + Sigstore (tinfoil) — not implemented here.
    SevSigstore,
    /// T0 self-host (operator == user); no remote TEE to attest.
    None,
}

/// The A7 failure→code table (attestation-evidence.md §1). RAW VALUES MUST MATCH the Swift
/// `VerdictReason` raw strings exactly. `RECEIPT_INVALID` is a session-layer concern, not here.
/// serde (web/wasm + native) serializes this as its WIRE CODE (`code()`), not the Rust variant
/// name — see the manual Serialize/Deserialize below, so every client speaks ONE vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictReason {
    Ok,
    /// Quote signature / Intel-root chain invalid (also: collateral sig/window failures roll up
    /// here unless they are specifically TCB-out-of-date — see `code()` mapping).
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

impl VerdictReason {
    /// The stable wire code (byte-identical to the Swift enum raw values).
    pub fn code(&self) -> &'static str {
        match self {
            VerdictReason::Ok => "ok",
            VerdictReason::QuoteSigInvalid => "QUOTE_SIG_INVALID",
            VerdictReason::TcbOutOfDate => "TCB_OUT_OF_DATE",
            VerdictReason::CollateralStale => "COLLATERAL_STALE",
            VerdictReason::MeasurementUnpinned => "MEASUREMENT_UNPINNED",
            VerdictReason::ComposeMismatch => "COMPOSE_MISMATCH",
            VerdictReason::AppIdMismatch => "APPID_MISMATCH",
            VerdictReason::BindingMismatch => "BINDING_MISMATCH",
            VerdictReason::NoLogAbsent => "NO_LOG_ABSENT",
            VerdictReason::RegimeUnsupported => "REGIME_UNSUPPORTED",
        }
    }

    /// Inverse of `code()` — parse a wire code back to a reason (cross-client round-trip).
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "ok" => VerdictReason::Ok,
            "QUOTE_SIG_INVALID" => VerdictReason::QuoteSigInvalid,
            "TCB_OUT_OF_DATE" => VerdictReason::TcbOutOfDate,
            "COLLATERAL_STALE" => VerdictReason::CollateralStale,
            "MEASUREMENT_UNPINNED" => VerdictReason::MeasurementUnpinned,
            "COMPOSE_MISMATCH" => VerdictReason::ComposeMismatch,
            "APPID_MISMATCH" => VerdictReason::AppIdMismatch,
            "BINDING_MISMATCH" => VerdictReason::BindingMismatch,
            "NO_LOG_ABSENT" => VerdictReason::NoLogAbsent,
            "REGIME_UNSUPPORTED" => VerdictReason::RegimeUnsupported,
            _ => return None,
        })
    }
}

// Serialize/Deserialize VerdictReason as its STABLE WIRE CODE (e.g. "QUOTE_SIG_INVALID"), NOT the
// Rust variant name ("QuoteSigInvalid"), so the web (wasm/serde), native (UniFFI) and Swift clients
// + the gateway all branch on ONE code vocabulary.
#[cfg(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"))]
impl serde::Serialize for VerdictReason {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.code())
    }
}

#[cfg(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"))]
impl<'de> serde::Deserialize<'de> for VerdictReason {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        VerdictReason::from_code(&s)
            .ok_or_else(|| <D::Error as serde::de::Error>::custom(format!("unknown verdict reason: {s}")))
    }
}

#[cfg(all(test, feature = "std"))]
mod reason_serde_tests {
    use super::*;

    #[test]
    fn reason_serializes_to_wire_code_not_variant_name() {
        let j = serde_json::to_string(&Verdict::fail(VerdictReason::QuoteSigInvalid)).unwrap();
        assert!(j.contains("\"QUOTE_SIG_INVALID\""), "must use the wire code: {j}");
        assert!(!j.contains("QuoteSigInvalid"), "must NOT leak the Rust variant name: {j}");
        let back: Verdict = serde_json::from_str(&j).unwrap();
        assert_eq!(back.reason, VerdictReason::QuoteSigInvalid); // round-trips
    }
}

/// The fail-closed verdict. `ok` is true ONLY when `reason == Ok`. `measurement_matched` records
/// whether the §4.3 measurement pin matched (useful for the 2-phase observe→pin→enforce rollout
/// diagnostics: a quote can be cryptographically valid yet measurement-unpinned).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"), derive(serde::Serialize, serde::Deserialize))]
pub struct Verdict {
    pub ok: bool,
    pub reason: VerdictReason,
    pub measurement_matched: bool,
}

impl Verdict {
    /// A failing verdict with the given reason. `measurement_matched` defaults false.
    pub fn fail(reason: VerdictReason) -> Self {
        Verdict {
            ok: false,
            reason,
            measurement_matched: false,
        }
    }

    /// A failing verdict that records whether the measurement matched (so a binding/app_id/no-log
    /// failure AFTER a measurement match still reports `measurement_matched = true`).
    pub fn fail_with_measurement(reason: VerdictReason, measurement_matched: bool) -> Self {
        Verdict {
            ok: false,
            reason,
            measurement_matched,
        }
    }

    pub fn pass() -> Self {
        Verdict {
            ok: true,
            reason: VerdictReason::Ok,
            measurement_matched: true,
        }
    }
}

/// The client-shipped pinned set (docs/security/measurements.md). NO TOFU / accept-new.
/// Mirrors `SwiftyKit/Attestation.swift::PinnedSet`.
///
/// - `measurements`: the lowercase-hex aggregate `mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2` (see
///   `mod.rs::measurement_aggregate`). The boot/runtime measured state of the CVM.
/// - `compose_hashes`: the dstack `compose_hash` (the app-layer workload contract).
/// - `workload_ids`: the dstack `app_id`.
#[derive(Debug, Clone, Default)]
pub struct PinnedSet {
    pub measurements: BTreeSet<String>,
    pub compose_hashes: BTreeSet<String>,
    pub workload_ids: BTreeSet<String>,
}

impl PinnedSet {
    pub fn new(
        measurements: BTreeSet<String>,
        compose_hashes: BTreeSet<String>,
        workload_ids: BTreeSet<String>,
    ) -> Self {
        PinnedSet {
            measurements,
            compose_hashes,
            workload_ids,
        }
    }

    /// Convenience: build from slices (the common pin-list shape).
    pub fn from_lists(measurements: &[&str], compose_hashes: &[&str], workload_ids: &[&str]) -> Self {
        PinnedSet {
            measurements: measurements.iter().map(|s| s.to_string()).collect(),
            compose_hashes: compose_hashes.iter().map(|s| s.to_string()).collect(),
            workload_ids: workload_ids.iter().map(|s| s.to_string()).collect(),
        }
    }
}
