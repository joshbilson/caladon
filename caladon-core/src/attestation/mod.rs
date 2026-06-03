//! Attestation keystone (contracts/attestation.md §4) — the fail-closed decision core for the
//! Caladon TDX regime, verifying a real Intel DCAP TDX quote with `dcap-qvl` (Phala, pure Rust)
//! and applying no-TOFU measurement / compose / app-id pinning + channel binding + no-log.
//!
//! ==========================================================================================
//! R2 SPIKE FINDINGS — dcap-qvl (pinned 0.5.x; the workspace cache had 0.5.2). Confirmed by
//! reading the crate source at
//! ~/.cargo/registry/src/.../dcap-qvl-0.5.2/src/{lib,verify,quote,collateral,configs}.rs
//! (also appended to internal spike notes). The task brief referenced "v0.3"; the live
//! API moved — recorded here so the binding can't silently drift:
//!
//!   * VERIFY FN: `dcap_qvl::verify::verify(raw_quote: &[u8], collateral: &QuoteCollateralV3,
//!     now_secs: u64) -> anyhow::Result<VerifiedReport>` is the convenience entry (DefaultConfig).
//!     Backend-pinned variants: `verify::ring::verify` and `verify::rustcrypto::verify`. We pin
//!     `verify::rustcrypto::verify` (pure Rust) so the SAME code path compiles to wasm32 (ring
//!     uses assembly and does NOT link on wasm32-unknown-unknown — see Cargo.toml feature notes).
//!     Also `QuoteVerifier::new(root_ca_der).verify_with::<C>(...)` to PIN an explicit Intel root
//!     CA DER (stronger than trusting the collateral chain).
//!
//!   * COLLATERAL TYPE: `dcap_qvl::QuoteCollateralV3` (serde Serialize/Deserialize) — the JSON
//!     blob `verify_quote` consumes. FETCH FN (native/`report` feature only):
//!     `dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)?.fetch(&quote).await`
//!     -> `QuoteCollateralV3`, keyed internally on the quote's FMSPC. Default PCCS:
//!     `dcap_qvl::PHALA_PCCS_URL` = "https://pccs.phala.network". (collateral.rs wraps this.)
//!
//!   * VerifiedReport { status: String ("UpToDate"|"OutOfDate"|"OutOfDateConfigurationNeeded"|...),
//!     advisory_ids: Vec<String>, report: Report, ppid: Vec<u8>, qe_status, platform_status }.
//!     verify_impl already `bail!`s if the merged TCB status is NOT valid; UpToDate vs the other
//!     accepted-but-degraded statuses is surfaced via `status` so WE enforce strict UpToDate.
//!
//!   * Report enum: `Report::{SgxEnclave(EnclaveReport), TD10(TDReport10), TD15(TDReport15)}`.
//!     `Report::as_td10() -> Option<&TDReport10>` returns the TD10 body for BOTH TD10 and TD15
//!     (TD15 embeds TD10 as `.base`). TDReport10 FIELD NAMES (all the §4.3 measurements):
//!       mr_td: [u8;48], rt_mr0: [u8;48], rt_mr1: [u8;48], rt_mr2: [u8;48], rt_mr3: [u8;48],
//!       report_data: [u8;64], plus mr_seam/mr_signer_seam/td_attributes/xfam/mr_config_id/...
//!     (NOTE: field is `rt_mr0` not `rt_mr_0`; `mr_td` not `mrtd`.) TD15 adds `mr_service_td`.
//!
//!   * report_data: dstack writes the 32-byte client challenge VERBATIM into report_data[0:32]
//!     (the rest zero-padded to 64) — see the internal deploy notes §"key unknown". The
//!     challenge itself = lowercase-hex SHA-256(eph_pub) (spike-notes (c)). So §4.6 binding =
//!     `report_data[0:32] == hex_decode(expected_challenge_hex)`.
//! ==========================================================================================
//!
//! compose_hash / app_id are NOT in the quote — they live in the dstack `info` JSON (POST /Info),
//! which the client passes ALONGSIDE the quote. They are reproduced in the RTMR3 event log
//! (events `app-id`, `compose-hash`); pinning them + the RTMR aggregate ties the app-layer
//! workload contract to the hardware-measured boot state. We pin BOTH (defense in depth) but the
//! cryptographic root of trust is the quote -> Intel root chain; `info` is untrusted until its
//! claims are checked against the pinned set.

pub mod verdict;

// Native async collateral fetch (reqwest via dcap-qvl `report`). Available whenever a native
// attestation feature that enables `dcap-qvl/report` is on (std or uniffi-bindings).
#[cfg(any(feature = "std", feature = "uniffi-bindings"))]
pub mod collateral;

pub use verdict::{PinnedSet, Regime, Verdict, VerdictReason};

#[cfg(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"))]
mod imp {
    use super::verdict::{PinnedSet, Verdict, VerdictReason};
    use dcap_qvl::quote::Report;
    use sha2::{Digest, Sha256};

    /// The dstack `info` JSON (POST /Info). Only the fields the keystone pins. Extra fields are
    /// ignored (serde default). `no_log` is OPTIONAL: see the no-log note in `verify_quote`.
    #[derive(serde::Deserialize)]
    struct DstackInfo {
        #[serde(default)]
        compose_hash: String,
        #[serde(default)]
        app_id: String,
        /// Optional explicit no-log assertion from the measured config. When absent, no-log is
        /// derived structurally from the pinned compose_hash (only no-log composes are pinned).
        #[serde(default)]
        no_log: Option<bool>,
    }

    /// Lowercase-hex measurement aggregate `mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2` — the §4.3 pinned
    /// boot/runtime measurement. rtmr3 is EXCLUDED: it carries the app-id/compose-hash/instance
    /// event log (those are pinned separately via `info`), so folding it in would make the
    /// measurement pin instance-specific. (Matches docs/security/measurements.md: mrtd + rtmr0..2.)
    fn measurement_aggregate(mr_td: &[u8; 48], rt_mr0: &[u8; 48], rt_mr1: &[u8; 48], rt_mr2: &[u8; 48]) -> String {
        let mut out = String::with_capacity((48 * 4) * 2);
        for part in [mr_td.as_slice(), rt_mr0, rt_mr1, rt_mr2] {
            out.push_str(&hex::encode(part));
        }
        out
    }

    /// Fail-closed quote verification (contracts/attestation.md §4 ORDER):
    ///   §4.1-4.2  quote signature -> Intel root chain  (dcap-qvl; FAIL: QUOTE_SIG_INVALID)
    ///   §4.2      TCB strictly UpToDate                 (FAIL: TCB_OUT_OF_DATE)
    ///   §4.3      measurement pin (mr_td + rtmr0..2)    (FAIL: MEASUREMENT_UNPINNED)
    ///   §4.4      compose_hash pin (from `info`)        (FAIL: COMPOSE_MISMATCH)
    ///   §4.5      app_id pin (from `info`)              (FAIL: APPID_MISMATCH)
    ///   §4.6      report_data[0:32] == challenge        (FAIL: BINDING_MISMATCH)
    ///   §4.7      no-log posture                        (FAIL: NO_LOG_ABSENT)
    /// Returns ok=true ONLY if every step passes. NO LOGGING of any field (no-log posture).
    ///
    /// `collateral_json` is `dcap_qvl::QuoteCollateralV3` serialized to JSON (fetched by the
    /// native helper or, on wasm, by JS). `info_json` is the dstack POST /Info body.
    /// `expected_challenge_hex` is lowercase-hex SHA-256(eph_pub) (the 32-byte channel binding).
    pub fn verify_quote(
        quote_bytes: &[u8],
        collateral_json: &str,
        info_json: &str,
        now_secs: u64,
        expected_challenge_hex: &str,
        pinned: &PinnedSet,
    ) -> Verdict {
        // --- §4.1-4.2: cryptographic chain to the Intel root + TCB validity (dcap-qvl). ---
        let collateral: dcap_qvl::QuoteCollateralV3 = match serde_json::from_str(collateral_json) {
            Ok(c) => c,
            // A malformed/missing collateral cannot anchor the chain — treat as a stale/absent
            // collateral failure (distinct from a bad quote signature) per §8 diagnostics.
            Err(_) => return Verdict::fail(VerdictReason::CollateralStale),
        };

        // Pure-Rust (rustcrypto) backend so this exact code path also compiles to wasm32.
        let report = match dcap_qvl::verify::rustcrypto::verify(quote_bytes, &collateral, now_secs) {
            Ok(r) => r,
            // dcap-qvl returns anyhow::Error; classify on its Display message (we don't take a
            // direct anyhow dep — the message is the only diagnostic the library exposes).
            Err(e) => return Verdict::fail(classify_verify_err(&e.to_string())),
        };

        // §4.2 strict TCB: verify_impl already rejected an *invalid* status; require UpToDate.
        // Any accepted-but-degraded status (OutOfDate / ConfigurationNeeded / SWHardeningNeeded)
        // is a fail-closed TCB_OUT_OF_DATE for our posture.
        if report.status != "UpToDate" {
            return Verdict::fail(VerdictReason::TcbOutOfDate);
        }

        // Extract the TD report (TD10 body; works for TD10 and TD15). SGX quotes are not a valid
        // Caladon CVM regime -> treat as an unpinnable measurement.
        let td = match &report.report {
            Report::TD10(_) | Report::TD15(_) => report
                .report
                .as_td10()
                .expect("TD10/TD15 report yields a TD10 body"),
            Report::SgxEnclave(_) => return Verdict::fail(VerdictReason::MeasurementUnpinned),
        };

        // --- §4.3: measurement pin (no TOFU). ---
        let measurement = measurement_aggregate(&td.mr_td, &td.rt_mr0, &td.rt_mr1, &td.rt_mr2);
        let measurement_matched = pinned.measurements.contains(&measurement);
        if !measurement_matched {
            return Verdict::fail_with_measurement(VerdictReason::MeasurementUnpinned, false);
        }

        // Parse the dstack info AFTER the crypto chain (untrusted until its claims are pinned).
        let info: DstackInfo = match serde_json::from_str(info_json) {
            Ok(i) => i,
            // info we can't parse can't satisfy the compose/app-id pin -> compose mismatch.
            Err(_) => return Verdict::fail_with_measurement(VerdictReason::ComposeMismatch, true),
        };

        // --- §4.4: compose_hash pin. ---
        if !pinned.compose_hashes.contains(&info.compose_hash) {
            return Verdict::fail_with_measurement(VerdictReason::ComposeMismatch, true);
        }

        // --- §4.5: app_id pin. ---
        if !pinned.workload_ids.contains(&info.app_id) {
            return Verdict::fail_with_measurement(VerdictReason::AppIdMismatch, true);
        }

        // --- §4.6: channel binding — report_data[0:32] == SHA-256(eph_pub). ---
        let expected = match hex::decode(expected_challenge_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return Verdict::fail_with_measurement(VerdictReason::BindingMismatch, true),
        };
        if td.report_data[..32] != expected[..] {
            return Verdict::fail_with_measurement(VerdictReason::BindingMismatch, true);
        }

        // --- §4.7: no-log posture. ---
        // No-log is bound to the measured workload: only no-log compose hashes are ever pinned,
        // so a matched+pinned compose_hash STRUCTURALLY asserts no-log. An explicit `no_log:false`
        // in the measured `info` overrides that and fails closed (defense in depth).
        if info.no_log == Some(false) {
            return Verdict::fail_with_measurement(VerdictReason::NoLogAbsent, true);
        }

        Verdict::pass()
    }

    /// Map a dcap-qvl verify error to the closest §8 diagnostic. dcap-qvl returns an
    /// `anyhow::Error` with a human message; we classify on the message rather than fake a
    /// finer-grained taxonomy the library does not expose. TCB-status invalidity is the one case
    /// verify_impl bails on with a "TCB status is invalid" message -> TCB_OUT_OF_DATE; expired /
    /// future collateral windows -> COLLATERAL_STALE; everything else (bad sig, bad chain,
    /// FMSPC/measurement-policy mismatch, malformed quote) -> QUOTE_SIG_INVALID.
    fn classify_verify_err(err_msg: &str) -> VerdictReason {
        let msg = err_msg.to_ascii_lowercase();
        if msg.contains("tcb status is invalid") || msg.contains("no matching tcb level") {
            VerdictReason::TcbOutOfDate
        } else if msg.contains("expired")
            || msg.contains("issue date is in the future")
            || msg.contains("next update")
        {
            VerdictReason::CollateralStale
        } else {
            VerdictReason::QuoteSigInvalid
        }
    }

    /// Compute the lowercase-hex SHA-256 challenge from an ephemeral public key — the value that
    /// must land in report_data[0:32]. Exposed so callers (and the wasm/uniffi bindings) derive
    /// the channel binding identically to the gateway.
    pub fn challenge_hex(eph_pub: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(eph_pub);
        hex::encode(h.finalize())
    }

    /// Parse a TDX quote and return its §4.3 measurement aggregate `mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2`
    /// (lowercase hex). This is the value to PIN (docs/security/measurements.md) and the value the
    /// 2-phase observe→pin→enforce rollout records. `None` for a non-TDX or unparseable quote.
    /// NOTE: this is the UNVERIFIED measurement (parse only); the trusted measurement is the one
    /// `verify_quote` checks AFTER the cryptographic chain. Use this only to build pin lists.
    pub fn measurement_of(quote_bytes: &[u8]) -> Option<String> {
        let q = dcap_qvl::quote::Quote::parse(quote_bytes).ok()?;
        let td = match &q.report {
            Report::TD10(_) | Report::TD15(_) => q.report.as_td10()?,
            Report::SgxEnclave(_) => return None,
        };
        Some(measurement_aggregate(&td.mr_td, &td.rt_mr0, &td.rt_mr1, &td.rt_mr2))
    }
}

#[cfg(any(feature = "std", feature = "wasm", feature = "uniffi-bindings"))]
pub use imp::{challenge_hex, measurement_of, verify_quote};
