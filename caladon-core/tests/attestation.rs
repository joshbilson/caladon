//! Attestation keystone tests against the REAL live TDX quote
//! (`tests/fixtures/intel_quote.hex`), verified to the Intel SGX Root CA.
//!
//! Asserts the happy path (ok=true) AND that each mutated §4 field fails closed with the CORRECT
//! `VerdictReason`. Offline + deterministic: collateral is the committed fixture
//! (`tests/fixtures/collateral.json`, fetched once from Phala PCCS) and `now` is pinned to a fixed
//! instant inside the collateral validity window (2026-06-03 .. 2026-07-03) so the test does not
//! age out as the wall clock advances.
//!
//! Requires `--features std` (the native dcap-qvl verify path). Run:
//!   cargo test --features std --test attestation

#![cfg(feature = "std")]

use caladon_core::attestation::{measurement_of, verify_quote, PinnedSet, VerdictReason};

const QUOTE_HEX: &str = include_str!("fixtures/intel_quote.hex");
const COLLATERAL_JSON: &str = include_str!("fixtures/collateral.json");

// Pinned instant inside the committed collateral's TCB-info / QE-identity validity window
// (issue 2026-06-03, next_update 2026-07-03). 2026-06-04T00:45:02Z.
const NOW_SECS: u64 = 1_780_533_902;

// Live CVM identity (the internal deploy notes + attestation-evidence.sample.json).
const CHALLENGE_HEX: &str = "a49d15e53c99ece49b4bbd54e4b92ba9eec3449a01ba148ab9683ac6b42dce24";
const APP_ID: &str = "64111f5c9442480b82b865f30e4085035a5e790b";
const COMPOSE_HASH: &str = "d95a0706c94055db38c3d26de7933f2c66a3b8c0da0a2b73bd3f85a0c1b0c90c";

// Documented prefix of the §4.3 measurement aggregate (mr_td ‖ rtmr0) from RESULT.md. rtmr1/rtmr2
// are not in RESULT.md, so the full aggregate is derived from the live quote via `measurement_of`.
const MR_TD_RTMR0_PREFIX: &str = concat!(
    "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
    "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
);

fn quote_bytes() -> Vec<u8> {
    hex::decode(QUOTE_HEX.trim()).expect("decode live quote hex")
}

/// The dstack info JSON the client passes alongside the quote (the pinned compose_hash/app_id).
fn info_json() -> String {
    format!(r#"{{"compose_hash":"{COMPOSE_HASH}","app_id":"{APP_ID}"}}"#)
}

/// The real measurement aggregate of the live quote (mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2), via the
/// public parse helper (the value an operator would pin in docs/security/measurements.md).
fn measurement() -> String {
    measurement_of(&quote_bytes()).expect("live quote is a parseable TDX quote")
}

fn full_pin() -> PinnedSet {
    PinnedSet::from_lists(&[&measurement()], &[COMPOSE_HASH], &[APP_ID])
}

#[test]
fn live_quote_verifies_ok() {
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), NOW_SECS, CHALLENGE_HEX, &full_pin());
    assert!(v.ok, "expected ok=true, got {v:?}");
    assert_eq!(v.reason, VerdictReason::Ok);
    assert!(v.measurement_matched);
}

#[test]
fn measurement_aggregate_shape_and_prefix() {
    let m = measurement();
    assert_eq!(m.len(), 4 * 48 * 2, "aggregate must be 4×48 bytes hex");
    assert!(m.starts_with(MR_TD_RTMR0_PREFIX), "mr_td/rtmr0 prefix must match RESULT.md; got {m}");
}

#[test]
fn tamper_quote_signature_fails_closed() {
    // Flip a byte inside the SIGNED region (the TD report, here in the mr_signer_seam area at
    // offset 100 = header 48 + ~52 into the report). The ISV attestation-key signature covers
    // header+report (Quote::signed_length), so this breaks the signature chain to the Intel root
    // at verify step 7 — before any measurement/binding check. NOT in the trailing PCK cert chain
    // (the collateral supplies the PCK chain, so a tail flip would be a no-op).
    let mut q = quote_bytes();
    q[100] ^= 0xFF;
    let v = verify_quote(&q, COLLATERAL_JSON, &info_json(), NOW_SECS, CHALLENGE_HEX, &full_pin());
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::QuoteSigInvalid, "got {v:?}");
}

#[test]
fn stale_now_after_collateral_window_fails_closed() {
    // `now` past the collateral next_update -> COLLATERAL_STALE (expired TCB info / QE identity).
    let future = 1_900_000_000u64; // ~2030
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), future, CHALLENGE_HEX, &full_pin());
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::CollateralStale, "got {v:?}");
}

#[test]
fn unpinned_measurement_fails_closed() {
    // A pin whose measurement does not match the quote -> MEASUREMENT_UNPINNED, measurement_matched=false.
    let wrong = "00".repeat(4 * 48); // wrong 192-byte aggregate
    let pinned = PinnedSet::from_lists(&[wrong.as_str()], &[COMPOSE_HASH], &[APP_ID]);
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), NOW_SECS, CHALLENGE_HEX, &pinned);
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::MeasurementUnpinned, "got {v:?}");
    assert!(!v.measurement_matched);
}

#[test]
fn unpinned_compose_hash_fails_closed() {
    let pinned = PinnedSet::from_lists(&[&measurement()], &["deadbeef"], &[APP_ID]);
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), NOW_SECS, CHALLENGE_HEX, &pinned);
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::ComposeMismatch, "got {v:?}");
    assert!(v.measurement_matched, "measurement matched before the compose check");
}

#[test]
fn unpinned_app_id_fails_closed() {
    let pinned = PinnedSet::from_lists(&[&measurement()], &[COMPOSE_HASH], &["not-our-app"]);
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), NOW_SECS, CHALLENGE_HEX, &pinned);
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::AppIdMismatch, "got {v:?}");
}

#[test]
fn wrong_challenge_binding_fails_closed() {
    // A different challenge (not the one bound into report_data[0:32]) -> BINDING_MISMATCH.
    let wrong = "00".repeat(32);
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info_json(), NOW_SECS, &wrong, &full_pin());
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::BindingMismatch, "got {v:?}");
}

#[test]
fn explicit_no_log_false_fails_closed() {
    // The measured info asserting no_log:false fails §4.7 even with everything else pinned.
    let info = format!(r#"{{"compose_hash":"{COMPOSE_HASH}","app_id":"{APP_ID}","no_log":false}}"#);
    let v = verify_quote(&quote_bytes(), COLLATERAL_JSON, &info, NOW_SECS, CHALLENGE_HEX, &full_pin());
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::NoLogAbsent, "got {v:?}");
}

#[test]
fn malformed_collateral_fails_closed() {
    let v = verify_quote(&quote_bytes(), "{not valid collateral}", &info_json(), NOW_SECS, CHALLENGE_HEX, &full_pin());
    assert!(!v.ok);
    assert_eq!(v.reason, VerdictReason::CollateralStale, "got {v:?}");
}
