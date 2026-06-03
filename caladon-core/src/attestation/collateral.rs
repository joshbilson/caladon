//! PCS/PCCS collateral fetch — NATIVE (`std`) ONLY.
//!
//! `verify_quote` is offline + deterministic: it takes the collateral JSON as an argument so the
//! SAME verification code runs on wasm32 (where networking is excluded — JS fetches collateral)
//! and native. This module is the native convenience that fetches that JSON via dcap-qvl's
//! reqwest-backed `CollateralClient` (the `report` feature), keyed on the quote's FMSPC.
//!
//! The fetched bundle is serialized to JSON with the EXACT shape `verify_quote` expects
//! (`dcap_qvl::QuoteCollateralV3` serde). Round-trip: fetch -> JSON -> commit as an offline
//! fixture -> feed the deterministic `verify_quote` in tests.

#![cfg(any(feature = "std", feature = "uniffi-bindings"))]

use dcap_qvl::collateral::{CollateralClient, PHALA_PCCS_URL};

/// Fetch collateral for `quote_bytes` from the given PCCS URL (default Phala PCCS when `None`),
/// returning it as the JSON string `verify_quote` consumes. Async (network). Native only.
pub async fn fetch_collateral_json(
    quote_bytes: &[u8],
    pccs_url: Option<&str>,
) -> Result<String, String> {
    let url = pccs_url.unwrap_or(PHALA_PCCS_URL).to_string();
    let collateral = CollateralClient::with_default_http(url)
        .map_err(|e| format!("collateral client build failed: {e}"))?
        .fetch(quote_bytes)
        .await
        .map_err(|e| format!("collateral fetch failed: {e}"))?;
    serde_json::to_string(&collateral).map_err(|e| format!("collateral serialize failed: {e}"))
}
