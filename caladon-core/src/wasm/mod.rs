//! WASM (wasm-bindgen) surface for the LibreChat web fork.
//!
//! The web client gets the SAME trust-core the native app gets: the dcap-qvl attestation verdict
//! and the sealed-channel crypto, compiled to wasm32-unknown-unknown. NETWORKING IS EXCLUDED on
//! wasm (the `report`/reqwest path is not in the `wasm` feature): JS fetches the PCS collateral
//! and passes the JSON into `verify_quote_sync`, so the verifier stays a pure, deterministic
//! function with no ambient I/O.

pub mod bindings;
