//! caladon-core — the single source of crypto + attestation truth for Caladon.
//!
//! Compiles to WASM (the LibreChat web fork) and a UniFFI xcframework (the native Swift app), so
//! the security-critical code is implemented ONCE. The Python `swifty_crypto` reference + the live
//! gateway remain the byte-parity oracle (NOT replaced) — `tests/vectors.rs` asserts byte-identical
//! output against fixtures generated from Python (`tests/generate_vectors.py`).
//!
//! P1 (this slice): `kdf` + `padding`, parity-gated. P1-next: `envelope`, `session`, `ratchet`,
//! `seed_codec`, `seed_auth`, `passkey`. P3: `attestation` (dcap-qvl) + wasm-bindgen + UniFFI.

pub mod envelope;
pub mod kdf;
pub mod padding;
pub mod passkey;
pub mod ratchet;
pub mod seed_auth;
pub mod seed_codec;
pub mod session;

// P3: attestation (dcap-qvl). The `attestation` module + bindings only compile when an
// attestation/binding feature is on, so the default parity-gate build stays pure-crypto and
// dependency-light. `verdict` (the Verdict/VerdictReason/PinnedSet types) is always available.
pub mod attestation;

#[cfg(feature = "wasm")]
pub mod wasm;

// UniFFI scaffolding (native Swift xcframework).
//
// TOOLCHAIN NOTE (see ffi.rs): UniFFI's UDL `udl_derive` codegen does not compile on rustc 1.96,
// so the scaffolding uses PROC-MACRO mode (`#[derive(uniffi::*)]` + `#[uniffi::export]` +
// `setup_scaffolding!`), which does compile. `src/caladon_core.udl` is retained as the
// authoritative interface contract. build.rs is a documented no-op for codegen accordingly.
#[cfg(feature = "uniffi-bindings")]
mod ffi;

#[cfg(feature = "uniffi-bindings")]
pub use ffi::*;

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!("caladon_core");
