//! Build script.
//!
//! TOOLCHAIN NOTE (P3/R2): UniFFI's UDL-mode scaffolding generator (`uniffi::generate_scaffolding`)
//! emits `udl_derive` code that does NOT compile on rustc 1.96 (the installed toolchain) — see
//! src/ffi.rs and internal spike notes. The `uniffi-bindings` feature therefore uses UniFFI
//! PROC-MACRO mode (`#[derive(uniffi::*)]` + `#[uniffi::export]` + `setup_scaffolding!`), which
//! needs NO build-time codegen. So this build script intentionally does nothing.
//!
//! `src/caladon_core.udl` is kept as the authoritative interface contract; re-enable
//! `uniffi::generate_scaffolding("src/caladon_core.udl")` here (and switch lib.rs back to
//! `include_scaffolding!`) once a uniffi/rustc combination compiles UDL mode again.

fn main() {
    println!("cargo:rerun-if-changed=src/caladon_core.udl");
}
