// uniffi-bindgen CLI entrypoint, pinned to uniffi 0.28.3 (matches caladon-core).
//
// `uniffi_bindgen_main` parses argv (`generate --library <lib> --language swift --out-dir ...`)
// and drives library-mode Swift binding generation against the compiled caladon-core staticlib.
fn main() {
    uniffi::uniffi_bindgen_main();
}
