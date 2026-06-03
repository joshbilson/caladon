//! Round-trip tests for the binding-surface modules via the PUBLIC crate API
//! (`passkey`, `seed_codec`, `padding`). These exercise the exact functions the WASM
//! (`src/wasm/bindings.rs`) and UniFFI (`src/ffi.rs`) exports delegate to, so a green run here
//! is the same logic both clients see across the FFI boundary.
//!
//! Pure-crypto: these modules are always compiled (no feature gate), so this file runs on the
//! default parity-gate build as well as `--features std`.

use caladon_core::{padding, passkey, seed_codec};

// ---------------------------------------------------------------------------------------------
// passkey-PRF seed custody
// ---------------------------------------------------------------------------------------------

#[test]
fn passkey_wrapping_key_is_deterministic_in_prf() {
    let prf = [7u8; 32];
    let k1 = passkey::passkey_derive_wrapping_key(&prf).expect("derive");
    let k2 = passkey::passkey_derive_wrapping_key(&prf).expect("derive");
    assert_eq!(k1, k2, "wrapping key must be a deterministic HKDF of the PRF");
    assert_eq!(k1.len(), passkey::KEY_LEN);

    // A different PRF yields a different key.
    let other = passkey::passkey_derive_wrapping_key(&[8u8; 32]).expect("derive");
    assert_ne!(k1, other);
}

#[test]
fn passkey_derive_wrapping_key_rejects_bad_prf_length() {
    assert_eq!(
        passkey::passkey_derive_wrapping_key(&[0u8; 31]),
        Err(passkey::PasskeyError::BadPrfLength)
    );
    assert_eq!(
        passkey::passkey_derive_wrapping_key(&[0u8; 33]),
        Err(passkey::PasskeyError::BadPrfLength)
    );
}

#[test]
fn passkey_wrap_unwrap_round_trip() {
    let prf = [0x11u8; 32];
    let seed = [0x42u8; 32];

    // wrap_seed returns (nonce, ct); the FFI/WASM exports concat them as `nonce || ct`. Mirror
    // that here so we exercise the same buffer shape the clients see.
    let (nonce, ct) = passkey::wrap_seed(&prf, &seed).expect("wrap");
    assert_eq!(nonce.len(), passkey::NONCE_LEN);

    let recovered = passkey::unwrap_seed(&prf, &nonce, &ct).expect("unwrap");
    assert_eq!(recovered, seed, "unwrap(wrap(seed)) must round-trip");
}

#[test]
fn passkey_unwrap_fails_closed_on_wrong_prf() {
    let prf = [0x11u8; 32];
    let wrong = [0x22u8; 32];
    let seed = [0x42u8; 32];

    let (nonce, ct) = passkey::wrap_seed(&prf, &seed).expect("wrap");
    assert_eq!(
        passkey::unwrap_seed(&wrong, &nonce, &ct),
        Err(passkey::PasskeyError::UnwrapFailed),
        "a wrong passkey/PRF must fail closed"
    );
}

#[test]
fn passkey_unwrap_fails_closed_on_tamper() {
    let prf = [0x11u8; 32];
    let seed = [0x42u8; 32];

    let (nonce, mut ct) = passkey::wrap_seed(&prf, &seed).expect("wrap");
    ct[0] ^= 0x01; // flip a ciphertext bit
    assert_eq!(
        passkey::unwrap_seed(&prf, &nonce, &ct),
        Err(passkey::PasskeyError::UnwrapFailed),
        "a tampered blob must fail closed"
    );
}

#[test]
fn passkey_wrap_rejects_bad_seed_length() {
    let prf = [0x11u8; 32];
    assert_eq!(
        passkey::wrap_seed(&prf, &[0u8; 31]),
        Err(passkey::PasskeyError::BadSeedLength)
    );
}

// ---------------------------------------------------------------------------------------------
// seed transcription codec
// ---------------------------------------------------------------------------------------------

#[test]
fn seed_codec_encode_decode_round_trip() {
    let seed: Vec<u8> = (0u8..32).collect();
    let encoded = seed_codec::encode(&seed).expect("encode");
    // Grouped in 4s with '-' separators.
    assert!(encoded.contains('-'), "encoding is grouped with '-'");
    let decoded = seed_codec::decode(&encoded).expect("decode");
    assert_eq!(decoded, seed, "decode(encode(seed)) must round-trip");
}

#[test]
fn seed_codec_decode_is_case_and_separator_insensitive() {
    let seed = [0x9au8; 32];
    let encoded = seed_codec::encode(&seed).expect("encode");
    let mangled = encoded.to_lowercase().replace('-', " ");
    let decoded = seed_codec::decode(&mangled).expect("decode");
    assert_eq!(decoded, seed);
}

#[test]
fn seed_codec_rejects_bad_checksum() {
    let seed = [0x01u8; 32];
    let encoded = seed_codec::encode(&seed).expect("encode");
    // Corrupt one symbol (within the alphabet so it parses but the checksum mismatches).
    let mut chars: Vec<char> = encoded.chars().collect();
    let idx = chars.iter().position(|c| *c != '-').unwrap();
    chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
    let corrupted: String = chars.into_iter().collect();
    // Either a checksum or a strict-trailing-bits character error — both are fail-closed.
    assert!(matches!(
        seed_codec::decode(&corrupted),
        Err(seed_codec::SeedError::BadChecksum) | Err(seed_codec::SeedError::BadCharacter)
    ));
}

#[test]
fn seed_codec_rejects_bad_character() {
    // 'U' is not in the Crockford alphabet and is not a normalisation alias.
    assert_eq!(
        seed_codec::decode("UUUU-UUUU"),
        Err(seed_codec::SeedError::BadCharacter)
    );
}

#[test]
fn seed_codec_encode_rejects_bad_length() {
    assert_eq!(
        seed_codec::encode(&[0u8; 16]),
        Err(seed_codec::SeedError::BadLength)
    );
}

// ---------------------------------------------------------------------------------------------
// metadata padding
// ---------------------------------------------------------------------------------------------

#[test]
fn padding_round_trip_across_buckets() {
    for len in [0usize, 1, 100, 251, 252, 1000, 5000] {
        let pt: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let padded = padding::pad(&pt).expect("pad");
        // The padded length is a fixed bucket (not the plaintext length, for len>0).
        assert!(padded.len() >= len + 4);
        let recovered = padding::unpad(&padded).expect("unpad");
        assert_eq!(recovered, pt, "unpad(pad(pt)) must round-trip for len={len}");
    }
}

#[test]
fn padding_hides_exact_length_within_a_bucket() {
    // Two different small plaintexts pad to the same bucket size (256).
    let a = padding::pad(&[1u8; 10]).expect("pad");
    let b = padding::pad(&[2u8; 50]).expect("pad");
    assert_eq!(a.len(), b.len(), "lengths within a bucket are indistinguishable");
    assert_eq!(a.len(), 256);
}

#[test]
fn padding_unpad_fails_closed_on_short_buffer() {
    assert_eq!(
        padding::unpad(&[0u8; 3]),
        Err(padding::PadError::TooShort),
        "a buffer shorter than the 4-byte length prefix must fail closed"
    );
}

#[test]
fn padding_unpad_fails_closed_on_declared_len_overflow() {
    // Declared length (0xFFFFFFFF) far exceeds the buffer.
    let bad = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
    assert_eq!(
        padding::unpad(&bad),
        Err(padding::PadError::DeclaredLenExceedsBuffer)
    );
}
