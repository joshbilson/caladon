//! Seed transcription codec (identity-envelope.md §2): Mullvad-style Crockford base32 with a
//! 2-byte SHA-256 checksum, grouped in 4s. Byte-identical to `SwiftyKit/SeedCodec.swift`
//! (`SeedCodec` + `Base32Crockford`) — the Swift impl is the oracle (no Python ref for this).
//!
//! A mistyped backup is caught (checksum), not silently wrong. Strict decode: the canonical
//! encoder zero-pads the trailing partial symbol, so any leftover bits MUST be zero — a corrupt
//! last character can't decode to valid bytes.

use sha2::{Digest, Sha256};

pub const SEED_BYTE_COUNT: usize = 32; // 256-bit entropy
const CHECKSUM_LEN: usize = 2; // first 2 bytes of SHA-256(seed)
const GROUP_SIZE: usize = 4;

/// Crockford base32 alphabet (excludes I, L, O, U). Decode normalises I/L→1, O→0.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, PartialEq, Eq)]
pub enum SeedError {
    BadLength,
    BadChecksum,
    BadCharacter,
}

fn checksum(seed: &[u8]) -> [u8; CHECKSUM_LEN] {
    let d = Sha256::digest(seed);
    [d[0], d[1]]
}

/// Lowest-level Crockford base32 encode (no grouping). Matches `Base32Crockford.encode`.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

/// Lowest-level Crockford base32 decode (input already cleaned of '-'/whitespace).
/// Matches `Base32Crockford.decode`, including the strict trailing-pad-bits check.
fn base32_decode(text: &str) -> Result<Vec<u8>, SeedError> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars() {
        let up = ch.to_ascii_uppercase();
        let value: u32 = match up {
            '0'..='9' => (up as u8 - b'0') as u32,
            // Crockford normalisation: I/L→1, O→0.
            'I' | 'L' => 1,
            'O' => 0,
            _ => match ALPHABET.iter().position(|&c| c == up as u8) {
                Some(i) => i as u32,
                None => return Err(SeedError::BadCharacter),
            },
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    // Strict: leftover bits from the trailing partial symbol MUST be zero (canonical zero-pad).
    if bits > 0 && (buffer & ((1u32 << bits) - 1)) != 0 {
        return Err(SeedError::BadCharacter);
    }
    Ok(bytes)
}

/// seed (32B) + checksum (2B) → Crockford base32, grouped in 4s with '-'.
pub fn encode(seed: &[u8]) -> Result<String, SeedError> {
    if seed.len() != SEED_BYTE_COUNT {
        return Err(SeedError::BadLength);
    }
    let mut payload = Vec::with_capacity(SEED_BYTE_COUNT + CHECKSUM_LEN);
    payload.extend_from_slice(seed);
    payload.extend_from_slice(&checksum(seed));
    let chars: Vec<char> = base32_encode(&payload).chars().collect();
    let groups: Vec<String> = chars
        .chunks(GROUP_SIZE)
        .map(|c| c.iter().collect::<String>())
        .collect();
    Ok(groups.join("-"))
}

/// Inverse of `encode`. Case-insensitive; '-' and whitespace ignored; Crockford normalisation.
/// Fails closed on a bad checksum / length / character.
pub fn decode(text: &str) -> Result<Vec<u8>, SeedError> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let payload = base32_decode(&cleaned)?;
    if payload.len() != SEED_BYTE_COUNT + CHECKSUM_LEN {
        return Err(SeedError::BadLength);
    }
    let seed = &payload[..SEED_BYTE_COUNT];
    let given = &payload[SEED_BYTE_COUNT..];
    if given != checksum(seed) {
        return Err(SeedError::BadChecksum);
    }
    Ok(seed.to_vec())
}
