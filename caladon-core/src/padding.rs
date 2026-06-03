//! Metadata padding — the sealed-sender SIZE analog (identity-envelope.md §9). Byte-identical to
//! `swifty_crypto/padding.py`: `uint32_be(len) ‖ plaintext ‖ zero-fill` to the next bucket.

const PAD_BUCKETS: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];
const LEN_PREFIX: usize = 4;
const MAX_LEN: usize = 0xFFFF_FFFF;

#[derive(Debug, PartialEq, Eq)]
pub enum PadError {
    TooLong,
    TooShort,
    DeclaredLenExceedsBuffer,
}

fn bucket(n: usize) -> usize {
    for &b in PAD_BUCKETS.iter() {
        if n <= b {
            return b;
        }
    }
    let largest = PAD_BUCKETS[PAD_BUCKETS.len() - 1];
    ((n + largest - 1) / largest) * largest // round up to a multiple of the largest
}

/// Pad to a fixed bucket. `pad(x).len()` reveals only the bucket, not `x.len()`.
pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>, PadError> {
    if plaintext.len() > MAX_LEN {
        return Err(PadError::TooLong);
    }
    let mut body = Vec::with_capacity(LEN_PREFIX + plaintext.len());
    body.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    body.extend_from_slice(plaintext);
    let target = bucket(body.len());
    body.resize(target, 0u8);
    Ok(body)
}

/// Recover the exact plaintext. Fail-closed on a malformed/short buffer.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PadError> {
    if padded.len() < LEN_PREFIX {
        return Err(PadError::TooShort);
    }
    let n = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if n > padded.len() - LEN_PREFIX {
        return Err(PadError::DeclaredLenExceedsBuffer);
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}
