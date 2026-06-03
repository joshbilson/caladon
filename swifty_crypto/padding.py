"""Metadata padding — the sealed-sender SIZE analog (identity-envelope.md §9).

Even with perfect content encryption, a relay sees ciphertext *sizes*. Padding the plaintext
to a fixed bucket before sealing means `ct` length reveals only the bucket, not the true
size, blunting size-based traffic analysis. (Disclosed non-goal: this is partial — timing
and frequency are out of scope; state so in vetting docs.)

Scheme (deterministic, so the Swift client and Python reference agree byte-for-byte):
  padded = uint32_be(len(plaintext)) ‖ plaintext ‖ zero-filler  →  total = next bucket ≥ (4+len)
The 4-byte length prefix lets `unpad` recover the exact plaintext. The filler is zero (its
content is irrelevant — it is inside the AEAD ciphertext after sealing).
"""

from __future__ import annotations

# Exponential buckets (bytes); past the largest, round UP to a multiple of it.
PAD_BUCKETS = (256, 1024, 4096, 16384, 65536, 262144)
_LEN_PREFIX = 4
MAX_LEN = 0xFFFF_FFFF  # uint32 length prefix


def _bucket(n: int) -> int:
    for b in PAD_BUCKETS:
        if n <= b:
            return b
    largest = PAD_BUCKETS[-1]
    return ((n + largest - 1) // largest) * largest  # round up to a multiple of the largest


def pad(plaintext: bytes) -> bytes:
    """Pad to a fixed bucket. `len(pad(x))` reveals only the bucket, not `len(x)`."""
    if len(plaintext) > MAX_LEN:
        raise ValueError("plaintext too long to pad")
    body = len(plaintext).to_bytes(_LEN_PREFIX, "big") + plaintext
    return body + b"\x00" * (_bucket(len(body)) - len(body))


def unpad(padded: bytes) -> bytes:
    """Recover the exact plaintext. Fail-closed on a malformed/short buffer."""
    if len(padded) < _LEN_PREFIX:
        raise ValueError("padded buffer too short")
    n = int.from_bytes(padded[:_LEN_PREFIX], "big")
    if n > len(padded) - _LEN_PREFIX:
        raise ValueError("declared length exceeds buffer")
    return padded[_LEN_PREFIX : _LEN_PREFIX + n]
