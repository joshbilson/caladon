"""Metadata padding (identity-envelope §9): fixed-bucket pad/unpad."""

from __future__ import annotations

import pytest

crypto = pytest.importorskip("swifty_crypto")


@pytest.mark.parametrize("n", [0, 1, 5, 251, 252, 253, 1000, 4096, 5000, 70000])
def test_round_trip(n: int) -> None:
    msg = b"x" * n
    assert crypto.unpad(crypto.pad(msg)) == msg


@pytest.mark.parametrize(
    "n,bucket",
    [
        (0, 256),       # body = 4 -> 256
        (252, 256),     # body = 256 -> 256
        (253, 1024),    # body = 257 -> 1024
        (1020, 1024),   # body = 1024 -> 1024
        (1021, 4096),
        (70000, 262144),  # > largest bucket -> multiple of 262144
    ],
)
def test_bucket_boundaries(n: int, bucket: int) -> None:
    assert len(crypto.pad(b"x" * n)) == bucket


def test_size_hidden_within_a_bucket() -> None:
    # two different plaintexts in the same bucket pad to the SAME length (size hidden)
    assert len(crypto.pad(b"a")) == len(crypto.pad(b"a" * 100))


def test_parity_vector() -> None:
    # Pinned so the Swift client must match byte-for-byte.
    v = crypto.pad(b"hello")
    assert len(v) == 256
    assert v[:9] == b"\x00\x00\x00\x05hello"  # uint32_be(5) ‖ "hello"
    assert v[:9].hex() == "0000000568656c6c6f"
    assert v[9:] == b"\x00" * (256 - 9)       # zero filler


def test_unpad_rejects_bad_length() -> None:
    with pytest.raises(ValueError):
        crypto.unpad(b"\xff\xff\xff\xff" + b"short")  # declared len >> buffer
    with pytest.raises(ValueError):
        crypto.unpad(b"\x00\x00")  # shorter than the length prefix
