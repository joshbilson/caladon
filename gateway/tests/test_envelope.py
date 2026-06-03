"""Envelope structural validation — the ciphertext router's fail-closed content guard
(identity-envelope.md §4)."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from app.envelope import Envelope


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _valid_kwargs() -> dict:
    return {
        "v": 1,
        "alg": "xchacha20poly1305",
        "kid": "t:0",
        "nonce": _b64(b"\x00" * 24),
        "aad": _b64(b"aad-bytes"),
        "ct": _b64(b"\x11" * 32),
    }


def test_valid_envelope_parses():
    e = Envelope(**_valid_kwargs())
    assert e.alg == "xchacha20poly1305"
    assert e.v == 1


@pytest.mark.parametrize(
    "patch",
    [
        {"alg": "aes-256-gcm"},            # alg not allowlisted
        {"alg": "XCHACHA20POLY1305"},      # case-sensitive allowlist
        {"v": 0},                          # version must be >= 1
        {"v": -1},
        {"kid": ""},                       # empty kid
        {"nonce": _b64(b"\x00" * 23)},     # wrong nonce length (must be 24)
        {"nonce": _b64(b"\x00" * 25)},
        {"nonce": "not-base64!!"},         # non-base64
        {"aad": ""},                       # empty aad
        {"aad": "not-base64!!"},
        {"ct": _b64(b"\x11" * 8)},         # too short to hold a 16-byte AEAD tag
        {"ct": "not-base64!!"},
    ],
)
def test_malformed_envelope_rejected(patch):
    kwargs = _valid_kwargs()
    kwargs.update(patch)
    with pytest.raises(ValidationError):
        Envelope(**kwargs)


@pytest.mark.parametrize("missing", ["v", "alg", "kid", "nonce", "aad", "ct"])
def test_missing_field_rejected(missing):
    kwargs = _valid_kwargs()
    del kwargs[missing]
    with pytest.raises(ValidationError):
        Envelope(**kwargs)


def test_extra_plaintext_field_rejected():
    """extra='forbid' is the load-bearing guard: a stray plaintext field (e.g. a leaked
    `content`/`text`) must be REFUSED, never silently stored/forwarded by the router."""
    with pytest.raises(ValidationError):
        Envelope(**_valid_kwargs(), content="hello plaintext")
    with pytest.raises(ValidationError):
        Envelope(**_valid_kwargs(), text="leaked prompt")
