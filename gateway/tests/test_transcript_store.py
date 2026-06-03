"""Per-tenant ciphertext transcript store: append-only, newest-last, isolated, fail-closed."""

from __future__ import annotations

import base64

import pytest

from app.envelope import Envelope
from app.transcript import TranscriptStore

ACCT_A = "accountA_0123456789ab"
ACCT_B = "accountB_0123456789ab"


def _env(tag: bytes) -> Envelope:
    return Envelope(
        v=1,
        alg="xchacha20poly1305",
        kid="t:0",
        nonce=base64.b64encode(b"\x00" * 24).decode(),
        aad=base64.b64encode(b"aad").decode(),
        ct=base64.b64encode(tag * 16).decode(),
    )


@pytest.fixture
def store(tmp_path):
    return TranscriptStore(tmp_path / "transcripts.json")


def test_append_and_list_newest_last(store):
    store.append(ACCT_A, _env(b"\x01"))
    store.append(ACCT_A, _env(b"\x02"))
    rows = store.list(ACCT_A)
    assert len(rows) == 2
    # chronological tail: first appended is first in the list
    assert rows[0]["ct"] == base64.b64encode(b"\x01" * 16).decode()
    assert rows[1]["ct"] == base64.b64encode(b"\x02" * 16).decode()


def test_limit_returns_tail(store):
    for i in range(5):
        store.append(ACCT_A, _env(bytes([i])))
    rows = store.list(ACCT_A, limit=2)
    assert len(rows) == 2  # newest two (the tail)
    assert rows[-1]["ct"] == base64.b64encode(bytes([4]) * 16).decode()


def test_limit_zero_returns_empty(store):
    store.append(ACCT_A, _env(b"\x01"))
    assert store.list(ACCT_A, limit=0) == []


def test_tenant_isolation(store):
    store.append(ACCT_A, _env(b"\xaa"))
    assert store.list(ACCT_B) == []  # B never sees A's log
    store.append(ACCT_B, _env(b"\xbb"))
    assert len(store.list(ACCT_A)) == 1
    assert len(store.list(ACCT_B)) == 1


def test_persists_across_instances(tmp_path):
    p = tmp_path / "t.json"
    s1 = TranscriptStore(p)
    s1.append(ACCT_A, _env(b"\x07"))
    s2 = TranscriptStore(p)  # reload from disk
    assert len(s2.list(ACCT_A)) == 1


def test_rejects_non_envelope(store):
    with pytest.raises(TypeError):
        store.append(ACCT_A, {"ct": "not-an-envelope-instance"})  # type: ignore[arg-type]


def test_rejects_bad_account_id(store):
    with pytest.raises(ValueError):
        store.append("short", _env(b"\x01"))
    with pytest.raises(ValueError):
        store.list("bad!chars")


def test_corrupt_store_fails_closed(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('["not", "an", "object"]', encoding="utf-8")  # array, not the expected map
    with pytest.raises(ValueError):
        TranscriptStore(p)


def test_returned_rows_do_not_alias_cache(store):
    store.append(ACCT_A, _env(b"\x01"))
    rows = store.list(ACCT_A)
    rows[0]["ct"] = "tampered"  # mutate the returned dict
    assert store.list(ACCT_A)[0]["ct"] != "tampered"  # cache is unaffected
