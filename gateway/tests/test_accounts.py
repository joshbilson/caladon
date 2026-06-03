"""Tests for the account registry (contracts/gateway-api.md, identity-envelope.md §3)."""

from __future__ import annotations

import base64

import pytest

from app.accounts import AccountRegistry


def _b64(n: int) -> str:
    return base64.b64encode(b"\x01" * n).decode()


ED = _b64(32)   # valid 32-byte Ed25519 pubkey
KEM = _b64(32)  # KEM pubkey (size not enforced beyond decodability for now)
ACCT = "acct_0123456789abcdef"  # valid url-safe, >=16 chars


def test_register_and_get(tmp_path):
    reg = AccountRegistry(tmp_path / "accounts.json")
    acct, created = reg.register(ACCT, ED, KEM, agent_id="agent-1")
    assert created is True
    assert acct.account_id == ACCT
    assert reg.get(ACCT).ed25519_pub_b64 == ED
    assert reg.agent_for(ACCT) == "agent-1"
    assert len(acct.ed25519_pub()) == 32


def test_register_is_idempotent(tmp_path):
    reg = AccountRegistry(tmp_path / "accounts.json")
    a, created_a = reg.register(ACCT, ED, KEM)
    b, created_b = reg.register(ACCT, ED, KEM)  # same key -> idempotent
    assert created_a is True and created_b is False
    assert a == b


def test_silent_key_rebind_rejected(tmp_path):
    reg = AccountRegistry(tmp_path / "accounts.json")
    reg.register(ACCT, ED, KEM)
    other_key = base64.b64encode(b"\x02" * 32).decode()
    with pytest.raises(ValueError):
        reg.register(ACCT, other_key, KEM)


def test_bad_pubkey_length_rejected(tmp_path):
    reg = AccountRegistry(tmp_path / "accounts.json")
    with pytest.raises(ValueError):
        reg.register(ACCT, _b64(16), KEM)  # 16 bytes != 32


@pytest.mark.parametrize("bad_id", ["short", "bad!chars", "", "x" * 200])
def test_invalid_account_id_rejected(tmp_path, bad_id):
    reg = AccountRegistry(tmp_path / "accounts.json")
    with pytest.raises(ValueError):
        reg.register(bad_id, ED, KEM)


def test_persists_across_instances(tmp_path):
    path = tmp_path / "accounts.json"
    AccountRegistry(path).register(ACCT, ED, KEM, agent_id="agent-1")
    reloaded = AccountRegistry(path)
    assert reloaded.get(ACCT).agent_id == "agent-1"


def test_write_is_atomic_no_tmp_left_behind(tmp_path):
    path = tmp_path / "accounts.json"
    reg = AccountRegistry(path)
    reg.register(ACCT, ED, KEM)
    assert path.exists()
    assert not (tmp_path / "accounts.json.tmp").exists()  # temp renamed away


def test_unknown_account_returns_none(tmp_path):
    reg = AccountRegistry(tmp_path / "accounts.json")
    assert reg.get("nope_0123456789abcdef") is None
    assert reg.agent_for("nope_0123456789abcdef") is None
