"""Tests for the inference policy layer (contracts/inference-providers.md §1-§4)."""

from __future__ import annotations

import pytest

from swifty_inference.models import Budget, Provider, Regime, RoutingConfig, Tier
from swifty_inference.policy import (
    BudgetExceeded,
    NoUsableProvider,
    SpendGuard,
    cache_allowed,
    choose_provider,
    provider_usable,
    select_model,
    select_tier,
)

CONFIG = RoutingConfig(
    models={
        Tier.TRIVIAL: "phala/gpt-oss-20b",
        Tier.CHEAP: "phala/deepseek-v3.2",
        Tier.FRONTIER: "phala/kimi-k2.6",
    }
)


# --- escalation routing ---------------------------------------------------

def test_default_is_cheap():
    assert select_tier([], CONFIG) is Tier.CHEAP
    assert select_model([], CONFIG) == "phala/deepseek-v3.2"


def test_trivial_hint_routes_trivial():
    assert select_tier(["trivial"], CONFIG) is Tier.TRIVIAL


@pytest.mark.parametrize("trigger", ["task.hard", "low_confidence", "explicit_request"])
def test_escalation_triggers_frontier(trigger):
    assert select_tier([trigger], CONFIG) is Tier.FRONTIER
    assert select_model([trigger], CONFIG) == "phala/kimi-k2.6"


def test_escalation_takes_precedence_over_trivial():
    assert select_tier(["trivial", "task.hard"], CONFIG) is Tier.FRONTIER


# --- attestation gate -----------------------------------------------------

def test_attested_provider_requires_receipt():
    p = Provider("phala", "https://api", Regime.TDX_ONCHAIN, attest_required=True)
    assert provider_usable(p, receipt_ok=True) is True
    assert provider_usable(p, receipt_ok=False) is False


def test_self_host_t0_needs_no_receipt():
    p = Provider("local", "http://localhost", Regime.NONE)
    assert provider_usable(p, receipt_ok=False) is True


def test_unavailable_provider_unusable():
    p = Provider("phala", "https://api", Regime.TDX_ONCHAIN, available=False)
    assert provider_usable(p, receipt_ok=True) is False


def test_hosted_provider_cannot_disable_attestation():
    """A non-NONE regime must fail loud at construction if attest_required is False —
    no single field can silently bypass the attestation gate."""
    with pytest.raises(ValueError):
        Provider("bad", "https://api", Regime.TDX_ONCHAIN, attest_required=False)
    with pytest.raises(ValueError):
        Provider("bad", "https://api", Regime.SEV_SIGSTORE, attest_required=False)


# --- cache gate -----------------------------------------------------------

def test_cache_only_when_in_enclave():
    assert cache_allowed(Provider("p", "u", Regime.TDX_ONCHAIN, cache_in_enclave=True)) is True
    assert cache_allowed(Provider("p", "u", Regime.TDX_ONCHAIN, cache_in_enclave=False)) is False


# --- failover -------------------------------------------------------------

def test_choose_provider_failover_skips_unusable():
    a = Provider("a", "u", Regime.TDX_ONCHAIN, available=False)   # down
    b = Provider("b", "u", Regime.TDX_ONCHAIN)                    # up, receipt ok
    chosen = choose_provider([a, b], Regime.TDX_ONCHAIN, receipt_check=lambda p: True)
    assert chosen.id == "b"


def test_choose_provider_skips_failed_attestation():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)  # receipt will fail
    b = Provider("b", "u", Regime.TDX_ONCHAIN)  # receipt ok
    chosen = choose_provider([a, b], Regime.TDX_ONCHAIN, receipt_check=lambda p: p.id == "b")
    assert chosen.id == "b"


def test_choose_provider_none_raises():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    with pytest.raises(NoUsableProvider):
        choose_provider([a], Regime.TDX_ONCHAIN, receipt_check=lambda p: False)


# --- spend cap ------------------------------------------------------------

def test_spend_guard_under_cap_ok():
    g = SpendGuard(Budget(coding_loop_cap_aud=10.0))
    g.check(5.0)
    g.record(5.0)
    g.check(4.0)  # 5 + 4 <= 10


def test_spend_guard_over_cap_raises():
    g = SpendGuard(Budget(coding_loop_cap_aud=10.0, spent_aud=8.0))
    with pytest.raises(BudgetExceeded):
        g.check(5.0)  # 8 + 5 > 10


def test_kill_switch_blocks_all():
    g = SpendGuard(Budget(kill_switch=True))
    with pytest.raises(BudgetExceeded):
        g.check(0.0)


def test_spend_guard_at_exact_cap_is_allowed():
    g = SpendGuard(Budget(coding_loop_cap_aud=10.0, spent_aud=6.0))
    g.check(4.0)  # 6 + 4 == 10 must NOT raise


def test_reserve_is_atomic_and_does_not_debit_on_breach():
    g = SpendGuard(Budget(coding_loop_cap_aud=10.0))
    g.reserve(7.0)
    assert g.budget.spent_aud == 7.0
    with pytest.raises(BudgetExceeded):
        g.reserve(5.0)  # 7 + 5 > 10
    assert g.budget.spent_aud == 7.0  # breach debited nothing


def test_select_model_missing_tier_raises_valueerror():
    partial = RoutingConfig(models={Tier.CHEAP: "x", Tier.FRONTIER: "y"})  # no TRIVIAL
    with pytest.raises(ValueError):
        select_model(["trivial"], partial)
