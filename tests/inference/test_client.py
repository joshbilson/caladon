"""Tests for the inference client routing/failover/attestation-gate (no litellm, no spend)."""

from __future__ import annotations

import pytest

from swifty_inference.client import InferenceClient
from swifty_inference.models import Budget, Provider, Regime, RoutingConfig, Tier
from swifty_inference.policy import BudgetExceeded, NoUsableProvider, SpendGuard

CONFIG = RoutingConfig(
    models={Tier.TRIVIAL: "trivial-m", Tier.CHEAP: "cheap-m", Tier.FRONTIER: "frontier-m"}
)
MSGS = [{"role": "user", "content": "hi"}]


def _client(providers, *, completion_fn, receipt_verifier=None, budget=None):
    return InferenceClient(
        providers,
        CONFIG,
        SpendGuard(budget or Budget(coding_loop_cap_aud=100.0)),
        completion_fn=completion_fn,
        receipt_verifier=receipt_verifier,
    )


def test_happy_path_returns_result():
    p = Provider("phala", "u", Regime.TDX_ONCHAIN)
    client = _client([p], completion_fn=lambda pr, m, msgs: f"resp-from-{pr.id}", receipt_verifier=lambda pr, r: True)
    out = client.complete(MSGS, regime=Regime.TDX_ONCHAIN)
    assert out.provider.id == "phala"
    assert out.model == "cheap-m"
    assert out.response == "resp-from-phala"


def test_escalation_selects_frontier_model():
    p = Provider("phala", "u", Regime.TDX_ONCHAIN)
    client = _client([p], completion_fn=lambda pr, m, msgs: m, receipt_verifier=lambda pr, r: True)
    out = client.complete(MSGS, regime=Regime.TDX_ONCHAIN, triggers=["task.hard"])
    assert out.model == "frontier-m"
    assert out.response == "frontier-m"


def test_failover_on_failed_receipt():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    b = Provider("b", "u", Regime.TDX_ONCHAIN)
    calls = []

    def comp(pr, m, msgs):
        calls.append(pr.id)
        return f"resp-{pr.id}"

    # a's receipt fails, b's passes -> should fail over to b
    client = _client([a, b], completion_fn=comp, receipt_verifier=lambda pr, r: pr.id == "b")
    out = client.complete(MSGS, regime=Regime.TDX_ONCHAIN)
    assert out.provider.id == "b"
    assert calls == ["a", "b"]  # tried a, failed receipt, then b


def test_all_receipts_fail_raises():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    secret = "SECRET-UNTRUSTED-PAYLOAD"
    client = _client([a], completion_fn=lambda pr, m, msgs: secret, receipt_verifier=lambda pr, r: False)
    with pytest.raises(NoUsableProvider) as exc:
        client.complete(MSGS, regime=Regime.TDX_ONCHAIN)
    # the rejected (untrusted) response must never leak into the raised error
    assert secret not in str(exc.value)


def test_verifier_exception_is_fail_closed():
    """A receipt verifier that raises must be treated as a FAILED receipt (never a pass)."""
    a = Provider("a", "u", Regime.TDX_ONCHAIN)

    def boom(pr, r):
        raise ValueError("malformed receipt")

    client = _client([a], completion_fn=lambda pr, m, msgs: "r", receipt_verifier=boom)
    with pytest.raises(NoUsableProvider):
        client.complete(MSGS, regime=Regime.TDX_ONCHAIN)


def test_spend_refunded_on_total_failure():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    guard = SpendGuard(Budget(coding_loop_cap_aud=100.0))
    client = InferenceClient([a], CONFIG, guard,
                             completion_fn=lambda pr, m, msgs: "r", receipt_verifier=lambda pr, r: False)
    with pytest.raises(NoUsableProvider):
        client.complete(MSGS, regime=Regime.TDX_ONCHAIN, est_cost_aud=10.0)
    assert guard.budget.spent_aud == 0.0  # reservation refunded on failure


def test_failover_on_provider_exception():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    b = Provider("b", "u", Regime.TDX_ONCHAIN)

    def comp(pr, m, msgs):
        if pr.id == "a":
            raise RuntimeError("provider a down")
        return "ok"

    client = _client([a, b], completion_fn=comp, receipt_verifier=lambda pr, r: True)
    out = client.complete(MSGS, regime=Regime.TDX_ONCHAIN)
    assert out.provider.id == "b"


def test_no_provider_for_regime_raises():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    client = _client([a], completion_fn=lambda pr, m, msgs: "r", receipt_verifier=lambda pr, r: True)
    with pytest.raises(NoUsableProvider):
        client.complete(MSGS, regime=Regime.SEV_SIGSTORE)


def test_spend_cap_blocks_before_any_call():
    a = Provider("a", "u", Regime.TDX_ONCHAIN)
    called = []
    client = _client(
        [a],
        completion_fn=lambda pr, m, msgs: called.append(1),
        receipt_verifier=lambda pr, r: True,
        budget=Budget(coding_loop_cap_aud=1.0),
    )
    with pytest.raises(BudgetExceeded):
        client.complete(MSGS, regime=Regime.TDX_ONCHAIN, est_cost_aud=5.0)
    assert called == []  # no provider call when the spend gate trips


def test_t0_self_host_needs_no_receipt():
    p = Provider("local", "http://localhost", Regime.NONE)
    # receipt_verifier returns False, but Regime.NONE bypasses the receipt requirement
    client = _client([p], completion_fn=lambda pr, m, msgs: "local-resp", receipt_verifier=lambda pr, r: False)
    out = client.complete(MSGS, regime=Regime.NONE)
    assert out.response == "local-resp"
