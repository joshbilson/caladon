"""Inference policy: tier escalation, per-backend attestation gate, cache gate, spend-cap.

Pure, dependency-free logic (contracts/inference-providers.md §1-§4). The litellm-backed
provider calls layer on top of these decisions in a later iteration.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable

from swifty_inference.models import Budget, Provider, Regime, RoutingConfig, Tier


class BudgetExceeded(Exception):
    """Raised when a call would breach the coding-loop spend cap (or the kill switch is on)."""


class NoUsableProvider(Exception):
    """Raised when no provider of the requested regime passes the attestation/availability gate."""


def select_tier(triggers: Iterable[str], config: RoutingConfig) -> Tier:
    """Escalation precedence: any escalate_when trigger -> FRONTIER; else a 'trivial' hint
    -> TRIVIAL; else the CHEAP default."""
    trig = set(triggers)
    if trig & config.escalate_when:
        return Tier.FRONTIER
    if "trivial" in trig:
        return Tier.TRIVIAL
    return Tier.CHEAP


def select_model(triggers: Iterable[str], config: RoutingConfig) -> str:
    return config.model_for(select_tier(triggers, config))


def provider_usable(provider: Provider, receipt_ok: bool) -> bool:
    """Usable only if available AND, for any hosted (non-NONE) regime, the per-response
    receipt verified. The gate keys on the REGIME, not the `attest_required` flag, so no
    single field value can silently disable attestation (a hosted provider can't even be
    constructed with attest_required=False — see Provider.__post_init__). T0 self-host
    (Regime.NONE, operator == user) needs no receipt. (inference-providers.md §1.)"""
    if not provider.available:
        return False
    if provider.regime is Regime.NONE:
        return True
    return receipt_ok


def cache_allowed(provider: Provider) -> bool:
    """Caching only if the provider's prompt/KV cache is proven in-enclave; else it is a
    plaintext-exposure vector (plaintext-exposure map row #4)."""
    return provider.cache_in_enclave


def choose_provider(
    providers: Iterable[Provider],
    regime: Regime,
    receipt_check: Callable[[Provider], bool],
) -> Provider:
    """Failover across providers of the regime in order; return the first usable one (the
    attestation gate is enforced via receipt_check). Raises NoUsableProvider if none."""
    for provider in providers:
        if provider.regime == regime and provider_usable(provider, receipt_check(provider)):
            return provider
    raise NoUsableProvider(f"no usable provider for regime {regime.value}")


class SpendGuard:
    """Enforces the coding-loop spend cap + kill switch (inference-providers.md §4).

    Use `reserve()` to atomically check-and-debit before a call — this is the hard ceiling
    (no check/record gap where two callers each pass and then both spend). `check()` is a
    non-committing read; `record()` debits a known actual cost (e.g. true tokens after a
    call). All three are guarded by a lock so the cap holds under concurrent callers."""

    def __init__(self, budget: Budget) -> None:
        self.budget = budget
        self._lock = threading.Lock()

    def _would_exceed(self, est_aud: float) -> None:
        if self.budget.kill_switch:
            raise BudgetExceeded("kill switch engaged")
        if self.budget.spent_aud + est_aud > self.budget.coding_loop_cap_aud:
            raise BudgetExceeded("coding-loop spend cap reached")

    def check(self, est_aud: float) -> None:
        with self._lock:
            self._would_exceed(est_aud)

    def reserve(self, est_aud: float) -> None:
        """Atomic check + debit. Raises BudgetExceeded (and debits nothing) if it would breach."""
        with self._lock:
            self._would_exceed(est_aud)
            self.budget.spent_aud += est_aud

    def record(self, aud: float) -> None:
        with self._lock:
            self.budget.spent_aud += aud

    def release(self, aud: float) -> None:
        """Refund a previously-reserved amount (floored at 0). Used to roll back an
        estimate when a call fails or to reconcile against the true cost."""
        with self._lock:
            self.budget.spent_aud = max(0.0, self.budget.spent_aud - aud)
