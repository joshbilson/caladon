"""Inference client: routes an OpenAI-compatible chat completion through the policy layer.

Flow (contracts/inference-providers.md): reserve spend -> select model by escalation tier
-> for each available provider of the regime, call it, then verify the PER-RESPONSE
attestation receipt (the receipt arrives WITH the response, so the gate is enforced AFTER
the call); a failing receipt drops the response and fails over to the next provider. T0
(Regime.NONE, operator == user) needs no receipt.

Provider calls go through `completion_fn` (defaults to litellm.completion, imported lazily
so the policy/client is testable without the heavy dep). Tests inject a fake.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from swifty_inference.models import Provider, Regime, RoutingConfig
from swifty_inference.policy import NoUsableProvider, SpendGuard, select_model

CompletionFn = Callable[[Provider, str, Sequence[dict]], Any]
ReceiptVerifier = Callable[[Provider, Any], bool]
CostFn = Callable[[Provider, Any], float]


@dataclass(frozen=True)
class InferenceResult:
    provider: Provider
    model: str
    response: Any


class InferenceClient:
    def __init__(
        self,
        providers: Iterable[Provider],
        config: RoutingConfig,
        spend_guard: SpendGuard,
        *,
        completion_fn: CompletionFn | None = None,
        receipt_verifier: ReceiptVerifier | None = None,
        cost_fn: CostFn | None = None,
    ) -> None:
        self._providers = list(providers)
        self._config = config
        self._guard = spend_guard
        self._completion_fn = completion_fn
        self._verify_receipt: ReceiptVerifier = receipt_verifier or (lambda _p, _r: True)
        # Maps a successful response -> its true AUD cost (e.g. from response.usage), to
        # reconcile against the reserved estimate. Defaults to 0.0 until cost wiring lands.
        self._cost_fn: CostFn = cost_fn or (lambda _p, _r: 0.0)

    def _completion(self) -> CompletionFn:
        if self._completion_fn is not None:
            return self._completion_fn
        try:
            import litellm  # lazy production dep
        except ImportError as exc:  # pragma: no cover - exercised only in prod without dep
            raise RuntimeError("litellm not installed and no completion_fn provided") from exc

        def _call(provider: Provider, model: str, messages: Sequence[dict]) -> Any:
            # key_ref is the already-resolved key (resolved in-CVM); never logged.
            return litellm.completion(
                model=model,
                messages=list(messages),
                api_base=provider.base_url,
                api_key=provider.key_ref or None,
            )

        return _call

    def complete(
        self,
        messages: Sequence[dict],
        *,
        regime: Regime,
        triggers: Iterable[str] = (),
        est_cost_aud: float = 0.0,
    ) -> InferenceResult:
        # Spend gate first (reserve the estimate up front; raises BudgetExceeded). The
        # reservation is reconciled to the true cost on success and refunded on failure,
        # so the cap is a hard ceiling during the call window and accurate afterward.
        self._guard.reserve(est_cost_aud)
        model = select_model(triggers, self._config)
        call = self._completion()
        reconciled = False
        try:
            candidates = [p for p in self._providers if p.regime == regime and p.available]
            if not candidates:
                raise NoUsableProvider(f"no available provider for regime {regime.value}")

            for provider in candidates:
                try:
                    response = call(provider, model, messages)
                except Exception:  # noqa: BLE001 - provider failure -> fail over to next
                    continue
                if self._receipt_ok(provider, response):
                    actual = self._cost_fn(provider, response)
                    self._guard.release(est_cost_aud)
                    self._guard.record(actual)
                    reconciled = True
                    return InferenceResult(provider=provider, model=model, response=response)
                # receipt failed -> drop the (untrusted) response, fail over. Never surface it.
            raise NoUsableProvider("no provider returned a verifiable response")
        finally:
            if not reconciled:
                self._guard.release(est_cost_aud)  # refund the reservation on any failure

    def _receipt_ok(self, provider: Provider, response: Any) -> bool:
        """PER-RESPONSE attestation gate. T0 (Regime.NONE) needs no receipt. For hosted
        regimes the receipt MUST verify; a verifier that RAISES is fail-closed (treated as
        a failed receipt, never a pass)."""
        if provider.regime is Regime.NONE:
            return True
        try:
            return bool(self._verify_receipt(provider, response))
        except Exception:  # noqa: BLE001 - fail-closed: a verifier crash is not a pass
            return False
