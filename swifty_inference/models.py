"""Config models for the inference policy layer (contracts/inference-providers.md §1-§4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Regime(str, Enum):
    TDX_ONCHAIN = "tdx-onchain"   # Phala / RedPill etc.
    SEV_SIGSTORE = "sev-sigstore"  # Tinfoil
    NONE = "none"                  # T0 self-host (operator = user)


class Tier(str, Enum):
    TRIVIAL = "trivial"   # loop bookkeeping steps (e.g. gpt-oss-20b)
    CHEAP = "cheap"       # default (e.g. deepseek-v3.2 / glm-4.7-flash)
    FRONTIER = "frontier"  # bursts (e.g. kimi-k2.6 / deepseek-v4-pro)


@dataclass(frozen=True)
class Provider:
    id: str
    base_url: str
    regime: Regime
    attest_required: bool = True   # MUST be True for any hosted (non-NONE) regime
    cache_in_enclave: bool = False  # enable prompt caching only if proven in-TEE
    available: bool = True
    # Resolved API key (the op:// ref is resolved IN-CVM before constructing Provider).
    # repr=False so the key never lands in a dataclass repr / traceback / log line.
    key_ref: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        # Fail loud on misconfiguration: a hosted (T1) provider can NEVER disable
        # attestation. Only the T0 self-host regime (operator == user) may.
        if self.regime is not Regime.NONE and not self.attest_required:
            raise ValueError("attest_required must be True for a hosted (non-NONE) regime")


@dataclass
class RoutingConfig:
    models: dict[Tier, str]                 # tier -> model slug (query catalog; never hardcode forever)
    chat_default: str = "phala/qwen3.6-35b-a3b-uncensored"
    escalate_when: frozenset[str] = field(
        default_factory=lambda: frozenset({"task.hard", "low_confidence", "explicit_request"})
    )

    def model_for(self, tier: Tier) -> str:
        try:
            return self.models[tier]
        except KeyError:
            raise ValueError(f"no model configured for tier {tier.value!r}") from None


@dataclass
class Budget:
    hard_cap_aud: float = 800.0
    target_aud: float = 500.0
    coding_loop_cap_aud: float = 200.0
    spent_aud: float = 0.0
    kill_switch: bool = False
