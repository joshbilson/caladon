"""Swifty inference policy layer (contracts/inference-providers.md).

Runs INSIDE the trust boundary (Agent CVM / coding CVM) — never the gateway. This package
is the provider-agnostic POLICY core: tier escalation routing, the per-backend attestation
gate, the in-enclave cache gate, and the spend-cap/kill-switch. The actual OpenAI-compatible
calls (DEPEND-ON litellm) are wired on top of this in a later iteration; the policy is kept
dependency-free so it is exhaustively unit-testable.
"""
