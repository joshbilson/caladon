# Contract: Inference Providers & Routing  (`/contracts/inference-providers.md`)

**Status:** FROZEN for Phase 1 (2026-06-02). Changes require maintainer + project-lead sign-off.
**Owners:** E (inference, primary), F (coding-tier consumes), C (runs in-CVM), H (tests).
**Pairs with:** `attestation-evidence.md` (per-response receipt gate), `docs/cost-model.md`
(rates + levers), `docs/oss-reuse-map.md` (litellm). Lives **inside the trust boundary**
(Agent CVM / coding CVM) — providers are reached from inside the TEE, never the gateway.

Implements the provider abstraction (DEPEND-ON **`BerriAI/litellm`**, MIT) + the
cheap-default→frontier **escalation router** + the **in-enclave cache gate** + the
**per-backend attestation gate**.

## 1. Provider registry (config, hot-swappable; query catalog at runtime, never hardcode slugs)
```
provider = {
  id:        string,            # "phala" | "tinfoil" | "near" | "chutes" | "0g"
  base_url:  string,            # OpenAI-compatible endpoint
  regime:    "tdx-onchain" | "sev-sigstore",   # for attestation-evidence.md
  attest_required: bool,        # MUST be true for any T1 (operator≠user) use
  key_ref:   string,            # op:// reference; resolved in-CVM, never logged
}
```
A provider is usable for a request **only if** its per-response receipt verifies
(`attestation-evidence.md §3`). `attest_required=true` backends that fail the receipt are
**rejected, not silently used** (covers cheap ZDR-not-TEE backends — `cost-model.md §2`).

## 2. Model tiers & escalation router
```
model_tier = "trivial" | "cheap" | "frontier"
routing = {
  default:  <cheap model>,        # e.g. deepseek-v3.2 / glm-4.7-flash
  trivial:  <trivial model>,      # e.g. gpt-oss-20b (loop bookkeeping steps)
  frontier: <frontier model>,     # e.g. kimi-k2.6 / deepseek-v4-pro
  escalate_when: [ "task.hard", "low_confidence", "explicit_request" ],
  chat_default: "phala/qwen3.6-35b-a3b-uncensored",   # uncensored chat
}
```
- Coding-tier loops run on `default`/`trivial`; **escalate to `frontier` only** on the
  `escalate_when` triggers. Every escalation is logged (model, reason, tokens, cost) to the
  coding-tier ledger and counts against the spend-cap.
- Chat tier: `chat_default`; BYO uncensored HF weights via Phala GPU TEE on demand.

## 3. Prompt-cache gate (the in-enclave requirement)
- Caching (`input_cache_read`, `cost-model.md`) is enabled for a provider **only if** it
  is proven the KV/prompt cache is held **inside the TEE** (measured config / provider
  attestation states it). Else `cache_enabled=false` for that provider — fall back to
  cheap-default+escalation only. Never cache plaintext context outside the enclave
  (plaintext-exposure row #4).

## 4. Spend-cap & kill switch (coding tier, P4 — interface defined now)
```
budget = { period: "month", hard_cap_aud: 800, target_aud: 500,
           coding_loop_cap_aud: <set per run>, kill_switch: bool }
```
- The router refuses calls that would breach `coding_loop_cap_aud`; on breach → pause loop
  + ESCALATE (`ORCHESTRATOR.md §5`). `kill_switch=true` halts all coding-tier inference.
- Spend tracked per `account_id` + tier; surfaced in `internal progress notes` cost tracker.

## 5. Provider-abstraction guarantees
- One OpenAI-compatible call site (litellm) → any provider; failover across providers of
  the same regime; **no single-vendor hard dependency** (RedPill is one adapter, never the
  trust anchor — `cost-model.md`). Tinfoil + Phala-dstack are the lead/vetting-grade paths.

## 6. Test obligations (H)
- A backend with `attest_required=true` and a failing receipt is **rejected** (not used).
- Escalation router: `trivial`/`cheap`/`frontier` selection per trigger; cost logged.
- Cache gate: caching OFF unless in-enclave proof present.
- Spend-cap: a call projected to breach is refused; kill switch halts inference.
- Failover: provider A down → provider B (same regime) → receipt still verified.
