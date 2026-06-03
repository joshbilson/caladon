# Caladon — Cost Model & Optimization (AUD)

**Created:** 2026-06-02 (Sprint 1). **Source:** live Phala `instance-types` + the live
RedPill catalog (`api.redpill.ai/v1/models`) pulled during the Sprint-1 spike, plus the
architecture handoff's volume assumptions. **FX:** A$1.39 / US$1. **24×7 = 730 hr/mo;
on-demand ≈ 6 hr/day = 180 hr/mo. Two users (Josh + Blake).**

> Supersedes the architecture handoff's cost section in one respect: **there is no free
> CVM tier** (smallest TDX = $0.058/hr). The handoff's "~$0 free CVM" assumption is stale.

---

## 1. Unit costs (verified)

### Confidential compute (Phala TDX CVM)
| Instance | Spec | $/hr | 24×7 A$/mo | On-demand 6h/day A$/mo |
|---|---|---|---|---|
| `tdx.small` | 1 vCPU / 2 GB | 0.058 | 59 | 15 |
| `tdx.medium` | 2 vCPU / 4 GB | 0.116 | 118 | 29 |
| `tdx.large` | 4 vCPU / 8 GB | 0.232 | 235 | 58 |
| `tdx.xlarge` | 8 vCPU / 16 GB | 0.464 | 471 | 116 |
| GPU `h200.small` | H200 141 GB | 4.80 | **4,871** | ~200 (1h/day) |

### Confidential inference (live RedPill catalog, USD per 1M tokens)
Price range across TEE-backed models is ~27×. `input_cache_read` = cached-input rate.

| Model | In | Out | Cache-read in | TEE backend(s) | Role |
|---|---|---|---|---|---|
| `gpt-oss-20b` | 0.04 | 0.15 | — | phala | trivial loop steps |
| `glm-4.7-flash` | 0.10 | 0.43 | — | phala | cheap default |
| `gpt-oss-120b` | 0.15 | 0.60 | — | near-ai, secretai | mid |
| `deepseek-v4-flash` | 0.20 | 0.50 | — | 0g | cheap coder |
| `qwen3.6-35b-a3b-uncensored` | 0.30 | 1.50 | — | phala | **chat (uncensored)** |
| `deepseek-v3.2` | 0.32 | 0.48 | — | chutes | **cheap coder default** |
| `kimi-k2.5` | 0.60 | 3.00 | 0.22 | chutes | coding |
| `kimi-k2.6` | 1.09 | 4.60 | 0.37 | chutes, tinfoil | frontier coding |
| `glm-5.1` | 1.21 | 4.20 | — | 0g, chutes, near-ai, tinfoil | frontier |
| `deepseek-v4-pro` | 1.50 | 5.25 | — | 0g, tinfoil | frontier |

TEE backends seen in catalog: **phala, tinfoil, chutes, near-ai, 0g, secretai** (router
spans 6 → strong provider diversity / no-lock-in hedge).

---

## 2. Cost-down levers (coding tier dominates the bill; base = 100M in / 25M out)

| Lever | Mechanism | Before | After | Saving | Box risk |
|---|---|---|---|---|---|
| **Cheap default + escalate** | run loops on `deepseek-v3.2`/`glm-4.7-flash`; burst to Kimi/DeepSeek-v4-pro only on hard steps | A$311 (all-Kimi) | ~A$60–110 (80/20 mix) | 65–80% | none — all TEE + open-weight |
| **Prompt caching** | `input_cache_read` on repeated loop context | input ~A$152 | ~A$80 @70% hit | ~45% of input | ⚠️ cache MUST live in-enclave (else plaintext-exposure row #4) |
| **Both** | — | A$311 | ~A$50–90 | ~75% | as above |
| CVM right-size + on-demand chat | run per-user chat CVMs on-demand, not 24×7; dstack portable to spot/raw-cloud TDX | — | — | secondary | none |
| GPU ≈ A$0 in practice | catalog already serves uncensored at $0.30/M → self-host GPU rarely needed | — | ~A$0 | secondary | none |

### Two enforcement caveats (handled by the multi-regime verifier + the team)
1. **Cheapest ≠ always attested.** Some cheap decentralized backends (`chutes`, `0g`) may
   be zero-data-retention *policy*, not hardware-TEE. **Every backend must pass the
   per-response attestation receipt check** (contracts A1/A2) or be rejected.
2. **Caching = a plaintext cache.** Confirm the provider's KV/prompt cache is held
   **inside the TEE** before enabling; otherwise forgo caching and rely on
   cheap-default+escalation alone (still ~65%).

---

## 3. Monthly totals (AUD)

| Config | Before opt | After (cache + escalation) | ≤ A$500 |
|---|---|---|---|
| **Lean** (small on-demand chat CVMs, modest coding CVM) | A$372 | **≈ A$242** | ✅✅ |
| **Balanced (recommended)** (large on-demand chat CVMs, occasional GPU) | A$497 | **≈ A$384** | ✅ headroom |
| Comfort (chat CVMs 24×7) | A$1,079 | ≈ A$700 | ❌ (under A$1,400 cap) |

**Recommended target: Config-2-optimized ≈ A$385/mo**, guardrails = (a) on-demand chat
CVMs, (b) cheap-default + escalation router, (c) in-enclave caching, (d) **hard coding
spend-cap** (the single biggest controllable line; uncapped 3× volume ≈ A$930/mo).

---

## 4. Phase-1 build implications (the team + F)
- **Escalation router**: cheap-default model → frontier only on hard steps (spend-cap aware).
- **Cache-confidentiality check**: gate caching on proof the cache is in-enclave.
- **Per-backend attestation gate**: a model is only usable if its backend emits a
  verifiable receipt (ties to contract A1 multi-regime verifier).
- **Spend-cap + kill switch** on the coding loops from day one.
