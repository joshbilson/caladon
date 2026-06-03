# OSS Reuse Map — Fork / Depend / Build

> **Licensing note (current):** Caladon ships under **Apache-2.0** throughout. Any
> AGPL/GPL/source-available items discussed below were evaluated during research and are
> **NOT bundled** — see `NOTICE` / `THIRD_PARTY_LICENSES.md` for what actually ships.


**Created:** 2026-06-02 (Sprint 1). **Source:** deep-research harness (105 agents, 23
primary sources, 114 claims → 25 adversarially verified, 22 confirmed / 3 refuted) +
**direct maintainer verification of the attestation-verifier keystone** (the research
flagged it unverified). Confidence is marked per row; treat unverified rows as leads.

> **Headline:** the iOS/macOS **attestation verifier — the keystone we feared was
> "build from scratch" — is mostly DEPEND + glue.** Both regimes have native-Swift
> starting points that already exist (`dcap-qvl-swift`, `tinfoil-swift`). This
> materially de-risks Gate 3.

---

## (a) Native Apple client + multiplatform sync

| Candidate | License | Platforms | Activity | Verdict | Why |
|---|---|---|---|---|---|
| **gluonfield/enchanted** | Apache-2.0 | iOS+macOS+visionOS, 100% Swift, **one codebase** | stale (v1.7.0, ~May 2024) | **FORK (UI shell)** | Cleanest multiplatform SwiftUI shell. Rip out the Ollama networking (`OllamaService`/OllamaKit, hits `/api/tags`) and replace with our attested OpenAI-compatible client. ✅ verified 3-0 |
| **alfianlosari/ChatGPTSwiftUI** | MIT | iOS/macOS/watchOS/tvOS + real `Shared/` folder | stale (~Apr 2024), solo | **LEARN-FROM** | Best reference for the shared-codebase streaming-chat pattern (ChatGPTAPI SSE parser, cross-platform ViewModel). ✅ 3-0 |
| **CherryHQ/hanlin-ai** (Cherry Studio iOS) | MIT | iOS only (no macOS target) | **active** (May 2026), solo | **LEARN-FROM** | Best reference for the multi-provider abstraction (OpenAI-compatible switch across 20+ providers, tool calling, history). ✅ 3-0 (iOS-only ✅, abstraction 2-1) |
| mainframecomputer/fullmoon-ios | MIT | iPhone/iPad/Mac | stale (May 2025) | **SKIP** (learn-from for on-device) | On-device only (MLX), no remote inference. ✅ 3-0 |
| bipark/swift_llm_bridge | **GPL-3.0** | iOS+macOS | low maturity (69★) | **SKIP** | Copyleft would force GPL on our client. ✅ 3-0 |

**Plan:** **FORK Enchanted** for the shell; graft the streaming pattern from
ChatGPTSwiftUI and the provider-switch shape from hanlin-ai. All are stale/solo, so we
own it after forking — fine for a shell, not a dependency.

## (b) Agentic memory backend
Brief mandates **Letta** (already integrated). Research surfaced `letta-ai/letta`,
`mem0ai/mem0`, `getzep/zep` as sources but **did not adversarially verify footprint/fit**
(coverage gap). **Verdict: DEPEND-ON Letta**, run in the CVM (decided). *Open item:*
confirm Letta's RAM/CPU footprint fits a small TDX CVM on budget; re-evaluate mem0/Zep
only if Letta is too heavy. *(unverified — needs a Phase-1 footprint test.)*

## (c) Attestation verifier — THE KEYSTONE (maintainer-verified)

| Candidate | License | What it does | Maturity | Verdict |
|---|---|---|---|---|
| **Phala-Network/dcap-qvl-swift** | **MIT** | Native **Intel TDX/SGX DCAP quote verification** for iOS/macOS (Rust core via UniFFI xcframework); fetches PCCS collateral → TCB + advisory IDs | immature (3 commits, v0.6.0, auto-gen from `dcap-qvl`) | **DEPEND-ON** (TDX regime core) |
| **tinfoilsh/tinfoil-swift** | **AGPL-3.0** ⚠️ | Native iOS17+/macOS12+ **fail-closed enclave attestation (SEV-SNP/TDX) + Sigstore code-integrity + cert-pinning**, OpenAI-compatible drop-in | **active** (v0.5.3, 25 releases, May 2026) | **DEPEND-ON / FORK** (Tinfoil regime), pending AGPL decision |
| Dstack-TEE/dstack, tinfoilsh/tinfoil-go | Apache/MIT | Go/Rust references | active | **LEARN-FROM** (port logic) |

**Plan:** the verifier is **DEPEND + glue**, not build-from-scratch:
- **TDX/Phala regime:** depend on `dcap-qvl-swift` (MIT) for quote→Intel-root; **BUILD
  the dstack glue** — `compose_hash`→on-chain registry, RTMR/`event_log` reconstruction,
  **NVIDIA GPU-CC attestation** (out of dcap-qvl scope), channel binding (`attestation.md
  §3`), measurement pinning (§6). Vet the library's immaturity before trusting it.
- **SEV-SNP+Sigstore regime (Tinfoil):** `tinfoil-swift` does the whole job (attest +
  OpenAI client) — **but it's AGPL-3.0** (App Store + AGPL is contentious; our project is
  open-source so it may be acceptable). **Decision needed:** accept AGPL (depend/fork) or
  re-implement the verification approach from its public source under our license.
- This is the concrete shape of contract **A1 (multi-regime)**: two adapters, two
  starting libraries.

## (d) Inference provider abstraction

| Candidate | License | Verdict | Why |
|---|---|---|---|
| **BerriAI/litellm** | MIT | **DEPEND-ON** (server-side, in the CVM/gateway) | Mature OpenAI-compatible proxy across 100+ providers; gives the multi-provider switch + the escalation router hook (`docs/cost-model.md`) without us writing it. Python — fits the gateway/CVM. |
| RedPill / Phala SDK | — | **DEPEND-ON** (one adapter) | The attested endpoint we verified in the spike. |

**Plan:** **DEPEND-ON litellm** as the provider-abstraction + escalation/caching layer
**inside** the trust boundary (gateway/CVM); each provider is an adapter gated by the
per-response attestation check.

## (e) Seed-identity / onboarding + multi-device sync (research's strongest area)

| Pattern | Source | License | Verdict | Reusable bit |
|---|---|---|---|---|
| **Protected Symmetric Key envelope** | Bitwarden white-paper | (doc) | **LEARN-FROM** | A data key is CSPRNG-generated, **wrapped** by a key stretched from the secret, stored server-side as ciphertext, synced back, unwrapped locally → maps directly to "second device from one seed." ✅ 3-0 |
| **3-tier client-held key hierarchy** | Ente architecture | AGPL (pattern only) | **LEARN-FROM** | libsodium `crypto_pwhash` Argon2id (SENSITIVE) → KEK never leaves device → wraps a 256-bit masterKey. *Caveat: Ente's input is a low-entropy password; we have a high-entropy seed (simpler). Their specific secondary-device flow was REFUTED — use the wrapping hierarchy only.* ✅ 3-0 |
| **Per-device sub-ratchet (fan-out)** | Signal **Sesame** | (spec) | **LEARN-FROM (concept)** | Separate Double-Ratchet session per device, per-device fan-out, no shared group key; per-user vs per-device identity choice. *"Directly reusable architecture" REFUTED — conceptual reference.* ✅ 3-0 |
| **Ratcheted Dynamic Multicast (RDM)** | IACR 2019/1363 (ACNS'20) | (paper) | **LEARN-FROM (advanced)** | Privacy-superior to Sesame: broadcasts ratchet secret over multicast, **hides device count/identity** (metadata-minimizing), FS + healing, dynamic add/revoke, no master device. Academic → from-scratch + security review if pursued. ✅ 3-0 |
| libsodium | — | ISC | **DEPEND-ON** | The crypto primitives (Argon2id, XChaCha20-Poly1305, X25519) per `identity-envelope.md §1`. |

**Plan:** **BUILD** the seed onboarding + key derivation ourselves (it's small and is the
core IP), **modeled on Bitwarden's wrapped-key envelope + Ente's hierarchy**, on
**libsodium**. Multi-device sync = the seed re-derives all keys on each device (simplest);
the **multi-device forward-secret ratchet** is the genuinely hard part — start from the
Sesame per-device-fan-out concept, consider RDM only if metadata-hiding of device count
becomes a requirement. (Feeds the `identity-envelope.md` multi-device amendment.)

---

## Master reuse map

| Component | Decision | What |
|---|---|---|
| Native Apple client shell | **FORK** | `gluonfield/enchanted` (Apache-2.0) — strip Ollama |
| Streaming-chat + shared-codebase pattern | **LEARN-FROM** | `ChatGPTSwiftUI`, `hanlin-ai` |
| TDX attestation core | **DEPEND-ON** | `Phala-Network/dcap-qvl-swift` (MIT) + build dstack/GPU/binding glue |
| Tinfoil (SEV+Sigstore) attestation + client | **DEPEND-ON / FORK** | `tinfoilsh/tinfoil-swift` (AGPL — decide) |
| Inference provider abstraction + escalation/caching | **DEPEND-ON** | `BerriAI/litellm` (MIT), in-CVM |
| Agentic memory | **DEPEND-ON** | `Letta` in the CVM (footprint TBD) |
| Crypto primitives | **DEPEND-ON** | libsodium |
| Seed identity + onboarding | **BUILD** | modeled on Bitwarden PSK + Ente hierarchy |
| Multi-device FS ratchet | **BUILD** | concept from Sesame; RDM optional |
| Whole confidential-AI product | **SKIP as fork** | `Maple` (Tauri/Nitro) — learn-from only |

## Coverage honesty (from the research caveats)
- **Verified well:** native Apple clients, seed-identity/multi-device patterns.
- **Orchestrator-verified after the run:** the three keystone leads above (c).
- **NOT independently verified (leads only):** Letta/mem0/Zep footprint; whether any
  whole-product is fork-worthy beyond Maple. Treat (b) as needing a Phase-1 footprint test.
