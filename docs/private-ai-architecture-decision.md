# Private‑AI architecture decision + landscape (2026‑06‑03)

A synthesis of five primary sources, an evaluation against Caladon's design, the new threats they
surface, and the resulting client‑framework decision. Pairs with `the internal status notes` (claims discipline) and
`docs/security/measurements.md`.

## Sources reviewed
1. **securethought.dev — "Private AI in 2025"** (SOTA survey: TEE vs MPC vs FHE vs on‑device; KV‑cache side channels).
2. **Apple — Private Cloud Compute (PCC)** security architecture (the 5 requirements; explicit "E2EE not possible for cloud AI").
3. **Anthropic — Confidential Inference Systems** whitepaper (TEE + attestation + key‑release design principles).
4. **Moxie Marlinspike / Confer** (`confer.to` blogs + Ars Technica): Signal's creator's confidential‑AI product — **TEE + remote attestation + passkey‑derived client encryption**.
5. (Cross‑refs: NVIDIA H100 CC, Proton Lumo, Venice.)

## The verdict (now high‑confidence, unanimous across all five)
- **TEE + remote attestation ("encrypted to an attested enclave boundary") is the ONLY production‑feasible path for big‑model private AI today.** MPC is ~5 min/token (PUMA, LLaMA‑7B); FHE is research‑grade / fixed‑size tasks. Caladon's Phala‑TDX + client‑verified‑attestation + sealed‑channel design is exactly the industry‑convergent architecture (Apple PCC, Anthropic, Confer all chose it).
- **It is NOT E2EE, and saying so is the defensible high ground.** Apple states it outright: *"complete end‑to‑end encryption is not an option"* for cloud AI because the model must access plaintext to compute. Confer is publicly critiqued for its "E2EE" marketing. → Our claims discipline ("attested confidential computing," scoped per tier) is **vindicated and is a differentiator** — we can be more honest than the gold standard's marketing.
- **The only true E2EE is locality:** on‑device, or self‑hosted on hardware the user owns (operator == user). This is the "private mode" — necessarily smaller/uncensored‑local models.

## Three things that are NEW and change our plan

### 1. Passkey (WebAuthn PRF) is the client key‑custody mechanism — and it works in web
Confer's exact code derives a 32‑byte key from a passkey via the WebAuthn **PRF extension**
(`navigator.credentials.get({publicKey:{… extensions:{prf:{eval:{first: salt}}}}})` → `prf.results.first`).
The private key lives in the **Secure Enclave / TPM / Titan**, gated by Face ID/Touch ID, never exposed to JS.
→ **This removes the "only native can do hardware key custody" objection** — a web client gets hardware‑backed
custody too. Native on macOS/iOS/Android; Windows needs a third‑party authenticator; Linux via an extension.
**Decision:** adopt passkey‑PRF custody (Confer's pattern), alongside the Mullvad seed (seed = sovereign/portable
recovery; passkey = easy default, hardware‑backed). A passkey can wrap the seed.

### 2. Apple PCC's five requirements = our security north‑star + gap analysis
| PCC requirement | Caladon today | Gap |
|---|---|---|
| **Stateless computation** (no logs/retention) | `logging:none`, no transcript persistence in v1 | ~met for v1; re‑audit when Letta/RAG land |
| **Enforceable (not policy) guarantees** | compose_hash measured; TLS terminates in‑CVM (dstack‑ingress) | ~met |
| **No privileged runtime access** | dstack CVM; **deploy injects an SSH key** | **GAP** — verify/eliminate operator break‑glass shell on the prod CVM |
| **Non‑targetability** | none — relay sees client IP, can route | **GAP** — add OHTTP‑style relay / IP hiding / single‑use creds (advanced, later) |
| **Verifiable transparency** | `measurements.md` (dev‑pinned), reproducible‑build goal | **GAP** — build an append‑only PUBLIC transparency log of measurements + publish images (Apple + Confer both do this) |
We pass ~2/5 cleanly; the three gaps are the concrete roadmap to "Signal/PCC‑grade."

### 3. KV‑cache / prefix‑cache side channel (PROMPTPEEK, NDSS 2025) — a real new threat
Multi‑tenant **KV‑cache sharing / prefix caching** in vLLM/SGLang‑style serving can enable **cross‑tenant prompt
reconstruction.** Our inference runs on **RedPill** (multi‑tenant). **Action:** (a) confirm with RedPill/Phala whether
prefix caching is per‑tenant/disabled; (b) disclose in the threat model if cross‑tenant; (c) for our future BYO‑vLLM
CVM, enforce per‑tenant KV isolation / no cross‑tenant prefix reuse. Add to `plaintext-exposure-map`.

## Competitive landscape + our niche
- **Confer** (Moxie): TEE + passkey + attestation, **standard/aligned models**, freemium $35/mo, web client (native passkey support).
- **Proton Lumo:** Proton‑crypto E2EE‑ish, aligned models.
- **Venice:** uncensored but **local‑only** (no confidential cloud).
- **Caladon's niche (defensible):** **fully OSS + self‑hostable + UNCENSORED models (attested confidential CLOUD, not just local) + user‑sovereign (seed *or* passkey, bring‑your‑own‑VPS).** No one fills the uncensored‑confidential‑cloud + self‑host + OSS quadrant.

## Client‑framework decision (stable, evidence‑backed)
**Fork LibreChat (MIT, active) now to go live fast; ship it as an INSTALLED, signed, reproducible build
(Capacitor/Tauri) with passkey‑PRF custody + our attested gateway + WASM attestation; native Swift continues in
parallel; both share ONE Rust trust‑core (compiled to WASM for the web fork + a UniFFI xcframework for Swift).**
This is precisely what Confer (the gold standard) does — web client + passkeys + TEE — adapted to our OSS/uncensored
niche. The PWA is a clearly‑labeled lower‑trust "access anywhere" tier (QR‑granted ephemeral sessions from the
trusted installed app). Rationale + the rejected alternatives: this doc + chat log 2026‑06‑03.

**Honest claims (unchanged):** attested confidential computing, NOT E2EE; the installed build (not the PWA) carries
the verifiable‑trust claim; on‑device/self‑host is the only true‑E2EE "private mode."
