# Caladon — Plaintext-Exposure Map (living build-requirements table)

**Status:** LIVING acceptance bar — **refreshed 2026-06-03 (an earlier iteration) to the built state.**
**This table IS the Phase-1 acceptance bar (BUILD-PLAN Gate 1: "no plaintext on any trusted
host; receipt verifies").** Each row is a build requirement for the confidential target, not
optional hardening — **if a control fails, the defensible claim is false.**
**Owner:** the team. **Derived from:** `the internal status notes` §"Plaintext-exposure inventory";
`MASTER-HANDOVER §5`; `contracts/attestation.md`; `contracts/identity-envelope.md`.

> A reviewer will demand this map. It enumerates **every point plaintext exists**
> and the control that must hold there. Owning agents are from the BUILD-PLAN
> sub-agent topology (§2): A Crypto/Identity · B Gateway · C CVM/Infra · D iOS ·
> E Inference · F Coding-tier · G Security/Docs · H Test/QA.

> **Built state (2026-06-03):** the confidential backbone is implemented in code — rows 1–5
> have their controls built + unit/parity-tested, a real gateway ran in an attested TDX CVM
> (an earlier iteration), and the client verifier parses real TDX quotes (dcap-qvl, an earlier iteration). What is NOT
> yet done: the **live full-backbone e2e** (gateway+Letta+Postgres+Ollama all up in one CVM
> with a real round-trip + per-response inference receipt) and the **client's live attestation
> connect** (async PCS-collateral fetch). So a deployment is confidential-by-construction in
> code + proven attestable on real hardware, but the live end-to-end proof + production
> measurement-pinning (Gate 5) remain. Do NOT call a *running* system "confidential" until its
> measured CVM is pinned and the live receipt verifies. The "Built state" column tracks this.

---

## The six exposure points

| # | Where plaintext exists | Required control (fail = claim false) | Owning agent | Gate that closes it | Built state (2026-06-03) | Target state |
|---|---|---|---|---|---|---|
| **1** | **Gateway** (FastAPI; on Netcup today) | **CRITICAL.** Gateway must NOT see plaintext: run it inside a CVM **or** make it a pure ciphertext router (routes `envelope` blobs by `account_id`, `id-env §4`). **TLS must terminate *inside* the attested boundary** — a dstack-gateway CVM whose cert carries its TDX quote (`attestation §3`), not a plain proxy. | **B** (gateway), with **C** (TLS-in-CVM) | Gate 1 | ✅ **built**: seed-auth ciphertext router — `/v1/messages` opaque envelopes (an earlier iteration), `/v1/session` WMK delivery (an earlier iteration), `/v1/chat` sealed round-trip (an earlier iteration); cvm-mode in-CVM compose (an earlier iteration); a real gateway ran in an attested TDX CVM (an earlier iteration). ⏳ live TLS-in-CVM full e2e + measurement-pin pending | Ciphertext-only router / in-CVM; TLS terminates inside the attested boundary; account-ID auth, no device tokens |
| **2** | **Letta memory at rest** (Postgres / pgvector) | Postgres runs **inside the CVM** with disk encryption bound to the **attestation-released key** (dstack KMS app-key, `attestation §7`). Plaintext at rest on a trusted host is a leak. | **C** (CVM/Infra) | Gate 1 | ✅ **built (compose)**: Postgres runs in-CVM on a dstack-encrypted volume + `logging:none` (`infra/cvm/dstack-compose.yml`, an earlier iteration). ⏳ live full-backbone deploy pending | Postgres in-CVM, disk-encrypted under the attestation-released key |
| **3** | **Embeddings** (`nomic-embed-text` via Ollama) | Embeddings are computed from plaintext and are **invertible** → the embedding step runs **inside the CVM**, never on a trusted host. | **C** (CVM/Infra) | Gate 1 | ✅ **built (compose)**: Ollama embeddings in-CVM, no host port, `logging:none` (an earlier iteration). ⏳ live full-backbone deploy pending | Embedding compute inside the CVM only |
| **4** | **Inference enclave** (Phala/Redpill; Tinfoil/NEAR fallback) | Protected by the TEE — but **verify the receipt**: `x-phala-no-log == true`, receipt signature chains to TDX root + on-chain entry, `compose-hash`/`app-id` match the **pinned inference build** + requested model slug; re-checked **per response** (`attestation §4.9`). Prefer **BYO-weights CVM** or a **transparency-log** provider (Tinfoil/Sigstore) over an unrebuildable hosted slug. | **E** (Inference), with **D** (client re-verifies receipt) | Gate 1 | ⚠️ **partial**: the client verifier is built + fail-closed (keystone an earlier iteration) and the REAL dcap-qvl verifier parses real TDX quotes to the Intel root (an earlier iteration CLI, an earlier iteration in-Swift); the `/v1/chat` `receipt` event is an honest "pending-attested-inference" marker (an earlier iteration). ⏳ live per-response inference-receipt wiring + client async PCS-collateral connect pending | Attested per-token inference; receipt verified per response; provider behind one config switch |
| **5** | **Logs** (gateway / Letta / model server) | **Fail-closed no-logging** of prompts/responses **everywhere** — the #1 accidental leak vector. Audit each component individually; do not assume. Verify `x-phala-no-log` on the inference path. | **C** (infra/relay) + **E** (inference) + **B** (gateway); **H** tests it | Gate 1 (verified in prod at Gate 5) | ✅ **built (design)**: `logging:none` on every data-touching service AND the gateway in the CVM compose (an earlier iteration); the gateway error paths carry no plaintext (an earlier iteration review); leak/claims-lint CI guard. ⏳ runtime no-logs verification in production (Gate 5) pending | RAM-only / no-logs everywhere, audited and test-enforced |
| **6** | **On-device / generative UI** | On-device plaintext is **inherent and acceptable**. **But** generative UI is a HARD GATE: model-emitted HTML/SVG is attacker-influenced. WKWebView sandbox — **CSP denying all origins, no JS bridge to native, no Keychain access, strict tag allowlist** — else it exfiltrates decrypted on-device data, bypassing all server-side TEE work. Seed in Secure Enclave (`id-env §2`). | **D** (iOS), with **G** (sandbox review); **H** tests | Gate 3 (WKWebView sandbox promoted to a hard gate) | ⚠️ **partial**: seed stored in the Keychain device-only + non-synced + backup-excluded (`KeychainSeedStore`, an earlier iteration; SE-*wrapping* a documented follow-up). The app is native SwiftUI with **no generative HTML/WKWebView yet**, so the sandbox hard-gate is N/A until generative UI is added — when it is, the CSP/no-bridge/allowlist sandbox is mandatory | Hard-sandboxed WKWebView; seed Secure-Enclave-wrapped; ephemeral per-session keys |

---

## Notes

- **Rows 1–3 are the Phase-1 core:** "no trusted host ever sees plaintext"
  (`MASTER-HANDOVER §5`, BUILD-PLAN Phase 1 / Gate 1). They are gated together.
- **Row 4** is protected by the TEE *plus* the client-side receipt re-check; the
  inference enclave is the one place plaintext exists off-device besides the Agent
  CVM, and only inside the attested boundary.
- **Row 5** is closed in design at Gate 1 but **verified in production at Gate 5**
  (`MASTER-HANDOVER §11`, BUILD-PLAN Phase 5: "verify RAM-only/no-logs in
  production; confirm `x-phala-no-log`").
- **Row 6** is the client-side leak vector that bypasses every server-side control;
  it is owned on the iOS side and is a Phase-3 HARD GATE.

This table is **living**: update the "Current v0 state" → "Target state" columns as
controls land, and keep it in sync with `contracts/attestation.md`,
`contracts/identity-envelope.md`, and the gate definitions in the BUILD-PLAN.

See also: `docs/security/threat-model.md` (adversaries & assets),
`docs/security/claims-register.md` (what we may/may not say about these controls).
