# Deployment Trust Tiers (LOCKED — Gate 0, 2026-06-02)

**Core principle:** *Attestation buys "the operator cannot read your data." A
self-hoster **is** the operator, so they don't need it.* Therefore the **trust tier is a
deployment configuration + a client attestation policy — never a hardcoded assumption.**
The same code runs in every tier; only *where* components run and *what the client
requires* changes.

This reconciles three otherwise-conflicting goals: **confidential-from-day-one** (our
hosted service), **open-source adoption** (must run on cheap servers or no one deploys
it), and **public scale** (multi-tenant from day 1).

---

## The tiers

| Tier | Operator vs user | Confidentiality mechanism | Where compute runs | Client attestation policy | Cost |
|---|---|---|---|---|---|
| **T0 — Self-host, no TEE** | operator **=** user | client-side encryption + "I trust my own box" | any commodity VPS / the user's own machine | **off / optional** (user opted into their own infra) | cheapest (a $5–20/mo VPS, or free on existing hardware) |
| **T1 — Attested hosted** (what *we* run for Josh, Blake & the public) | operator **≠** user | Phala dstack CVM (TDX) + attested inference; **client verifies fail-closed** | per-tenant CVM(s) on Phala | **mandatory, fail-closed** (`attestation.md §4`) | shared multi-tenant; ~A$385+/mo optimized |
| **T2 — BYO inference** | either | depends on the endpoint | gateway anywhere; inference at a user-chosen OpenAI-compatible endpoint (local Ollama, their GPU, a cheap/attested API) | per-endpoint (attested → verify; local → trusted) | varies (can be ~free with local models) |

A deployment can mix tiers (e.g. T1 agent CVM + T2 BYO inference).

## What stays identical across tiers
- The **gateway** (ciphertext router), **Letta + Postgres + embeddings** container, the
  **identity/seed/KDF** model, the **encryption envelope**, the **client UI**.
- A self-hoster runs the *exact same Letta container* on a plain VM (T0) that we run
  inside a dstack CVM (T1). The CVM is just a confidential place to run it.

## What changes across tiers
1. **Where the Letta/gateway container runs:** plain VM (T0) vs dstack CVM (T1).
2. **The client's attestation policy** — a per-deployment/per-account setting:
   - `require-attestation` (T1 default for our hosted service): the client refuses to
     send unless `attestation.md §4` passes, fail-closed. **This is the only honest
     posture when operator ≠ user.**
   - `trusted-self-host` (T0): the user has explicitly designated their own server as
     trusted; attestation is not required because they ARE the operator. The UI must
     state plainly that this tier's confidentiality rests on the user trusting their own
     box, not on attestation.
3. **TLS termination:** inside the CVM (T1) vs ordinary TLS to the user's box (T0).

## Claims discipline per tier (carry into UI/docs)
- **T1 (attested hosted):** the full attested-confidential claim — "operator cannot read
  unless the TEE hardware or its attestation is compromised." Still **never** an E2E or
  ZK claim.
- **T0 (self-host):** claim only "your data stays on infrastructure you control; the app
  encrypts it client-side." Do **not** imply attestation-grade guarantees here.
- The client must **show the active tier + its honest guarantee** so a user always knows
  which trust model is in force. Mixing claims across tiers is a review failure.

## Why this is the right call (Gate-0 rationale)
- **Adoption:** OSS adopters self-host T0 on cheap commodity hardware — the expensive
  Phala TEE is *our* hosted-service cost, not a barrier to using the software.
- **No lock-in:** T0/T2 require zero Phala dependency; T1 is one (swappable) option.
- **Public scale:** a public multi-tenant service is exactly the operator≠user case that
  T1 attestation is designed for.
- **Engineering cost now:** small — the gateway and client already need a
  provider/regime abstraction (contract A1); making attestation a policy rather than a
  constant is a natural extension, cheap to build while we're "designing for public
  scale" anyway.

## Build implications (Phase 1+)
- Gateway: run-mode config (`plain` | `cvm`); never assume a TEE is present.
- Client: attestation policy is per-account/per-deployment; **`require-attestation` is
  the default and is mandatory for any hosted (operator≠user) connection.**
- Provisioning (multi-tenant, T1): per-tenant CVM orchestration + the spend-cap/abuse
  controls a public service needs.
- Self-host packaging (T0): a one-command `docker compose up` on a plain VPS.
