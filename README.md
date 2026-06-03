# Caladon

> *Caladon* — from an old word for light: a flame carried into dark places when every
> other light goes out. A private space that stays yours, lit for you alone.

**Caladon is a self-hostable, trust-no-one confidential AI assistant.** It is genuinely
open source (Apache-2.0) — a chat app + an attested gateway + a shared Rust trust-core that
you can run on **any** Linux box with `docker compose up`, or connect to a hosted gateway
running inside a hardware enclave that your client cryptographically verifies before it
sends a single byte.

> **Status: under active development, not yet independently audited.** The confidential
> (attested) path described below is real and proven against live hardware, but the whole
> system has not been through an external security review. Don't trust it with data you
> can't afford to lose until that review lands. See [Status & honesty](#status--honesty).

---

## Why Caladon

Your AI chat history has become as sensitive as your browser history — often more so.
Most "private AI" products ask you to *trust them*. Caladon is built so you don't have to:

- **Genuinely open source.** The entire platform — chat UI, gateway, and the Rust
  trust-core that does all the crypto and attestation — is Apache-2.0. No open-core bait, no
  "source-available" license that forbids self-hosting, no copyleft strings attached. Read
  it, build it, run it, fork it, embed it — commercially or otherwise.
- **Self-host on anything.** One `docker compose up` on a $5/mo VPS or your own laptop. No
  Kubernetes, no proprietary cloud, no phone-home.
- **Confidential / attested inference.** In the hosted tier, the model and agent memory run
  inside a hardware Trusted Execution Environment (Intel TDX). The client **verifies the
  enclave's attestation, fail-closed**, before sending anything. If verification fails, it
  refuses to transmit.
- **Sealed client-side crypto.** Prompts and replies are sealed in the browser/app; the
  gateway routes opaque envelopes. Plaintext exists in exactly two places: your device, and
  the verified enclave's RAM. Never in between, never at rest outside the enclave.
- **Seed / passkey custody.** Identity is a locally generated high-entropy **account seed**
  (Mullvad-style — no email, username, password, or third-party login). The seed *is* your
  identity and the root of your encryption keys. Optionally hold it under a WebAuthn passkey
  (PRF-wrapped) so the raw seed never persists.
- **No vendor lock-in on the model.** Bring your own OpenAI-compatible endpoint, run a local
  model, or use the attested hosted inference. Open-weight, user-chosen.

### The honest part: attested ≠ end-to-end encrypted

This is the whole point of the project, so we state it plainly. Any system that runs a model
on a remote machine — **including a TEE** — exposes plaintext to that machine. A TEE raises
the bar enormously, but it is not magic and not unbreakable.

So Caladon is **attested confidential computing, NOT end-to-end encryption.** We do **not**
claim "zero-knowledge", "we can't read your data" (unqualified), or "no possibility of
leaks". The defensible claim is:

> *All inference and agent memory run inside hardware TEEs whose attestation the app verifies
> before any data is sent. The operator cannot read your data **unless the TEE hardware or
> its attestation is compromised.** Per-user data is encrypted under a key derived from a
> secret only you hold.*

Content confidentiality also does **not** hide traffic metadata (timing, size, frequency).
We minimize it; we don't eliminate it, and we say so. The only architecture that could
honestly claim "the server mathematically cannot read it" is fully on-device inference — a
deliberate non-goal here, because it sacrifices the large remote model. See
[Security model](#security-model) and `docs/security/` for the full disclosure.

---

## Two deployment tiers

The same code runs in every tier. **The trust tier is a deployment configuration plus a
client attestation policy — never a hardcoded assumption.** Attestation buys you "the
operator cannot read my data." If you *are* the operator, you don't need it.

| | **T0 — Self-host** | **T1 — Hosted + attested** |
|---|---|---|
| Operator vs. you | operator **=** you | operator **≠** you |
| Confidentiality rests on | client-side crypto + "I trust my own box" | Intel TDX CVM + attested inference, **client-verified fail-closed** |
| Where compute runs | any commodity Linux / your own machine | per-tenant Confidential VM (Phala dstack, Intel TDX) |
| Client attestation policy | **off / optional** (you opted into your own infra) | **mandatory, fail-closed** |
| Inference | local **Ollama** model, **or** bring-your-own OpenAI-compatible endpoint | attested confidential inference |
| Cost | a cheap VPS, or free on hardware you own | shared multi-tenant hosted service |

**T0 — Self-host (your own box).** You run the exact same gateway + agent + model container
on a plain Linux VM. Because you are the operator, attestation is *optional* — your
confidentiality rests on you trusting your own server, and the UI says exactly that. Point
it at a **local Ollama model** for a fully offline-capable setup, or at **any
OpenAI-compatible endpoint** (your own GPU, a hosted API) — no Phala dependency, no lock-in.

**T1 — Hosted + attested (we run the gateway; you verify it).** The gateway runs inside a
**Phala dstack Confidential VM (Intel TDX)**. Your client fetches the enclave's attestation
evidence, verifies the TDX quote to the Intel root, checks the TCB is up to date, confirms
the enclave measurement matches a **pinned** value (no trust-on-first-use), and binds the
session key to the attestation — **all before sending anything.** This is the only honest
posture when the operator isn't you.

A deployment can mix tiers (e.g. a hosted attested agent CVM with a bring-your-own inference
endpoint). The client always **shows the active tier and its honest guarantee**, so you
always know which trust model is in force.

Full rationale: [`docs/deployment-tiers.md`](docs/deployment-tiers.md).

---

## Quick Start (T0 self-host)

You need Docker with Compose. A local **Ollama** is optional but recommended for a fully
self-contained setup.

```bash
# 1. Clone
git clone https://github.com/joshbilson/caladon.git
cd caladon

# 2. Configure
cp .env.example .env   # template lives at infra/.env.example too
#   - set strong random values for the Postgres / agent / device-token fields
#   - point VLLM_API_BASE / OLLAMA_BASE_URL at your local model, OR set an
#     OpenAI-compatible endpoint + key to bring your own inference
#   (generate a device token: openssl rand -hex 32)

# 3. Bring it up
docker compose -f infra/docker-compose.yml up -d

# 4. Open the app
#   visit the web client in your browser (installable as a PWA), or build the
#   iOS/macOS app from the apple/ component
```

**Onboard with a seed.** On first run the client generates a high-entropy account seed.
**Write it down / store it in a password manager** — it is your identity *and* your
decryption key; lose it and the data is unrecoverable by design (no one else holds it).
Optionally bind the seed under a passkey so the raw seed never persists on the device.

That's it — your assistant is now running on infrastructure you control, with all
data-touching state encrypted under a key only you hold.

> Connecting to a **T1 hosted** gateway instead? Set the client's attestation policy to
> `require-attestation` and point it at the gateway URL. The client will verify the enclave
> and refuse to send if verification fails.

---

## Open source vs. the commercial cloud

We want zero ambiguity here.

**Open source (this repo, Apache-2.0) — the entire platform, fully permissive:**

- the chat application (a LibreChat-derived chat SPA) and the native iOS/macOS app shell;
- the **gateway** — the ciphertext router that fronts the agent and routes opaque envelopes;
- **`caladon-core`** — the shared Rust trust-core: identity/seed key derivation, the
  encryption envelope, the session channel, and the **fail-closed attestation verifier**
  (compiled to WASM for the web client and bound natively into the app);
- the agent-memory + database + embeddings container wiring and the infra/Compose to run it;
- the security docs, frozen interface contracts, and the threat model.

Everything required to run Caladon for yourself, at T0 or T1, is in here under Apache-2.0.
The license is permissive: you may use, modify, redistribute, and embed it — including
commercially, and including by AI agents and automated tooling — with attribution and the
explicit patent grant the Apache-2.0 license carries. No copyleft, no network-source
obligation, no strings attached.

**The commercial cloud (a separate proprietary service, NOT in this repo):**

Our hosted SaaS adds the operational plumbing a public, paid, multi-tenant service needs and
that has nothing to do with the privacy guarantee:

- billing and metering;
- multi-tenant orchestration (per-tenant CVM provisioning, spend caps, abuse controls);
- the operator admin/console.

That layer is simply a separate private, proprietary service that lives elsewhere — not a
copyleft boundary and not an obligation we impose on you. Because this repo is permissively
licensed, self-hosting the full attested stack carries **no** reciprocal-source requirement:
run it, change it, keep your changes private if you want to. The commercial service is just
how *we* operate a hosted offering at scale — it neither weakens nor gates anything in here.

---

## Security model

- **Client-verified attestation, fail-closed.** The client pins enclave measurements,
  verifies the TDX quote to the Intel root + checks TCB freshness, binds the session key to
  the attestation, and **refuses to transmit if verification fails.** No trust-on-first-use:
  the pinned measurement ships in a signed client update, never set at runtime.
- **Sealed data plane.** Identity → Argon2id/HKDF key derivation; an XChaCha20-Poly1305
  envelope; an X25519 session channel into the enclave; metadata padding. The working-memory
  key is sealed to the *verified* enclave's session key and held in TEE RAM for the session
  only.
- **Forward-secrecy split (disclosed).** The conversation transcript is forward-secret
  (device-side ratchet). Working memory is seed-recoverable and therefore *not* forward-secret
  — an agent must be able to re-read its own memory. We document this rather than hide it.
- **Residual trust.** Security rests on Intel TDX silicon, the DCAP/PCS attestation roots,
  the measurement-pinning chain, and pinned-measurement == audited-source. Compromise any of
  those and the guarantee weakens. TEEs have a real side-channel/fault break history.
- **Metadata.** Traffic-analysis resistance is partial; timing, sizes, and frequency are
  visible to the relay. A disclosed non-goal.
- **Reproducible builds (goal).** The aim is that anyone can rebuild the enclave image from
  this source and confirm its measurement equals the value the client pins.

Read the docs — they're written to be checked, not believed:

- [`docs/deployment-tiers.md`](docs/deployment-tiers.md) — the trust tiers in full
- [`docs/security/threat-model.md`](docs/security/threat-model.md) — adversaries, residual trust, non-goals
- [`docs/security/plaintext-exposure-map.md`](docs/security/plaintext-exposure-map.md) — every place plaintext exists + the control
- [`docs/security/claims-register.md`](docs/security/claims-register.md) — the exact claims we allow and forbid
- [`docs/security/measurements.md`](docs/security/measurements.md) — what gets pinned and why
- [`docs/security/reproducible-builds.md`](docs/security/reproducible-builds.md) — rebuild-and-verify approach
- [`contracts/attestation.md`](contracts/attestation.md) — exactly what the enclave emits and what the client checks

---

## Repo layout

```
web-client/   LibreChat-derived chat SPA (+ the @caladon/protocol SDK and shim)
apple/        SwiftUI iOS + macOS app (chat UI + the attestation verifier)
gateway/      the ciphertext router that fronts the agent
caladon-core/ shared Rust trust-core: identity/crypto/envelope + fail-closed verifier (WASM + native)
infra/        Compose + provisioning for the agent / Postgres / embeddings, plain VM and CVM
contracts/    frozen interface contracts (attestation, identity-envelope, gateway-api, ...)
docs/         specs, deployment tiers, and docs/security/ (threat model, exposure map, claims)
```

---

## Status & honesty

- **Confidential gateway — built.** Multi-tenant seed-signature auth, key-bound onboarding,
  the attestation handshake, an opaque-envelope transcript store, working-memory-key delivery
  into TEE RAM, and a sealed chat round-trip (no plaintext on the wire). Runs in `cvm`
  (attested) or `plain` (self-host) mode.
- **Attestation — proven on real hardware.** A real Intel TDX quote verifies to the Intel
  root; the gateway image has run in a live Phala dstack TDX CVM with a full sealed round-trip
  and fail-closed measurement pinning, exercised end-to-end from the web client SDK.
- **Trust-core — built, cross-language byte-parity.** Argon2id→HKDF identity, the XChaCha20
  envelope, the forward-secret transcript ratchet, the X25519 session channel, and the
  fail-closed verifier, shared by the WASM (web) and native (app) clients.
- **Clients — building.** The LibreChat-derived web client + protocol SDK, and the SwiftUI
  iOS/macOS app, both wire to the confidential client.
- **Not yet:** an independent third-party security audit, full reproducible-build vetting,
  and the long-running autonomous-agent tier. Until those land, treat this as pre-release.

**Independent review is the most valuable contribution you can make.** This project exists
because "trust us" isn't good enough. Finding an overclaim, a plaintext-exposure path, or a
gap in the attestation logic is exactly the kind of issue we want.

---

## Contributing

- Issues and PRs welcome — especially security review, claims-discipline catches, and
  attestation-logic scrutiny.
- **DCO required, no CLA.** Sign off every commit (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/). The sign-off line
  (`Signed-off-by: Your Name <you@example.com>`) is your agreement to it — that's the only
  provenance step; there is no contributor license agreement to sign.
- **Claims discipline is enforced.** A CI claims-lint rejects the forbidden privacy phrases
  (see [`docs/security/claims-register.md`](docs/security/claims-register.md)). If you find
  one of those phrases in the code, UI, or docs outside the allowlist, that's a bug — please
  report it.

---

## License

**Apache-2.0.** Caladon is permissively, genuinely open source. Anyone may use, modify,
redistribute, and embed it — including commercially, and including by AI agents and
automated tooling — subject only to the attribution and notice terms of the license, which
also carries an explicit patent grant. There is **no copyleft and no network-source
obligation**: running a modified version, as a service or otherwise, imposes no requirement
to publish your changes. The **entire** repository — chat UI, gateway, and the
`caladon-core` Rust trust-core — is Apache-2.0. See [`LICENSE`](LICENSE).
